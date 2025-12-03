import { Daytona, Image, Sandbox } from "@daytonaio/sdk";
import type { AIModel } from "../../../ai";
import { runAgent as runThoroughPentestAgent } from "../../thoroughPentestAgent/agent";
import { createSession, BENCHMARK_OUTCOME_GUIDANCE } from "../../sessions";
import { extractFlagFromRepo, detectFlagInArtifacts } from "../flag-detector";
import { runComparisonAgent } from "../comparisonAgent";
import type { BenchmarkResults } from "../types";
import type {
  ExecuteCommandOpts,
  ExecuteCommandResult,
  HttpRequestOpts,
  HttpRequestResult,
} from "../../tools";
import { writeFileSync, readFileSync, existsSync, readdirSync, statSync } from "fs";
import { join } from "path";
import path from "path";
import pLimit from "p-limit";
import { parseDockerComposePort } from "../docker-utils";

export interface DaytonaBenchmarkOptions {
  benchmarkPath: string; // Local path to benchmark directory (e.g., /path/to/repo/benchmarks/XBOW-001-24)
  benchmarkName: string; // Benchmark name (e.g., XBOW-001-24)
  model: AIModel;
  apiKey?: string;
  orgId?: string;
  anthropicKey?: string;
  openrouterKey?: string;
}

export interface MultipleBranchOptions extends Omit<DaytonaBenchmarkOptions, "benchmarkPath" | "benchmarkName"> {
  repoPath: string; // Local path to repo root
  benchmarks?: string[]; // Benchmark names (e.g., ["XBOW-001-24", "XBOW-002-24"])
  maxParallel?: number;
}

/**
 * Recursively collect all files from a directory
 */
function collectFilesRecursive(
  dirPath: string,
  baseDir: string,
  files: Array<{ source: Buffer; destination: string }> = []
): Array<{ source: Buffer; destination: string }> {
  const entries = readdirSync(dirPath);

  for (const entry of entries) {
    const fullPath = path.join(dirPath, entry);
    const stat = statSync(fullPath);

    if (stat.isDirectory()) {
      // Recursively collect files from subdirectory
      collectFilesRecursive(fullPath, baseDir, files);
    } else if (stat.isFile()) {
      // Calculate relative path from base directory
      const relativePath = path.relative(baseDir, fullPath);
      const contents = readFileSync(fullPath)
      files.push({
        source: contents,
        destination: relativePath,
      });
    }
  }

  return files;
}


/**
 * Run a single benchmark with Daytona sandbox
 * Agent runs locally, but commands/requests execute in sandbox
 */
export async function runBenchmarkWithDaytona(
  options: DaytonaBenchmarkOptions
): Promise<BenchmarkResults> {
  const { benchmarkPath, benchmarkName, model } = options;
  const apiKey = options.apiKey || process.env.DAYTONA_API_KEY;
  const orgId = options.orgId || process.env.DAYTONA_ORG_ID;

  if (!apiKey) {
    throw new Error("DAYTONA_API_KEY is required");
  }

  console.log(`\n${"=".repeat(80)}`);
  console.log(`[${benchmarkName}] Starting Daytona Benchmark`);
  console.log(`${"=".repeat(80)}`);

  // Parse docker-compose port before creating sandbox
  console.log(`[${benchmarkName}] 🔍 Parsing docker-compose for web service...`);
  const portInfo = parseDockerComposePort(benchmarkPath);
  console.log(`[${benchmarkName}] ✅ Found web service: ${portInfo.serviceName} on port ${portInfo.hostPort}`);

  const daytona = new Daytona({ apiKey: apiKey });

  let sandbox: Sandbox | undefined;
  let remoteBenchmarkPath = "";

  try {
    // Step 1: Create sandbox
    console.log(`[${benchmarkName}] 🚀 Creating Daytona sandbox...`);
    sandbox = await daytona.create(
      {
        language: "typescript",
        envVars: {
          ANTHROPIC_API_KEY: options.anthropicKey || process.env.ANTHROPIC_API_KEY || "",
          OPENROUTER_API_KEY: options.openrouterKey || process.env.OPENROUTER_API_KEY || "",
        },
        public: true,
        networkBlockAll: false,
        resources: {
          cpu: 2,
          memory: 2,
          disk: 1
        },
        image: Image.fromDockerfile(path.join(process.cwd(), 'container', 'benchmark', 'Dockerfile'))
      },
      { timeout: 180000 }
    );

    console.log(`[${benchmarkName}] ✅ Sandbox created: ${sandbox.id}`);

    // Disable auto-stop
    await sandbox.setAutostopInterval(0);

    // Wait for sandbox and Docker daemon to be fully ready
    console.log(`[${benchmarkName}] ⏳ Waiting for sandbox and Docker daemon to be ready...`);
    await new Promise((resolve) => setTimeout(resolve, 10000));

    // Verify Docker daemon is running
    console.log(`[${benchmarkName}] 🐳 Verifying Docker daemon...`);
    const dockerCheckResult = await sandbox.process.executeCommand(
      "docker info",
      undefined,
      undefined,
      30000
    );

    if (dockerCheckResult.exitCode !== 0) {
      console.error(`[${benchmarkName}] ❌ Docker daemon not ready: ${dockerCheckResult.result}`);
      throw new Error(`Docker daemon is not running in sandbox: ${dockerCheckResult.result}`);
    }

    console.log(`[${benchmarkName}] ✅ Docker daemon is ready`);

    // Step 2: Upload benchmark directory to sandbox
    console.log(`[${benchmarkName}] 📦 Uploading benchmark directory...`);
    const userHome = await sandbox.getUserHomeDir();
    if(!userHome) console.info("User home directory path is empty in sandbox");
    // Use posix path for Linux sandbox
    remoteBenchmarkPath = path.posix.join(userHome??"", "benchmark");

    // Collect all files from benchmark directory
    const filesToUpload = collectFilesRecursive(benchmarkPath, benchmarkPath);
    console.log(`[${benchmarkName}] 📁 Found ${filesToUpload.length} files to upload`);

    // Map to Daytona upload format with remote path prefix (use posix paths for Linux sandbox)
    const uploadFiles = filesToUpload.map(file => ({
      source: file.source,
      // Convert local path separators to posix for remote paths
      destination: path.posix.join(remoteBenchmarkPath, file.destination.replace(/\\/g, '/')),
    }));

    // Upload files in batches to avoid overwhelming the API
    const BATCH_SIZE = 10;
    const batches = [];
    for (let i = 0; i < uploadFiles.length; i += BATCH_SIZE) {
      batches.push(uploadFiles.slice(i, i + BATCH_SIZE));
    }

    try {
      console.log(`[${benchmarkName}] 📤 Uploading ${uploadFiles.length} files in ${batches.length} batch(es)...`);

      for (let i = 0; i < batches.length; i++) {
        const batch = batches[i]!;
        console.log(`[${benchmarkName}] 📦 Batch ${i + 1}/${batches.length}: ${batch.length} files...`);
        await sandbox.fs.uploadFiles(batch, 300);

        // Small delay between batches to avoid rate limiting
        if (i < batches.length - 1) {
          await new Promise((resolve) => setTimeout(resolve, 1000));
        }
      }

      console.log(`[${benchmarkName}] ✅ Benchmark uploaded to ${remoteBenchmarkPath}`);
    } catch (uploadError: any) {
      console.error(`[${benchmarkName}] ❌ Upload failed: ${uploadError.message}`);
      if (uploadError.response) {
        console.error(`[${benchmarkName}] Response status: ${uploadError.response.status}`);
        console.error(`[${benchmarkName}] Response data:`, uploadError.response.data);
      }
      throw new Error(`File upload failed: ${uploadError.message}`);
    }

    // Step 3: Extract flag from local benchmark directory
    console.log(`[${benchmarkName}] 🔍 Extracting flag from local benchmark...`);
    const expectedFlag = await extractFlagFromRepo(benchmarkPath, benchmarkName);

    if (expectedFlag) {
      console.log(`[${benchmarkName}] ✅ FLAG found: ${expectedFlag.substring(0, 20)}...`);
    } else {
      console.log(`[${benchmarkName}] ⚠️  FLAG not found in benchmark`);
    }

    // Step 4: Build docker images with flag injection
    console.log(`[${benchmarkName}] 🔨 Building docker images with flag...`);

    const buildCommands = `
cd ${remoteBenchmarkPath}
BENCHMARK_UPPER=$(basename "$PWD" | tr '[:lower:]' '[:upper:]')
FLAG_HASH=$(echo -n "$BENCHMARK_UPPER" | openssl sha256 -r | cut -d' ' -f1)
FLAG_FMT="FLAG{\${FLAG_HASH}}"
echo "Generated flag: \${FLAG_FMT}"
docker compose build --build-arg FLAG="\${FLAG_FMT}" --build-arg flag="\${FLAG_FMT}"
`;

    const buildResult = await sandbox.process.executeCommand(
      buildCommands,
      undefined,
      undefined,
      300000 // 5 minute timeout for builds
    );

    if (buildResult.exitCode !== 0) {
      throw new Error(`Failed to build docker images: ${buildResult.result} CODE: ${buildResult.exitCode}`);
    }

    console.log(`[${benchmarkName}] ✅ Docker images built`);

    // Step 5: Start docker compose
    console.log(`[${benchmarkName}] 🐳 Starting docker compose...`);
    const startDockerResult = await sandbox.process.executeCommand(
      `cd ${remoteBenchmarkPath} && docker compose up -d --wait`,
      undefined,
      undefined,
      120000
    );

    if (startDockerResult.exitCode !== 0) {
      throw new Error(`Failed to start docker compose: ${startDockerResult.result} CODE: ${startDockerResult.exitCode}`);
    }

    console.log(`[${benchmarkName}] ✅ Docker compose started`);

    // Wait a bit for services to be ready
    console.log(`[${benchmarkName}] ⏳ Waiting for services to be ready...`);
    await new Promise((resolve) => setTimeout(resolve, 10000));

    // Step 6: Build target URL from parsed port
    const targetUrl = `http://localhost:${portInfo.hostPort}`;
    console.log(`[${benchmarkName}] 🎯 Target URL: ${targetUrl}`);

    // Step 7: Create local session with benchmark guidance and scope constraints
    const session = createSession(
      targetUrl,
      `Benchmark testing for ${benchmarkName}`,
      `benchmark-${benchmarkName}`,
      {
        outcomeGuidance: BENCHMARK_OUTCOME_GUIDANCE,
        scopeConstraints: {
          allowedHosts: ['localhost'],
          allowedPorts: [portInfo.hostPort],
          strictScope: true,
        },
      }
    );

    console.log(`[${benchmarkName}] 📝 Local session created: ${session.id}`);

    // Step 8: Create tool overrides that proxy to Daytona sandbox
    const executeCommandOverride = async (
      opts: ExecuteCommandOpts
    ): Promise<ExecuteCommandResult> => {
      try {
        if(!sandbox) throw new Error("Sandbox not created");
        const result = await sandbox.process.executeCommand(opts.command, undefined, undefined, opts.timeout || 120000,);

        return {
          command: opts.command,
          success: result.exitCode === 0,
          stdout: result.result || "",
          stderr: result.result || "",
          error: result.exitCode !== 0 ? result.result : ""
        };
      } catch (error: any) {
        return {
          command: opts.command,
          success: false,
          stdout: "",
          stderr: error.message,
          error: error.message,
        };
      }
    };

    const httpRequestOverride = async (
      opts: HttpRequestOpts
    ): Promise<HttpRequestResult> => {
      try {
        // Build curl command
        let curlCmd = `curl -s -w "\\n%{http_code}" -X ${opts.method || "GET"}`;

        // Add headers
        if (opts.headers) {
          for (const [key, value] of Object.entries(opts.headers)) {
            curlCmd += ` -H "${key}: ${value}"`;
          }
        }

        // Add body
        if (opts.body) {
          curlCmd += ` -d '${opts.body.replace(/'/g, "'\\''")}'`;
        }

        curlCmd += ` "${opts.url}"`;
        if(!sandbox) throw new Error("Sandbox not created");
        const result = await sandbox.process.executeCommand(curlCmd);

        if (result.exitCode !== 0) {
          return {
            success: false,
            status: 0,
            statusText: result.result,
            url: opts.url,
            redirected: opts.followRedirects,
            headers: {},
            body: result.result,
          };
        }

        // Parse output (body + status code)
        const output = result.result || "";
        const lines = output.split("\n");
        const statusCode = parseInt(lines[lines.length - 1] || "0");
        const body = lines.slice(0, -1).join("\n");

        return {
          success: true,
          status: statusCode,
          statusText: output,
          headers: {}, // Can't easily extract headers from curl without -i
          body,
          redirected: false,
          url: opts.url
        };
      } catch (error: any) {
        return {
          success: false,
          status: 0,
          headers: {},
          body: "",
          statusText: error.message,
          redirected: false,
          url: opts.url
        };
      }
    };

    // Step 9: Run thorough pentest with tool overrides (scope constraints in session config)
    console.log(`[${benchmarkName}] 🔍 Starting thorough pentest (local agent, remote execution)...`);
    const { streamResult } = runThoroughPentestAgent({
      target: targetUrl,
      model,
      session,
      toolOverride: {
        execute_command: executeCommandOverride,
        http_request: httpRequestOverride,
      },
    });

    // Consume the stream
    for await (const delta of streamResult.fullStream) {
      if (delta.type === "text-delta") {
        process.stdout.write(delta.text);
      }
    }

    console.log(`[${benchmarkName}] ✅ Pentest completed`);

    // Step 10: Run comparison agent (locally)
    console.log(`[${benchmarkName}] 📊 Running comparison agent...`);
    let comparison;
    try {
      // Use local benchmark path for comparison
      comparison = await runComparisonAgent({
        repoPath: benchmarkPath,
        sessionPath: session.rootPath,
        model,
      });
    } catch (error: any) {
      console.log(`[${benchmarkName}] ⚠️  Comparison failed: ${error.message}`);
      comparison = {
        totalExpected: 0,
        totalActual: 0,
        matched: [],
        missed: [],
        extra: [],
        accuracy: 0,
        recall: 0,
        precision: 0,
      };
    }

    // Step 11: Detect flag in artifacts (locally)
    console.log(`[${benchmarkName}] 🎯 Detecting flag in artifacts...`);
    let flagDetection;
    if (expectedFlag) {
      flagDetection = await detectFlagInArtifacts(
        session.rootPath,
        expectedFlag,
        benchmarkName
      );
    } else {
      flagDetection = {
        detected: false,
        flagValue: null,
        foundIn: [],
        searchLocations: [],
      };
    }

    // Step 12: Generate benchmark results
    const results: BenchmarkResults = {
      repoPath: benchmarkPath,
      branch: benchmarkName,
      targetUrl,
      sessionId: session.id,
      sessionPath: session.rootPath,
      flagDetection,
      expectedFlag,
      expectedResults: [
        ...comparison.matched.map((m: any) => m.expected),
        ...comparison.missed,
      ],
      actualResults: [
        ...comparison.matched.map((m: any) => m.actual),
        ...comparison.extra,
      ],
      comparison,
      timestamp: new Date().toISOString(),
    };

    const reportPath = join(session.rootPath, "benchmark_results.json");
    writeFileSync(reportPath, JSON.stringify(results, null, 2));

    console.log(`\n[${benchmarkName}] 📄 Benchmark report saved to: ${reportPath}`);
    console.log(`\n[${benchmarkName}] 🎯 FLAG STATUS: ${flagDetection.detected ? "✅ DETECTED" : "❌ NOT DETECTED"}`);
    if (flagDetection.detected) {
      console.log(`[${benchmarkName}]    Found in: ${flagDetection.foundIn.join(", ")}`);
    }

    return results;
  } finally {
    // Cleanup: Stop docker and delete sandbox
    if (sandbox) {
      try {
        console.log(`[${benchmarkName}] 🧹 Cleaning up sandbox...`);

        // Only try to stop docker if we successfully uploaded and started it
        if (remoteBenchmarkPath) {
          try {
            console.log(`[${benchmarkName}] 🐳 Stopping docker compose...`);
            await sandbox.process.executeCommand(`cd ${remoteBenchmarkPath} && docker compose down`, undefined, undefined, 30000);
          } catch (dockerError: any) {
            // Don't fail cleanup if docker stop fails (might not have started)
            console.log(`[${benchmarkName}] ⚠️  Docker stop failed (may not have started): ${dockerError.message}`);
          }
        }

        // Wait for sandbox to settle before deleting
        console.log(`[${benchmarkName}] ⏳ Waiting for sandbox to settle...`);
        let attempts = 0;
        while (attempts < 10) {
          try {
            await sandbox.refreshData();
            if (sandbox.state !== "stopping" && sandbox.state !== "starting") {
              break;
            }
          } catch (refreshError: any) {
            console.log(`[${benchmarkName}] ⚠️  Refresh failed (attempt ${attempts + 1}): ${refreshError.message}`);
          }
          await new Promise((resolve) => setTimeout(resolve, 3000));
          attempts++;
        }

        // Delete the sandbox
        try {
          console.log(`[${benchmarkName}] 🗑️  Deleting sandbox...`);
          await sandbox.delete();
          console.log(`[${benchmarkName}] ✅ Cleanup complete`);
        } catch (deleteError: any) {
          console.error(`[${benchmarkName}] ⚠️  Failed to delete sandbox: ${deleteError.message}`);
          console.error(`[${benchmarkName}] ⚠️  You may need to manually delete sandbox: ${sandbox.id}`);
        }
      } catch (error: any) {
        console.error(`[${benchmarkName}] ⚠️  Cleanup error: ${error.message}`);
        console.error(`[${benchmarkName}] ⚠️  Sandbox may still be running: ${sandbox.id}`);
      }
    }
  }
}

/**
 * Run benchmarks across multiple benchmarks in parallel
 */
export async function runMultipleBenchmarks(
  options: MultipleBranchOptions
): Promise<BenchmarkResults[]> {
  const benchmarks = options.benchmarks || [];

  if (benchmarks.length === 0) {
    throw new Error("No benchmarks provided");
  }

  const maxParallel = options.maxParallel || 4;
  const startTime = Date.now();

  console.log("\n" + "=".repeat(80));
  console.log("🚀 STARTING PARALLEL BENCHMARK EXECUTION");
  console.log("=".repeat(80));
  console.log(`Repository: ${options.repoPath}`);
  console.log(`Benchmarks: ${benchmarks.length}`);
  console.log(`Model: ${options.model}`);
  console.log(`Max Parallel: ${maxParallel}`);
  console.log("=".repeat(80) + "\n");

  // Run with concurrency limit
  const limit = pLimit(maxParallel);
  const results = await Promise.all(
    benchmarks.map((benchmarkName) =>
      limit(() => {
        const benchmarkPath = path.join(options.repoPath, "benchmarks", benchmarkName);
        return runBenchmarkWithDaytona({
          benchmarkPath,
          benchmarkName,
          model: options.model,
          apiKey: options.apiKey,
          orgId: options.orgId,
          anthropicKey: options.anthropicKey,
          openrouterKey: options.openrouterKey,
        });
      })
    )
  );

  const totalDuration = ((Date.now() - startTime) / 1000 / 60).toFixed(2);
  const flagsDetected = results.filter((r) => r.flagDetection?.detected).length;
  const flagsMissed = results.filter((r) => !r.flagDetection?.detected).length;

  console.log("\n" + "=".repeat(80));
  console.log("📊 BENCHMARK SUMMARY");
  console.log("=".repeat(80));
  console.log(`Total Duration: ${totalDuration}m`);
  console.log(`Total Benchmarks: ${benchmarks.length}`);
  console.log(`Flags Detected: ${flagsDetected}/${benchmarks.length} (${Math.round((flagsDetected / benchmarks.length) * 100)}%)`);
  console.log(`Flags Missed: ${flagsMissed}/${benchmarks.length}`);
  console.log("=".repeat(80));

  // Generate summary report
  const summaryDir = path.join(
    process.cwd(),
    ".pensar",
    "benchmarks",
    "executions",
    `parallel-run-${new Date().toISOString().replace(/[:.]/g, "-")}`
  );

  const fs = await import("fs");
  fs.mkdirSync(summaryDir, { recursive: true });

  const summary = {
    timestamp: new Date().toISOString(),
    repoPath: options.repoPath,
    model: options.model,
    totalBenchmarks: benchmarks.length,
    flagsDetected,
    flagsMissed,
    duration: totalDuration,
    benchmarks: results.map((r) => ({
      benchmark: r.branch, // branch field contains benchmarkName
      flagDetected: r.flagDetection?.detected || false,
      expectedFlag: r.expectedFlag,
      foundIn: r.flagDetection?.foundIn || [],
      sessionPath: r.sessionPath,
    })),
  };

  fs.writeFileSync(
    path.join(summaryDir, "summary.json"),
    JSON.stringify(summary, null, 2)
  );

  console.log(`\n📄 Summary report saved to: ${summaryDir}/summary.json\n`);

  return results;
}
