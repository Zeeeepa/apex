import { Daytona, Image, Sandbox } from "@daytonaio/sdk";
import type { AIModel } from "../../../ai";
import { createSession, BENCHMARK_OUTCOME_GUIDANCE } from "../../sessions";
import { extractFlagFromRepo, detectFlagInArtifacts } from "../flag-detector";
import { runComparisonAgent } from "../comparisonAgent";
import { runStreamlinedPentest } from "../../thoroughPentestAgent/streamlined";
import type { BenchmarkResults } from "../types";
import type {
  ExecuteCommandOpts,
  ExecuteCommandResult,
  HttpRequestOpts,
  HttpRequestResult,
} from "../../tools";
import {
  writeFileSync,
  readFileSync,
  existsSync,
  readdirSync,
  statSync,
  mkdirSync,
} from "fs";
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
  prefix?: string; // Prefix for session names and output directories
}

export interface MultipleBenchmarkOptions
  extends Omit<DaytonaBenchmarkOptions, "benchmarkPath" | "benchmarkName"> {
  repoPath: string; // Local path to repo root
  benchmarks?: string[]; // Benchmark names (e.g., ["XBOW-001-24", "XBOW-002-24"])
  maxParallel?: number;
  prefix?: string; // Prefix for session names and output directories
}

interface PocRunResult {
  pocFile: string;
  pocName: string;
  exitCode: number | null;
  stdout: string;
  stderr: string;
  duration: number;
  success: boolean;
  error?: string;
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
      const contents = readFileSync(fullPath);
      files.push({
        source: contents,
        destination: relativePath,
      });
    }
  }

  return files;
}

/**
 * Re-run all POC scripts in a session via Daytona sandbox and save their outputs
 */
async function rerunAllPocsInSandbox(
  sandbox: Sandbox,
  sessionPath: string,
  remoteBenchmarkPath: string,
  benchmarkName: string,
  targetUrl: string
): Promise<{
  total: number;
  passed: number;
  failed: number;
  results: PocRunResult[];
}> {
  const pocsDir = path.join(sessionPath, "pocs");
  const logsDir = path.join(pocsDir, "logs");

  // Check if pocs directory exists locally
  if (!existsSync(pocsDir)) {
    console.log(
      `[${benchmarkName}] 📁 No POCs directory found, skipping POC re-run`
    );
    return { total: 0, passed: 0, failed: 0, results: [] };
  }

  // Create logs directory
  mkdirSync(logsDir, { recursive: true });

  // Find all POC files
  const files = readdirSync(pocsDir);
  const pocFiles = files.filter(
    (f) => f.endsWith(".sh") || f.endsWith(".html")
  );

  if (pocFiles.length === 0) {
    console.log(`[${benchmarkName}] 📁 No POC files found in ${pocsDir}`);
    return { total: 0, passed: 0, failed: 0, results: [] };
  }

  console.log(`[${benchmarkName}] 🔄 Re-running ${pocFiles.length} POC(s)...`);

  const results: PocRunResult[] = [];
  let passed = 0;
  let failed = 0;

  for (const pocFile of pocFiles) {
    const pocPath = path.join(pocsDir, pocFile);
    const pocName = pocFile.replace(/\.(sh|html)$/, "");
    const logFileName = `${pocName}-${new Date()
      .toISOString()
      .replace(/[:.]/g, "-")}.log`;
    const logPath = path.join(logsDir, logFileName);

    if (pocFile.endsWith(".html")) {
      // HTML POCs can't be executed automatically
      const result: PocRunResult = {
        pocFile,
        pocName,
        exitCode: null,
        stdout: "",
        stderr: "",
        duration: 0,
        success: false,
        error: "HTML POCs cannot be executed automatically (requires browser)",
      };
      results.push(result);

      const logContent = `POC: ${pocFile}
Type: HTML
Status: SKIPPED (HTML POCs require manual browser execution)
Timestamp: ${new Date().toISOString()}
`;
      writeFileSync(logPath, logContent);
      console.log(`[${benchmarkName}]   ⏭️  ${pocFile} (HTML - skipped)`);
      continue;
    }

    // Read the POC file content and upload to sandbox
    const pocContent = readFileSync(pocPath, "utf-8");
    const remotePocPath = `/tmp/poc-${pocName}.sh`;

    // Upload POC script to sandbox
    await sandbox.fs.uploadFiles([
      {
        source: Buffer.from(pocContent),
        destination: remotePocPath,
      },
    ]);

    // Execute bash POC in sandbox
    const startTime = Date.now();
    let result: PocRunResult;

    try {
      // Make script executable and run it
      const execResult = await sandbox.process.executeCommand(
        `chmod +x "${remotePocPath}" && TARGET="${targetUrl}" bash "${remotePocPath}"`,
        undefined,
        undefined,
        120000 // 2 minute timeout
      );

      const duration = Date.now() - startTime;

      if (execResult.exitCode === 0) {
        result = {
          pocFile,
          pocName,
          exitCode: 0,
          stdout: execResult.result || "",
          stderr: "",
          duration,
          success: true,
        };
        passed++;
        console.log(
          `[${benchmarkName}]   ✅ ${pocFile} (${(duration / 1000).toFixed(1)}s)`
        );
      } else {
        result = {
          pocFile,
          pocName,
          exitCode: execResult.exitCode ?? 1,
          stdout: execResult.result || "",
          stderr: execResult.result || "",
          duration,
          success: false,
          error: `Exit code: ${execResult.exitCode}`,
        };
        failed++;
        console.log(
          `[${benchmarkName}]   ❌ ${pocFile} (exit code: ${result.exitCode})`
        );
      }
    } catch (error: any) {
      const duration = Date.now() - startTime;
      result = {
        pocFile,
        pocName,
        exitCode: 1,
        stdout: "",
        stderr: error.message || "",
        duration,
        success: false,
        error: error.message,
      };
      failed++;
      console.log(
        `[${benchmarkName}]   ❌ ${pocFile} (error: ${error.message})`
      );
    }

    results.push(result);

    // Save log file
    const logContent = `POC: ${pocFile}
Type: Bash Script
Exit Code: ${result.exitCode}
Success: ${result.success}
Duration: ${result.duration}ms
Timestamp: ${new Date().toISOString()}
Target: ${targetUrl}

${"=".repeat(60)}
STDOUT:
${"=".repeat(60)}
${result.stdout || "(empty)"}

${"=".repeat(60)}
STDERR:
${"=".repeat(60)}
${result.stderr || "(empty)"}

${result.error ? `\n${"=".repeat(60)}\nERROR:\n${"=".repeat(60)}\n${result.error}\n` : ""}
`;
    writeFileSync(logPath, logContent);
  }

  // Save summary
  const summaryPath = path.join(logsDir, "poc-run-summary.json");
  const summary = {
    timestamp: new Date().toISOString(),
    benchmarkName,
    targetUrl,
    total: pocFiles.length,
    passed,
    failed,
    skipped: pocFiles.filter((f) => f.endsWith(".html")).length,
    results: results.map((r) => ({
      pocFile: r.pocFile,
      pocName: r.pocName,
      exitCode: r.exitCode,
      success: r.success,
      duration: r.duration,
      error: r.error,
    })),
  };
  writeFileSync(summaryPath, JSON.stringify(summary, null, 2));

  console.log(
    `[${benchmarkName}] 📊 POC Re-run Summary: ${passed} passed, ${failed} failed, ${summary.skipped} skipped`
  );
  console.log(`[${benchmarkName}] 📁 POC logs saved to: ${logsDir}`);

  return { total: pocFiles.length, passed, failed, results };
}

/**
 * Run a single benchmark with Daytona sandbox using Docker-in-Docker
 * Agent runs locally, but commands/requests execute in sandbox
 */
export async function runBenchmarkWithDaytona(
  options: DaytonaBenchmarkOptions
): Promise<BenchmarkResults> {
  const { benchmarkPath, benchmarkName, model, prefix } = options;
  const apiKey = options.apiKey || process.env.DAYTONA_API_KEY;
  const orgId = options.orgId || process.env.DAYTONA_ORG_ID;
  const startTime = Date.now();

  if (!apiKey) {
    throw new Error("DAYTONA_API_KEY is required");
  }

  console.log(`\n${"=".repeat(80)}`);
  console.log(`[${benchmarkName}] STARTING DAYTONA BENCHMARK`);
  console.log(`${"=".repeat(80)}`);
  console.log(`[${benchmarkName}] Path: ${benchmarkPath}`);
  console.log(`[${benchmarkName}] Model: ${model}`);
  console.log(`${"=".repeat(80)}\n`);

  // Parse docker-compose port before creating sandbox
  console.log(`[${benchmarkName}] 🔍 Parsing docker-compose for web service...`);
  const portInfo = parseDockerComposePort(benchmarkPath);
  console.log(
    `[${benchmarkName}] ✅ Found web service: ${portInfo.serviceName} on port ${portInfo.hostPort}${portInfo.needsPortMapping ? " (added port mapping)" : ""}`
  );

  const daytona = new Daytona({ apiKey });

  let sandbox: Sandbox | undefined;
  let remoteBenchmarkPath = "";

  try {
    // Step 1: Create sandbox with DinD support and sufficient resources
    console.log(`[${benchmarkName}] 🚀 Creating Daytona sandbox with Docker-in-Docker...`);

    // Create image with required tools pre-installed
    const dindImage = Image.base("docker:28.3.3-dind").runCommands(
      "apk add --no-cache curl make bash coreutils git jq"
    );

    sandbox = await daytona.create(
      {
        language: "typescript",
        envVars: {
          ANTHROPIC_API_KEY:
            options.anthropicKey || process.env.ANTHROPIC_API_KEY || "",
          OPENROUTER_API_KEY:
            options.openrouterKey || process.env.OPENROUTER_API_KEY || "",
        },
        public: true,
        networkBlockAll: false,
        // Increased resources for Docker-in-Docker (per Daytona docs)
        resources: {
          cpu: 4, // At least 2 vCPU recommended for DinD
          memory: 8, // At least 4GiB recommended for DinD
          disk: 4, // More disk for Docker images
        },
        image: dindImage,
      },
      { timeout: 300000 } // 5 minute timeout for sandbox creation
    );

    console.log(`[${benchmarkName}] ✅ Sandbox created: ${sandbox.id}`);

    // Wait for sandbox to be ready
    console.log(
      `[${benchmarkName}] ⏳ Waiting for sandbox to be ready...`
    );
    await new Promise((resolve) => setTimeout(resolve, 5000));

    // Start Docker daemon manually (DinD image entrypoint may not run in Daytona)
    console.log(`[${benchmarkName}] 🐳 Starting Docker daemon...`);

    // First check if dockerd is already running
    const psCheck = await sandbox.process.executeCommand(
      "ps aux | grep -v grep | grep dockerd || echo 'not running'",
      undefined,
      undefined,
      10000
    );
    console.log(`[${benchmarkName}] 📋 Docker process check: ${psCheck.result?.trim()}`);

    // Try using the DinD entrypoint script if available, or start dockerd directly
    // Use storage-driver=vfs which works without device-mapper/overlay issues in nested containers
    const startDaemonResult = await sandbox.process.executeCommand(
      `(dockerd-entrypoint.sh dockerd --storage-driver=vfs > /var/log/dockerd.log 2>&1 &) || (dockerd --storage-driver=vfs --host=unix:///var/run/docker.sock > /var/log/dockerd.log 2>&1 &)`,
      undefined,
      undefined,
      30000
    );

    console.log(`[${benchmarkName}] 📋 Start daemon result: ${startDaemonResult.result?.substring(0, 200)}`);

    // Wait for Docker daemon to be ready
    console.log(`[${benchmarkName}] ⏳ Waiting for Docker daemon to start...`);
    let dockerReady = false;
    for (let attempt = 0; attempt < 30; attempt++) {
      // Wait a bit before checking
      await new Promise((resolve) => setTimeout(resolve, 2000));

      // Check if daemon socket exists and is responsive
      const dockerCheckResult = await sandbox.process.executeCommand(
        "docker version --format '{{.Server.Version}}' 2>&1",
        undefined,
        undefined,
        10000
      );

      // If we get a version number, daemon is ready
      if (dockerCheckResult.exitCode === 0 && dockerCheckResult.result && !dockerCheckResult.result.includes("Cannot connect")) {
        console.log(`[${benchmarkName}] ✅ Docker daemon version: ${dockerCheckResult.result.trim()}`);
        dockerReady = true;
        break;
      }

      // Log progress with more details on certain attempts
      if (attempt === 0 || attempt === 5 || attempt === 10 || attempt === 20) {
        // Check daemon logs
        const logSnippet = await sandbox.process.executeCommand(
          "tail -5 /var/log/dockerd.log 2>/dev/null || echo 'no logs yet'",
          undefined,
          undefined,
          5000
        );
        console.log(
          `[${benchmarkName}] ⏳ Docker check (attempt ${attempt + 1}/30): ${dockerCheckResult.result?.substring(0, 150)}`
        );
        console.log(`[${benchmarkName}]    Daemon log: ${logSnippet.result?.substring(0, 200)}`);
      } else {
        console.log(
          `[${benchmarkName}] ⏳ Docker not ready, waiting... (attempt ${attempt + 1}/30)`
        );
      }
    }

    if (!dockerReady) {
      // Get full dockerd logs for debugging
      const logsResult = await sandbox.process.executeCommand(
        "cat /var/log/dockerd.log 2>&1 | tail -100",
        undefined,
        undefined,
        10000
      );
      console.error(`[${benchmarkName}] Docker daemon logs:\n${logsResult.result}`);

      // Also check dmesg for kernel issues
      const dmesgResult = await sandbox.process.executeCommand(
        "dmesg 2>&1 | tail -20 || echo 'dmesg not available'",
        undefined,
        undefined,
        10000
      );
      console.error(`[${benchmarkName}] System logs:\n${dmesgResult.result}`);

      throw new Error("Docker daemon failed to start in sandbox after 30 attempts");
    }

    console.log(`[${benchmarkName}] ✅ Docker daemon is ready`);

    // Check docker-compose
    console.log(`[${benchmarkName}] 📦 Checking docker-compose...`);
    const composeCheck = await sandbox.process.executeCommand(
      "docker compose version || docker-compose version",
      undefined,
      undefined,
      30000
    );
    console.log(`[${benchmarkName}] ✅ Docker Compose: ${composeCheck.result?.trim()}`);

    // Step 2: Upload benchmark directory to sandbox
    console.log(`[${benchmarkName}] 📦 Uploading benchmark directory...`);
    const userHome = await sandbox.getUserHomeDir();
    if (!userHome) console.info("User home directory path is empty in sandbox");
    // Use posix path for Linux sandbox
    remoteBenchmarkPath = path.posix.join(userHome ?? "", "benchmark");

    // Collect all files from benchmark directory
    const filesToUpload = collectFilesRecursive(benchmarkPath, benchmarkPath);
    console.log(
      `[${benchmarkName}] 📁 Found ${filesToUpload.length} files to upload`
    );

    // Map to Daytona upload format with remote path prefix (use posix paths for Linux sandbox)
    const uploadFiles = filesToUpload.map((file) => ({
      source: file.source,
      // Convert local path separators to posix for remote paths
      destination: path.posix.join(
        remoteBenchmarkPath,
        file.destination.replace(/\\/g, "/")
      ),
    }));

    // Upload files in batches to avoid overwhelming the API
    const BATCH_SIZE = 10;
    const batches = [];
    for (let i = 0; i < uploadFiles.length; i += BATCH_SIZE) {
      batches.push(uploadFiles.slice(i, i + BATCH_SIZE));
    }

    try {
      console.log(
        `[${benchmarkName}] 📤 Uploading ${uploadFiles.length} files in ${batches.length} batch(es)...`
      );

      for (let i = 0; i < batches.length; i++) {
        const batch = batches[i]!;
        console.log(
          `[${benchmarkName}] 📦 Batch ${i + 1}/${batches.length}: ${batch.length} files...`
        );
        await sandbox.fs.uploadFiles(batch, 300);

        // Small delay between batches to avoid rate limiting
        if (i < batches.length - 1) {
          await new Promise((resolve) => setTimeout(resolve, 1000));
        }
      }

      console.log(
        `[${benchmarkName}] ✅ Benchmark uploaded to ${remoteBenchmarkPath}`
      );
    } catch (uploadError: any) {
      console.error(`[${benchmarkName}] ❌ Upload failed: ${uploadError.message}`);
      if (uploadError.response) {
        console.error(
          `[${benchmarkName}] Response status: ${uploadError.response.status}`
        );
        console.error(
          `[${benchmarkName}] Response data:`,
          uploadError.response.data
        );
      }
      throw new Error(`File upload failed: ${uploadError.message}`);
    }

    // Step 3: Extract flag from local benchmark directory
    console.log(`[${benchmarkName}] 🔍 Extracting flag from benchmark...`);
    const expectedFlag = await extractFlagFromRepo(benchmarkPath, benchmarkName);

    if (expectedFlag) {
      console.log(
        `[${benchmarkName}] ✅ FLAG found: ${expectedFlag.substring(0, 20)}...`
      );
    } else {
      console.log(`[${benchmarkName}] ⚠️  FLAG not found in benchmark`);
    }

    // Step 4: Build docker images with flag injection using make build
    console.log(`[${benchmarkName}] 🔨 Building docker images with make build...`);

    // Clear BuildKit cache to avoid corruption issues with VFS storage driver
    console.log(`[${benchmarkName}] 🧹 Clearing BuildKit cache...`);
    await sandbox.process.executeCommand(
      "docker builder prune -af 2>/dev/null || true",
      undefined,
      undefined,
      30000
    );

    const buildResult = await sandbox.process.executeCommand(
      `cd ${remoteBenchmarkPath} && make build`,
      undefined,
      {
        FLAG: expectedFlag || "",
      },
      300000 // 5 minute timeout for builds
    );

    if (buildResult.exitCode !== 0) {
      // Try docker compose build as fallback
      console.log(`[${benchmarkName}] ⚠️  make build failed, trying docker compose build...`);
      const composeResult = await sandbox.process.executeCommand(
        `cd ${remoteBenchmarkPath} && docker compose build`,
        undefined,
        {
          FLAG: expectedFlag || "",
        },
        300000
      );

      if (composeResult.exitCode !== 0) {
        throw new Error(
          `Failed to build docker images: ${composeResult.result} CODE: ${composeResult.exitCode}`
        );
      }
    }

    console.log(`[${benchmarkName}] ✅ Docker images built`);

    // Step 5: Start docker compose
    console.log(`[${benchmarkName}] 🐳 Starting docker compose...`);
    const startDockerResult = await sandbox.process.executeCommand(
      `cd ${remoteBenchmarkPath} && docker compose up -d --wait`,
      undefined,
      undefined,
      180000 // 3 minute timeout
    );

    if (startDockerResult.exitCode !== 0) {
      throw new Error(
        `Failed to start docker compose: ${startDockerResult.result} CODE: ${startDockerResult.exitCode}`
      );
    }

    console.log(`[${benchmarkName}] ✅ Docker compose started`);

    // Wait a bit for services to be ready
    console.log(`[${benchmarkName}] ⏳ Waiting for services to be ready...`);
    await new Promise((resolve) => setTimeout(resolve, 10000));

    // Step 6: Query Docker to get the actual mapped host port
    console.log(`[${benchmarkName}] 🔍 Querying Docker for actual port mapping...`);
    const portQueryResult = await sandbox.process.executeCommand(
      `cd ${remoteBenchmarkPath} && docker compose port ${portInfo.serviceName} ${portInfo.containerPort} 2>/dev/null | cut -d: -f2 || echo "${portInfo.hostPort}"`,
      undefined,
      undefined,
      30000
    );

    const actualHostPort = parseInt(portQueryResult.result?.trim() || String(portInfo.hostPort), 10);

    // Step 7: Build target URL from actual mapped port
    const targetUrl = `http://localhost:${actualHostPort}`;
    console.log(`[${benchmarkName}] 🎯 Target URL: ${targetUrl}`);

    const preview = await sandbox.getPreviewLink(actualHostPort);
    console.log(`[${benchmarkName}] Preview URL: ${preview.url}`);

    // Step 8: Create local session with benchmark guidance and scope constraints
    const sessionPrefix = prefix ? `${prefix}-${benchmarkName}` : `benchmark-${benchmarkName}`;
    const session = createSession(
      targetUrl,
      `Benchmark testing for ${benchmarkName}`,
      sessionPrefix,
      {
        outcomeGuidance: BENCHMARK_OUTCOME_GUIDANCE,
        scopeConstraints: {
          allowedHosts: ["localhost"],
          allowedPorts: [actualHostPort],
          strictScope: true,
        },
      }
    );

    console.log(`[${benchmarkName}] 📝 Local session created: ${session.id}`);

    // Step 9: Create tool overrides that proxy to Daytona sandbox
    // These must return EXACTLY the same format as the original tools in tools.ts
    const executeCommandOverride = async (
      opts: ExecuteCommandOpts
    ): Promise<ExecuteCommandResult> => {
      try {
        if (!sandbox) throw new Error("Sandbox not created");

        // Execute command directly - Daytona combines stdout/stderr in result
        const result = await sandbox.process.executeCommand(
          opts.command,
          undefined,
          undefined,
          opts.timeout || 120000
        );

        const output = result.result || "";
        const success = result.exitCode === 0;

        // Match the exact format from tools.ts
        return {
          command: opts.command,
          success,
          stdout: output,
          stderr: success ? "" : output,
          error: success ? "" : output,
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
        if (!sandbox) throw new Error("Sandbox not created");

        // Build curl command - use -i to include headers in output
        const timeoutSec = Math.ceil((opts.timeout || 10000) / 1000);
        let curlCmd = `curl -s -i --max-time ${timeoutSec} --connect-timeout 10`;

        // Handle redirects
        if (opts.followRedirects !== false) {
          curlCmd += " -L --max-redirs 10";
        }

        // Add method
        curlCmd += ` -X ${opts.method || "GET"}`;

        // Add headers
        if (opts.headers) {
          for (const [key, value] of Object.entries(opts.headers)) {
            const safeValue = String(value).replace(/'/g, "'\\''");
            curlCmd += ` -H '${key}: ${safeValue}'`;
          }
        }

        // Add body using heredoc for complex payloads
        if (opts.body) {
          // Use base64 to safely transfer the body
          const bodyBase64 = Buffer.from(opts.body).toString("base64");
          curlCmd = `echo '${bodyBase64}' | base64 -d | curl -s -i --max-time ${timeoutSec} --connect-timeout 10`;
          if (opts.followRedirects !== false) {
            curlCmd += " -L --max-redirs 10";
          }
          curlCmd += ` -X ${opts.method || "GET"}`;
          if (opts.headers) {
            for (const [key, value] of Object.entries(opts.headers)) {
              const safeValue = String(value).replace(/'/g, "'\\''");
              curlCmd += ` -H '${key}: ${safeValue}'`;
            }
          }
          curlCmd += " --data-binary @-";
        }

        // Add URL
        const safeUrl = opts.url.replace(/'/g, "'\\''");
        curlCmd += ` '${safeUrl}'`;

        const result = await sandbox.process.executeCommand(
          curlCmd,
          undefined,
          undefined,
          (opts.timeout || 10000) + 15000
        );

        const output = result.result || "";

        // Parse curl -i output: headers\r\n\r\nbody
        // Find the blank line separating headers from body
        const headerEndIndex = output.indexOf("\r\n\r\n");
        let headersText = "";
        let body = "";

        if (headerEndIndex !== -1) {
          headersText = output.substring(0, headerEndIndex);
          body = output.substring(headerEndIndex + 4);
        } else {
          // Try with just \n\n
          const altIndex = output.indexOf("\n\n");
          if (altIndex !== -1) {
            headersText = output.substring(0, altIndex);
            body = output.substring(altIndex + 2);
          } else {
            body = output;
          }
        }

        // Parse status from first line: HTTP/1.1 200 OK
        const statusLine = headersText.split("\n")[0] || "";
        const statusMatch = statusLine.match(/HTTP\/[\d.]+\s+(\d+)\s*(.*)/);
        const status = statusMatch ? parseInt(statusMatch[1], 10) : 0;
        const statusText = statusMatch ? statusMatch[2]?.trim() || "" : "";

        // Parse headers
        const headers: Record<string, string> = {};
        const headerLines = headersText.split("\n").slice(1);
        for (const line of headerLines) {
          const colonIndex = line.indexOf(":");
          if (colonIndex > 0) {
            const key = line.substring(0, colonIndex).trim().toLowerCase();
            const value = line.substring(colonIndex + 1).trim();
            if (key) {
              headers[key] = value;
            }
          }
        }

        // Detect redirect
        const redirected = headers["location"] !== undefined || status >= 300 && status < 400;

        // Truncate body like the original tool does (5000 chars)
        const truncatedBody = body.length > 5000
          ? `${body.substring(0, 5000)}... \n\n (truncated) use execute_command with grep / tail to paginate the response`
          : body;

        // Match the exact format from tools.ts - success: true if no exception
        return {
          success: true,
          status,
          statusText,
          headers,
          body: truncatedBody,
          url: opts.url,
          redirected,
        };
      } catch (error: any) {
        // Match the exact error format from tools.ts
        return {
          success: false,
          url: opts.url,
          status: 0,
          statusText: "",
          headers: {},
          body: "",
          redirected: false,
        };
      }
    };

    // Step 10: Run streamlined pentest (scope constraints are in session config)
    console.log(`[${benchmarkName}] 🔍 Starting streamlined pentest...`);
    const pentestResult = await runStreamlinedPentest({
      target: targetUrl,
      model,
      session,
      toolOverride: {
        execute_command: executeCommandOverride,
        http_request: httpRequestOverride,
      },
      onProgress: (status) => {
        const progressParts: string[] = [`[${benchmarkName}] [${status.phase}]`];

        if (
          status.tasksCompleted !== undefined &&
          status.totalTasks !== undefined
        ) {
          progressParts.push(`[${status.tasksCompleted}/${status.totalTasks} tasks]`);
        }
        if (status.activeAgents !== undefined && status.activeAgents > 0) {
          progressParts.push(`[${status.activeAgents} active]`);
        }
        progressParts.push(status.message);

        console.log(progressParts.join(" "));

        if (status.findingsCount !== undefined && status.findingsCount > 0) {
          console.log(`[${benchmarkName}]   Findings so far: ${status.findingsCount}`);
        }
      },
      sessionConfig: {
        remoteSandboxUrl: preview.url
      }
    });

    if (!pentestResult.success) {
      console.log(
        `[${benchmarkName}] ⚠️  Pentest completed with error: ${pentestResult.error}`
      );
    }

    console.log(
      `[${benchmarkName}] ✅ Pentest completed. Total findings: ${pentestResult.totalFindings}`
    );

    // Step 11: Run comparison agent
    console.log(`[${benchmarkName}] 📊 Running comparison agent...`);
    let comparison;
    try {
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

    // Step 12: Detect flag in artifacts
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
        locations: [],
        searchLocations: [],
      };
    }

    // Step 13: Re-run all POCs and save their outputs
    console.log(`[${benchmarkName}] 🔄 Re-running POCs...`);
    const pocRunResults = await rerunAllPocsInSandbox(
      sandbox,
      session.rootPath,
      remoteBenchmarkPath,
      benchmarkName,
      targetUrl
    );

    // Step 14: Generate benchmark results
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
      pocRunSummary:
        pocRunResults.total > 0
          ? {
              total: pocRunResults.total,
              passed: pocRunResults.passed,
              failed: pocRunResults.failed,
              skipped: pocRunResults.results.filter((r) => r.exitCode === null)
                .length,
              results: pocRunResults.results.map((r) => ({
                pocFile: r.pocFile,
                pocName: r.pocName,
                exitCode: r.exitCode,
                success: r.success,
                duration: r.duration,
                error: r.error,
              })),
            }
          : undefined,
      timestamp: new Date().toISOString(),
    };

    const reportPath = path.join(session.rootPath, "benchmark_results.json");
    writeFileSync(reportPath, JSON.stringify(results, null, 2));

    console.log(`\n[${benchmarkName}] 📄 Benchmark report saved to: ${reportPath}`);
    console.log(
      `\n[${benchmarkName}] 🎯 FLAG STATUS: ${flagDetection.detected ? "✅ DETECTED" : "❌ NOT DETECTED"}`
    );
    if (flagDetection.detected) {
      console.log(
        `[${benchmarkName}]    Found in: ${flagDetection.foundIn.join(", ")}`
      );
      if (flagDetection.locations && flagDetection.locations.length > 0) {
        console.log(`[${benchmarkName}]    Exact locations:`);
        for (const loc of flagDetection.locations.slice(0, 5)) {
          // Show first 5 locations
          console.log(`[${benchmarkName}]      ${loc.file}:${loc.line}`);
        }
        if (flagDetection.locations.length > 5) {
          console.log(
            `[${benchmarkName}]      ... and ${flagDetection.locations.length - 5} more`
          );
        }
      }
    }
    if (pocRunResults.total > 0) {
      console.log(
        `\n[${benchmarkName}] 🧪 POC RESULTS: ${pocRunResults.passed}/${pocRunResults.total} passed`
      );
    }

    const duration = ((Date.now() - startTime) / 1000 / 60).toFixed(2);
    console.log(`\n[${benchmarkName}] ✅ Completed in ${duration}m`);

    return results;
  } catch (error: any) {
    const duration = ((Date.now() - startTime) / 1000 / 60).toFixed(2);
    console.error(`\n[${benchmarkName}] ❌ Failed after ${duration}m: ${error.message}`);

    // Return a failure result
    return {
      repoPath: benchmarkPath,
      branch: benchmarkName,
      targetUrl: "",
      sessionId: "",
      sessionPath: "",
      flagDetection: {
        detected: false,
        flagValue: null,
        foundIn: [],
        locations: [],
        searchLocations: [],
      },
      expectedFlag: null,
      expectedResults: [],
      actualResults: [],
      comparison: {
        totalExpected: 0,
        totalActual: 0,
        matched: [],
        missed: [],
        extra: [],
        accuracy: 0,
        recall: 0,
        precision: 0,
      },
      timestamp: new Date().toISOString(),
    };
  } finally {
    // Cleanup: Stop docker and delete sandbox
    if (sandbox) {
      try {
        console.log(`[${benchmarkName}] 🧹 Cleaning up sandbox...`);

        // Only try to stop docker if we successfully uploaded and started it
        if (remoteBenchmarkPath) {
          try {
            console.log(`[${benchmarkName}] 🐳 Stopping docker compose...`);
            await sandbox.process.executeCommand(
              `cd ${remoteBenchmarkPath} && docker compose down`,
              undefined,
              undefined,
              30000
            );
          } catch (dockerError: any) {
            // Don't fail cleanup if docker stop fails (might not have started)
            console.log(
              `[${benchmarkName}] ⚠️  Docker stop failed (may not have started): ${dockerError.message}`
            );
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
            console.log(
              `[${benchmarkName}] ⚠️  Refresh failed (attempt ${attempts + 1}): ${refreshError.message}`
            );
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
          console.error(
            `[${benchmarkName}] ⚠️  Failed to delete sandbox: ${deleteError.message}`
          );
          console.error(
            `[${benchmarkName}] ⚠️  You may need to manually delete sandbox: ${sandbox.id}`
          );
        }
      } catch (error: any) {
        console.error(`[${benchmarkName}] ⚠️  Cleanup error: ${error.message}`);
        console.error(
          `[${benchmarkName}] ⚠️  Sandbox may still be running: ${sandbox.id}`
        );
      }
    }
  }
}

/**
 * Generate markdown summary report
 */
function generateMarkdownSummary(summary: any): string {
  const lines = [
    "# Daytona Benchmark Results",
    "",
    `**Repository**: ${summary.repoPath}`,
    `**Model**: ${summary.model}`,
    `**Mode**: Daytona Docker-in-Docker`,
    `**Timestamp**: ${new Date(summary.timestamp).toLocaleString()}`,
    `**Duration**: ${summary.duration}m`,
    "",
    "## Summary",
    "",
    `- Total Benchmarks: ${summary.totalBenchmarks}`,
    `- Successful: ${summary.successful}/${summary.totalBenchmarks}`,
    `- Failed: ${summary.failed}/${summary.totalBenchmarks}`,
    `- Flags Detected: ${summary.flagsDetected}/${summary.totalBenchmarks} (${Math.round((summary.flagsDetected / summary.totalBenchmarks) * 100)}%)`,
    `- Flags Missed: ${summary.flagsMissed}/${summary.totalBenchmarks}`,
  ];

  // Add POC stats if available
  if (summary.pocStats && summary.pocStats.total > 0) {
    lines.push(
      `- POCs Passed: ${summary.pocStats.passed}/${summary.pocStats.total} (${Math.round((summary.pocStats.passed / summary.pocStats.total) * 100)}%)`
    );
  }

  lines.push("");
  lines.push("## Benchmark Results");
  lines.push("");

  for (const benchmark of summary.benchmarks) {
    const statusIcon = benchmark.status === "success" ? "✅" : "❌";
    const flagIcon = benchmark.flagDetected ? "🎯" : "❌";

    lines.push(`### ${statusIcon} ${benchmark.benchmark}`);
    lines.push("");
    lines.push(`- **Status**: ${benchmark.status}`);

    if (benchmark.status === "success") {
      lines.push(
        `- **Flag Detected**: ${flagIcon} ${benchmark.flagDetected ? "YES" : "NO"}`
      );
      if (benchmark.flagDetected) {
        lines.push(`  - Expected: \`${benchmark.expectedFlag}\``);
        lines.push(`  - Found in: ${benchmark.foundIn.join(", ")}`);
      }
      lines.push(`- **Metrics**:`);
      lines.push(`  - Accuracy: ${benchmark.metrics.accuracy}%`);
      lines.push(`  - Precision: ${benchmark.metrics.precision}%`);
      lines.push(`  - Recall: ${benchmark.metrics.recall}%`);
      if (benchmark.pocResults) {
        lines.push(
          `- **POC Results**: ${benchmark.pocResults.passed}/${benchmark.pocResults.total} passed`
        );
      }
      lines.push(`- **Session**: [${benchmark.sessionPath}](${benchmark.sessionPath})`);
    } else {
      lines.push(`- **Error**: ${benchmark.error}`);
    }

    lines.push("");
  }

  return lines.join("\n");
}

/**
 * Run benchmarks across multiple benchmarks in parallel with Daytona Docker-in-Docker
 */
export async function runMultipleBenchmarks(
  options: MultipleBenchmarkOptions
): Promise<BenchmarkResults[]> {
  const benchmarks = options.benchmarks || [];

  if (benchmarks.length === 0) {
    throw new Error("No benchmarks provided");
  }

  const maxParallel = options.maxParallel || 10;
  const startTime = Date.now();

  console.log("\n" + "=".repeat(80));
  console.log("🚀 STARTING PARALLEL DAYTONA BENCHMARK EXECUTION");
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
        const benchmarkPath = path.join(
          options.repoPath,
          "benchmarks",
          benchmarkName
        );
        return runBenchmarkWithDaytona({
          benchmarkPath,
          benchmarkName,
          model: options.model,
          apiKey: options.apiKey,
          orgId: options.orgId,
          anthropicKey: options.anthropicKey,
          openrouterKey: options.openrouterKey,
          prefix: options.prefix,
        });
      })
    )
  );

  const totalDuration = ((Date.now() - startTime) / 1000 / 60).toFixed(2);
  const flagsDetected = results.filter((r) => r.flagDetection?.detected).length;
  const flagsMissed = results.filter((r) => !r.flagDetection?.detected).length;
  const successful = results.filter(
    (r) => !(r.comparison as any).error && r.sessionId
  ).length;
  const failed = results.filter(
    (r) => !!(r.comparison as any).error || !r.sessionId
  ).length;

  // Aggregate POC results
  const totalPocs = results.reduce(
    (sum, r) => sum + (r.pocRunSummary?.total || 0),
    0
  );
  const passedPocs = results.reduce(
    (sum, r) => sum + (r.pocRunSummary?.passed || 0),
    0
  );
  const failedPocs = results.reduce(
    (sum, r) => sum + (r.pocRunSummary?.failed || 0),
    0
  );

  console.log("\n" + "=".repeat(80));
  console.log("📊 BENCHMARK SUMMARY");
  console.log("=".repeat(80));
  console.log(`Total Duration: ${totalDuration}m`);
  console.log(`Total Benchmarks: ${benchmarks.length}`);
  console.log(`Successful: ${successful}/${benchmarks.length}`);
  console.log(`Failed: ${failed}/${benchmarks.length}`);
  console.log(
    `Flags Detected: ${flagsDetected}/${benchmarks.length} (${Math.round((flagsDetected / benchmarks.length) * 100)}%)`
  );
  console.log(`Flags Missed: ${flagsMissed}/${benchmarks.length}`);
  if (totalPocs > 0) {
    console.log(
      `POCs Passed: ${passedPocs}/${totalPocs} (${Math.round((passedPocs / totalPocs) * 100)}%)`
    );
  }
  console.log("=".repeat(80));

  // Generate summary report
  const summaryDirName = options.prefix
    ? `${options.prefix}-${new Date().toISOString().replace(/[:.]/g, "-")}`
    : `daytona-run-${new Date().toISOString().replace(/[:.]/g, "-")}`;
  const summaryDir = path.join(
    process.cwd(),
    ".pensar",
    "benchmarks",
    "executions",
    summaryDirName
  );

  mkdirSync(summaryDir, { recursive: true });

  const summary = {
    timestamp: new Date().toISOString(),
    repoPath: options.repoPath,
    model: options.model,
    mode: "daytona-dind",
    totalBenchmarks: benchmarks.length,
    successful,
    failed,
    flagsDetected,
    flagsMissed,
    pocStats: {
      total: totalPocs,
      passed: passedPocs,
      failed: failedPocs,
    },
    duration: totalDuration,
    benchmarks: results.map((r) => ({
      benchmark: r.branch,
      status: (r.comparison as any).error || !r.sessionId ? "failed" : "success",
      error: (r.comparison as any).error,
      flagDetected: r.flagDetection?.detected || false,
      expectedFlag: r.expectedFlag,
      foundIn: r.flagDetection?.foundIn || [],
      sessionPath: r.sessionPath,
      metrics: {
        accuracy: Math.round((r.comparison.accuracy || 0) * 100),
        precision: Math.round((r.comparison.precision || 0) * 100),
        recall: Math.round((r.comparison.recall || 0) * 100),
      },
      pocResults: r.pocRunSummary
        ? {
            total: r.pocRunSummary.total,
            passed: r.pocRunSummary.passed,
            failed: r.pocRunSummary.failed,
          }
        : undefined,
    })),
  };

  writeFileSync(
    path.join(summaryDir, "summary.json"),
    JSON.stringify(summary, null, 2)
  );

  // Generate markdown summary
  const markdown = generateMarkdownSummary(summary);
  writeFileSync(path.join(summaryDir, "summary.md"), markdown);

  console.log(`\n📄 Summary report saved to: ${summaryDir}/summary.json`);
  console.log(`📄 Markdown report saved to: ${summaryDir}/summary.md\n`);

  return results;
}
