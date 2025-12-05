#!/usr/bin/env tsx

import { readdirSync, statSync, existsSync, mkdirSync, writeFileSync, readFileSync } from "fs";
import path from "path";
import { exec as nodeExec } from "child_process";
import { promisify } from "util";
import type { AIModel } from "../src/core/ai";
import pLimit from "p-limit";
import type { BenchmarkResults } from "../src/core/agent/benchmark/types";
import { parseDockerComposePort, getActualDockerPort } from "../src/core/agent/benchmark/docker-utils";
import { createSession, BENCHMARK_OUTCOME_GUIDANCE } from "../src/core/agent/sessions";
import { runStreamlinedPentest } from "../src/core/agent/thoroughPentestAgent/streamlined";
import { runComparisonAgent } from "../src/core/agent/benchmark/comparisonAgent";
import { extractFlagFromRepo, detectFlagInArtifacts } from "../src/core/agent/benchmark/flag-detector";

const exec = promisify(nodeExec);

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
 * Re-run all POC scripts in a session and save their outputs
 */
async function rerunAllPocs(
  sessionPath: string,
  benchmarkName: string,
  targetUrl: string
): Promise<{ total: number; passed: number; failed: number; results: PocRunResult[] }> {
  const pocsDir = path.join(sessionPath, "pocs");
  const logsDir = path.join(pocsDir, "logs");

  // Check if pocs directory exists
  if (!existsSync(pocsDir)) {
    console.log(`[${benchmarkName}] 📁 No POCs directory found, skipping POC re-run`);
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
    const logFileName = `${pocName}-${new Date().toISOString().replace(/[:.]/g, "-")}.log`;
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

    // Execute bash POC
    const startTime = Date.now();
    let result: PocRunResult;

    try {
      // Make script executable
      await exec(`chmod +x "${pocPath}"`);

      // Run the POC with a timeout of 2 minutes
      // Set TARGET environment variable to override any hardcoded target
      const { stdout, stderr } = await exec(`bash "${pocPath}"`, {
        timeout: 120000,
        env: {
          ...process.env,
          TARGET: targetUrl,
        },
        cwd: pocsDir,
      });

      const duration = Date.now() - startTime;
      result = {
        pocFile,
        pocName,
        exitCode: 0,
        stdout,
        stderr,
        duration,
        success: true,
      };
      passed++;
      console.log(`[${benchmarkName}]   ✅ ${pocFile} (${(duration / 1000).toFixed(1)}s)`);
    } catch (error: any) {
      const duration = Date.now() - startTime;
      result = {
        pocFile,
        pocName,
        exitCode: error.code ?? 1,
        stdout: error.stdout || "",
        stderr: error.stderr || error.message || "",
        duration,
        success: false,
        error: error.message,
      };
      failed++;
      console.log(`[${benchmarkName}]   ❌ ${pocFile} (exit code: ${result.exitCode})`);
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

  console.log(`[${benchmarkName}] 📊 POC Re-run Summary: ${passed} passed, ${failed} failed, ${summary.skipped} skipped`);
  console.log(`[${benchmarkName}] 📁 POC logs saved to: ${logsDir}`);

  return { total: pocFiles.length, passed, failed, results };
}

interface CLIOptions {
  repoPath: string;
  benchmarks?: string[];
  model?: AIModel;
  anthropicKey?: string;
  openrouterKey?: string;
  maxParallel?: number;
}

/**
 * Enumerate all XBEN-* benchmark directories in /benchmarks
 */
function enumerateXBENBenchmarks(repoPath: string): string[] {
  console.log(`🔍 Enumerating XBEN benchmarks in ${repoPath}/benchmarks...`);

  const benchmarksDir = path.join(repoPath, "benchmarks");

  if (!existsSync(benchmarksDir)) {
    throw new Error(`Benchmarks directory not found: ${benchmarksDir}`);
  }

  try {
    const entries = readdirSync(benchmarksDir);

    const xbenBenchmarks = entries.filter((entry) => {
      const fullPath = path.join(benchmarksDir, entry);
      const isDirectory = statSync(fullPath).isDirectory();
      const isXBEN = entry.startsWith("XBEN");
      return isDirectory && isXBEN;
    });

    console.log(`✅ Found ${xbenBenchmarks.length} XBEN benchmarks: ${xbenBenchmarks.join(", ")}`);

    return xbenBenchmarks;
  } catch (error: any) {
    throw new Error(`Failed to enumerate benchmarks: ${error.message}`);
  }
}

/**
 * Run a single benchmark locally
 */
async function runSingleBenchmark(
  benchmarkPath: string,
  benchmarkName: string,
  model: AIModel
): Promise<BenchmarkResults> {
  const startTime = Date.now();

  try {
    console.log(`\n${"=".repeat(80)}`);
    console.log(`[${benchmarkName}] STARTING LOCAL BENCHMARK`);
    console.log(`${"=".repeat(80)}`);
    console.log(`[${benchmarkName}] Path: ${benchmarkPath}`);
    console.log(`[${benchmarkName}] Model: ${model}`);
    console.log(`${"=".repeat(80)}\n`);

    // Step 1: Parse docker-compose port before building and ensure ports are forwarded
    console.log(`[${benchmarkName}] 🔍 Parsing docker-compose for web service...`);
    const portInfo = parseDockerComposePort(benchmarkPath);
    console.log(`[${benchmarkName}] ✅ Found web service: ${portInfo.serviceName} on port ${portInfo.hostPort}${portInfo.needsPortMapping ? " (added port mapping)" : ""}`);

    // Step 2: Extract flag from local benchmark directory
    console.log(`[${benchmarkName}] 🔍 Extracting flag from benchmark...`);
    const expectedFlag = await extractFlagFromRepo(benchmarkPath, benchmarkName);

    if (expectedFlag) {
      console.log(`[${benchmarkName}] ✅ FLAG found: ${expectedFlag.substring(0, 20)}...`);
    } else {
      console.log(`[${benchmarkName}] ⚠️  FLAG not found in benchmark`);
    }

    // Step 3: Build docker images with flag injection using make build
    console.log(`[${benchmarkName}] 🔨 Building docker images with make build...`);

    // Change to benchmark directory and run make build
    const buildResult = await exec("make build", {
      cwd: benchmarkPath,
      env: {
        ...process.env,
        // Pass the flag as environment variable if needed
        FLAG: expectedFlag || "",
      },
    });

    console.log(`[${benchmarkName}] ✅ Docker images built`);
    if (buildResult.stdout) {
      console.log(`[${benchmarkName}] Build output: ${buildResult.stdout.substring(0, 200)}...`);
    }

    // Step 4: Start docker compose
    console.log(`[${benchmarkName}] 🐳 Starting docker compose...`);
    await exec("docker compose up -d --wait", { cwd: benchmarkPath });
    console.log(`[${benchmarkName}] ✅ Docker compose started`);

    // Wait a bit for services to be ready
    console.log(`[${benchmarkName}] ⏳ Waiting for services to be ready...`);
    await new Promise((resolve) => setTimeout(resolve, 10000));

    // Step 5: Query Docker to get the actual mapped host port
    console.log(`[${benchmarkName}] 🔍 Querying Docker for actual port mapping...`);
    const actualHostPort = await getActualDockerPort(
      benchmarkPath,
      portInfo.serviceName,
      portInfo.containerPort
    );

    // Step 6: Build target URL from actual mapped port
    const targetUrl = `http://localhost:${actualHostPort}`;
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
          allowedPorts: [actualHostPort],
          strictScope: true,
        },
      }
    );

    console.log(`[${benchmarkName}] 📝 Local session created: ${session.id}`);

    // Step 8: Run streamlined pentest (scope constraints are in session config)
    console.log(`[${benchmarkName}] 🔍 Starting streamlined pentest...`);
    const pentestResult = await runStreamlinedPentest({
      target: targetUrl,
      model,
      session,
      onProgress: (status) => {
        const progressParts: string[] = [`[${benchmarkName}] [${status.phase}]`];

        if (status.tasksCompleted !== undefined && status.totalTasks !== undefined) {
          progressParts.push(`[${status.tasksCompleted}/${status.totalTasks} tasks]`);
        }
        if (status.activeAgents !== undefined && status.activeAgents > 0) {
          progressParts.push(`[${status.activeAgents} active]`);
        }
        progressParts.push(status.message);

        console.log(progressParts.join(' '));

        if (status.findingsCount !== undefined && status.findingsCount > 0) {
          console.log(`[${benchmarkName}]   Findings so far: ${status.findingsCount}`);
        }
      },
    });

    if (!pentestResult.success) {
      console.log(`[${benchmarkName}] ⚠️  Pentest completed with error: ${pentestResult.error}`);
    }

    console.log(`[${benchmarkName}] ✅ Pentest completed. Total findings: ${pentestResult.totalFindings}`);

    // Step 9: Run comparison agent
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

    // Step 10: Detect flag in artifacts
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

    // Step 11: Re-run all POCs and save their outputs
    console.log(`[${benchmarkName}] 🔄 Re-running POCs...`);
    const pocRunResults = await rerunAllPocs(session.rootPath, benchmarkName, targetUrl);

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
      pocRunSummary: pocRunResults.total > 0 ? {
        total: pocRunResults.total,
        passed: pocRunResults.passed,
        failed: pocRunResults.failed,
        skipped: pocRunResults.results.filter(r => r.exitCode === null).length,
        results: pocRunResults.results.map(r => ({
          pocFile: r.pocFile,
          pocName: r.pocName,
          exitCode: r.exitCode,
          success: r.success,
          duration: r.duration,
          error: r.error,
        })),
      } : undefined,
      timestamp: new Date().toISOString(),
    };

    const reportPath = path.join(session.rootPath, "benchmark_results.json");
    writeFileSync(reportPath, JSON.stringify(results, null, 2));

    console.log(`\n[${benchmarkName}] 📄 Benchmark report saved to: ${reportPath}`);
    console.log(`\n[${benchmarkName}] 🎯 FLAG STATUS: ${flagDetection.detected ? "✅ DETECTED" : "❌ NOT DETECTED"}`);
    if (flagDetection.detected) {
      console.log(`[${benchmarkName}]    Found in: ${flagDetection.foundIn.join(", ")}`);
      if (flagDetection.locations && flagDetection.locations.length > 0) {
        console.log(`[${benchmarkName}]    Exact locations:`);
        for (const loc of flagDetection.locations.slice(0, 5)) { // Show first 5 locations
          console.log(`[${benchmarkName}]      ${loc.file}:${loc.line}`);
        }
        if (flagDetection.locations.length > 5) {
          console.log(`[${benchmarkName}]      ... and ${flagDetection.locations.length - 5} more`);
        }
      }
    }
    if (pocRunResults.total > 0) {
      console.log(`\n[${benchmarkName}] 🧪 POC RESULTS: ${pocRunResults.passed}/${pocRunResults.total} passed`);
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
        // error: error.message,
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
    // Step 13: Cleanup - Stop docker compose
    try {
      console.log(`[${benchmarkName}] 🧹 Stopping docker compose...`);
      await exec("docker compose down", { cwd: benchmarkPath });
      console.log(`[${benchmarkName}] ✅ Cleanup complete`);
    } catch (cleanupError: any) {
      console.error(`[${benchmarkName}] ⚠️  Cleanup failed: ${cleanupError.message}`);
    }
  }
}

/**
 * Run multiple benchmarks in parallel
 */
async function runMultipleBenchmarks(
  repoPath: string,
  benchmarks: string[],
  model: AIModel,
  maxParallel: number
): Promise<BenchmarkResults[]> {
  const startTime = Date.now();

  console.log("\n" + "=".repeat(80));
  console.log("🚀 STARTING PARALLEL LOCAL BENCHMARK EXECUTION");
  console.log("=".repeat(80));
  console.log(`Repository: ${repoPath}`);
  console.log(`Benchmarks: ${benchmarks.length}`);
  console.log(`Model: ${model}`);
  console.log(`Max Parallel: ${maxParallel}`);
  console.log("=".repeat(80) + "\n");

  // Run with concurrency limit
  const limit = pLimit(maxParallel);
  const results = await Promise.all(
    benchmarks.map((benchmarkName) =>
      limit(() => {
        const benchmarkPath = path.join(repoPath, "benchmarks", benchmarkName);
        return runSingleBenchmark(benchmarkPath, benchmarkName, model);
      })
    )
  );

  const totalDuration = ((Date.now() - startTime) / 1000 / 60).toFixed(2);
  const flagsDetected = results.filter((r) => r.flagDetection?.detected).length;
  const flagsMissed = results.filter((r) => !r.flagDetection?.detected).length;
  const successful = results.filter(r => !(r.comparison as any).error).length;
  const failed = results.filter(r => !!(r.comparison as any).error).length;

  // Aggregate POC results
  const totalPocs = results.reduce((sum, r) => sum + (r.pocRunSummary?.total || 0), 0);
  const passedPocs = results.reduce((sum, r) => sum + (r.pocRunSummary?.passed || 0), 0);
  const failedPocs = results.reduce((sum, r) => sum + (r.pocRunSummary?.failed || 0), 0);

  console.log("\n" + "=".repeat(80));
  console.log("📊 BENCHMARK SUMMARY");
  console.log("=".repeat(80));
  console.log(`Total Duration: ${totalDuration}m`);
  console.log(`Total Benchmarks: ${benchmarks.length}`);
  console.log(`Successful: ${successful}/${benchmarks.length}`);
  console.log(`Failed: ${failed}/${benchmarks.length}`);
  console.log(`Flags Detected: ${flagsDetected}/${benchmarks.length} (${Math.round((flagsDetected / benchmarks.length) * 100)}%)`);
  console.log(`Flags Missed: ${flagsMissed}/${benchmarks.length}`);
  if (totalPocs > 0) {
    console.log(`POCs Passed: ${passedPocs}/${totalPocs} (${Math.round((passedPocs / totalPocs) * 100)}%)`);
  }
  console.log("=".repeat(80));

  // Generate summary report
  const summaryDir = path.join(
    process.cwd(),
    ".pensar",
    "benchmarks",
    "executions",
    `local-run-${new Date().toISOString().replace(/[:.]/g, "-")}`
  );

  mkdirSync(summaryDir, { recursive: true });

  const summary = {
    timestamp: new Date().toISOString(),
    repoPath,
    model,
    mode: "local",
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
      status: (r.comparison as any).error ? "failed" : "success",
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
      pocResults: r.pocRunSummary ? {
        total: r.pocRunSummary.total,
        passed: r.pocRunSummary.passed,
        failed: r.pocRunSummary.failed,
      } : undefined,
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

/**
 * Generate markdown summary report
 */
function generateMarkdownSummary(summary: any): string {
  const lines = [
    "# Local Benchmark Results",
    "",
    `**Repository**: ${summary.repoPath}`,
    `**Model**: ${summary.model}`,
    `**Mode**: Local Execution`,
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
    lines.push(`- POCs Passed: ${summary.pocStats.passed}/${summary.pocStats.total} (${Math.round((summary.pocStats.passed / summary.pocStats.total) * 100)}%)`);
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
      lines.push(`- **Flag Detected**: ${flagIcon} ${benchmark.flagDetected ? "YES" : "NO"}`);
      if (benchmark.flagDetected) {
        lines.push(`  - Expected: \`${benchmark.expectedFlag}\``);
        lines.push(`  - Found in: ${benchmark.foundIn.join(", ")}`);
      }
      lines.push(`- **Metrics**:`);
      lines.push(`  - Accuracy: ${benchmark.metrics.accuracy}%`);
      lines.push(`  - Precision: ${benchmark.metrics.precision}%`);
      lines.push(`  - Recall: ${benchmark.metrics.recall}%`);
      if (benchmark.pocResults) {
        lines.push(`- **POC Results**: ${benchmark.pocResults.passed}/${benchmark.pocResults.total} passed`);
      }
      lines.push(`- **Session**: [${benchmark.sessionPath}](${benchmark.sessionPath})`);
    } else {
      lines.push(`- **Error**: ${benchmark.error}`);
    }

    lines.push("");
  }

  return lines.join("\n");
}

async function main() {
  const args = process.argv.slice(2);

  if (args.length === 0) {
    console.error("Usage: bun run scripts/local-benchmark.ts <repo-path> [options] [XBEN-001-24 XBEN-002-24 ...]");
    console.error();
    console.error("Arguments:");
    console.error("  <repo-path>          Local path to XBEN challenges repository");
    console.error();
    console.error("Options:");
    console.error("  --model <model>              AI model to use (default: claude-sonnet-4-5)");
    console.error("  --anthropic-key <key>        Anthropic API key (default: ANTHROPIC_API_KEY env)");
    console.error("  --openrouter-key <key>       OpenRouter API key (default: OPENROUTER_API_KEY env)");
    console.error("  --max-parallel <num>         Max concurrent benchmarks (default: 4)");
    console.error();
    console.error("Environment Variables:");
    console.error("  ANTHROPIC_API_KEY            Anthropic API key (or --anthropic-key)");
    console.error("  OPENROUTER_API_KEY           OpenRouter API key (or --openrouter-key)");
    console.error();
    console.error("Benchmark Selection:");
    console.error("  • If no benchmarks specified: Automatically runs ALL benchmarks in /benchmarks/XBEN-*");
    console.error("  • If benchmarks specified: Runs only those specific XBEN benchmarks");
    console.error();
    console.error("Examples:");
    console.error("  # Run ALL XBEN benchmarks (auto-discovers all /benchmarks/XBEN-* directories)");
    console.error("  bun run scripts/local-benchmark.ts /path/to/xben-challenges");
    console.error();
    console.error("  # Run specific XBEN benchmark(s)");
    console.error("  bun run scripts/local-benchmark.ts /path/to/xben-challenges XBEN-001-24");
    console.error("  bun run scripts/local-benchmark.ts /path/to/xben-challenges XBEN-001-24 XBEN-002-24");
    console.error();
    console.error("  # Run with custom model and parallel limit");
    console.error("  bun run scripts/local-benchmark.ts /path/to/xben-challenges \\");
    console.error("    --model claude-haiku-4-5 --max-parallel 2");
    console.error();
    console.error("How it works:");
    console.error("  - Runs benchmarks LOCALLY (no remote sandbox)");
    console.error("  - Enumerates XBEN-* directories in /benchmarks");
    console.error("  - Starts docker compose locally for each benchmark");
    console.error("  - Runs thoroughPentestAgent locally against the running application");
    console.error("  - Compares results with expected findings");
    console.error("  - Detects flags in pentest artifacts");
    console.error("  - Stops docker compose and cleans up");
    console.error("  - Generates comprehensive reports");
    console.error();
    console.error("Differences from Daytona benchmark:");
    console.error("  ✓ No Daytona API key needed");
    console.error("  ✓ Runs entirely on local machine");
    console.error("  ✓ Uses local Docker daemon");
    console.error("  ✓ Faster for local development/testing");
    console.error("  ✗ No isolation between benchmarks");
    console.error("  ✗ Limited by local machine resources");
    console.error();
    process.exit(1);
  }

  const repoPath = args[0]!;

  // Validate repo path exists
  if (!existsSync(repoPath)) {
    console.error(`Error: Repository path does not exist: ${repoPath}`);
    process.exit(1);
  }

  if (!statSync(repoPath).isDirectory()) {
    console.error(`Error: Path is not a directory: ${repoPath}`);
    process.exit(1);
  }

  // Parse options
  const options: CLIOptions = { repoPath };

  // Parse --model
  const modelIndex = args.indexOf("--model");
  if (modelIndex !== -1) {
    const modelValue = args[modelIndex + 1];
    if (!modelValue) {
      console.error("Error: --model must be followed by a model name");
      process.exit(1);
    }
    options.model = modelValue as AIModel;
  }

  // Parse --anthropic-key
  const anthropicKeyIndex = args.indexOf("--anthropic-key");
  if (anthropicKeyIndex !== -1) {
    const anthropicKeyValue = args[anthropicKeyIndex + 1];
    if (!anthropicKeyValue) {
      console.error("Error: --anthropic-key must be followed by a key");
      process.exit(1);
    }
    options.anthropicKey = anthropicKeyValue;
  }

  // Parse --openrouter-key
  const openrouterKeyIndex = args.indexOf("--openrouter-key");
  if (openrouterKeyIndex !== -1) {
    const openrouterKeyValue = args[openrouterKeyIndex + 1];
    if (!openrouterKeyValue) {
      console.error("Error: --openrouter-key must be followed by a key");
      process.exit(1);
    }
    options.openrouterKey = openrouterKeyValue;
  }

  // Parse --max-parallel
  const maxParallelIndex = args.indexOf("--max-parallel");
  if (maxParallelIndex !== -1) {
    const maxParallelValue = args[maxParallelIndex + 1];
    if (!maxParallelValue) {
      console.error("Error: --max-parallel must be followed by a number");
      process.exit(1);
    }
    const maxParallelNum = parseInt(maxParallelValue, 10);
    if (isNaN(maxParallelNum) || maxParallelNum < 1) {
      console.error("Error: --max-parallel must be a positive number");
      process.exit(1);
    }
    options.maxParallel = maxParallelNum;
  }

  // Parse benchmark arguments
  const flagArgs = [
    "--model",
    "--anthropic-key",
    "--openrouter-key",
    "--max-parallel",
  ];

  const benchmarks: string[] = [];
  for (let i = 1; i < args.length; i++) {
    const arg = args[i]!;

    // Skip flag names
    if (flagArgs.includes(arg)) {
      i++; // Also skip the next arg (flag value)
      continue;
    }

    // Skip flag values
    if (i > 0 && flagArgs.includes(args[i - 1]!)) {
      continue;
    }

    // This is a benchmark name
    benchmarks.push(arg);
  }

  // If no benchmarks specified, enumerate all XBEN benchmarks
  let targetBenchmarks: string[];
  if (benchmarks.length === 0) {
    console.log("No benchmarks specified, enumerating all XBEN-* benchmarks...\n");
    targetBenchmarks = enumerateXBENBenchmarks(repoPath);

    if (targetBenchmarks.length === 0) {
      console.error("Error: No XBEN benchmarks found in /benchmarks directory");
      console.error("Please ensure the repository has /benchmarks/XBEN-* directories");
      console.error("Or specify benchmarks manually as arguments");
      process.exit(1);
    }
  } else {
    targetBenchmarks = benchmarks;
    console.log(`Using specified benchmarks: ${targetBenchmarks.join(", ")}\n`);
  }

  options.benchmarks = targetBenchmarks;

  // Validate environment variables
  const anthropicKey = options.anthropicKey || process.env.ANTHROPIC_API_KEY;
  const openrouterKey = options.openrouterKey || process.env.OPENROUTER_API_KEY;

  if (!anthropicKey && !openrouterKey) {
    console.error("Error: At least one AI API key is required");
    console.error("Set ANTHROPIC_API_KEY or OPENROUTER_API_KEY environment variable");
    console.error("Or use --anthropic-key or --openrouter-key flag");
    process.exit(1);
  }

  // Set environment variables for the agents to use
  if (anthropicKey) {
    process.env.ANTHROPIC_API_KEY = anthropicKey;
  }
  if (openrouterKey) {
    process.env.OPENROUTER_API_KEY = openrouterKey;
  }

  // Display configuration
  console.log("\n" + "=".repeat(80));
  console.log("LOCAL BENCHMARK RUNNER");
  console.log("=".repeat(80));
  console.log(`Repository: ${options.repoPath}`);
  console.log(`Benchmarks: ${targetBenchmarks.join(", ")}`);
  console.log(`Total Benchmarks: ${targetBenchmarks.length}`);
  console.log(`Model: ${options.model || "claude-sonnet-4-5"}`);
  console.log(`Max Parallel: ${options.maxParallel || 4}`);
  console.log(`AI Keys: ${anthropicKey ? "Anthropic ✓" : ""} ${openrouterKey ? "OpenRouter ✓" : ""}`);
  console.log("=".repeat(80));
  console.log();
  console.log("Architecture:");
  console.log("  • Runs entirely locally (no remote sandbox)");
  console.log("  • Uses local Docker daemon");
  console.log("  • Starts docker compose for each benchmark");
  console.log("  • Runs thoroughPentestAgent locally");
  console.log("  • Compares results with expected findings");
  console.log("  • Detects flags in artifacts");
  console.log("  • Generates comprehensive reports");
  console.log("=".repeat(80) + "\n");

  try {
    if (targetBenchmarks.length === 1) {
      // Single benchmark - run directly
      console.log(`Running single benchmark: ${targetBenchmarks[0]}`);
      const benchmarkPath = path.join(repoPath, "benchmarks", targetBenchmarks[0]!);
      await runSingleBenchmark(
        benchmarkPath,
        targetBenchmarks[0]!,
        (options.model || "claude-sonnet-4-5") as AIModel
      );
    } else {
      // Multiple benchmarks - run in parallel
      console.log(`Running parallel benchmark for ${targetBenchmarks.length} benchmarks`);
      await runMultipleBenchmarks(
        repoPath,
        targetBenchmarks,
        (options.model || "claude-sonnet-4-5") as AIModel,
        options.maxParallel || 4
      );
    }

    console.log("\n✅ Benchmark execution completed successfully!");
  } catch (error: any) {
    console.error("\n❌ Benchmark execution failed:");
    console.error(error.message);
    if (error.stack) {
      console.error("\nStack trace:");
      console.error(error.stack);
    }
    process.exit(1);
  }
}

main().catch((error) => {
  console.error("Unhandled error:", error);
  process.exit(1);
});
