#!/usr/bin/env tsx

import { readdirSync, statSync, existsSync } from "fs";
import path from "path";
import {
  runBenchmarkWithDaytona,
  runMultipleBenchmarks,
} from "../src/core/agent/benchmark/remote/daytona-benchmark";
import type { AIModel } from "../src/core/ai";

interface CLIOptions {
  repoPath: string;
  benchmarks?: string[];
  model?: AIModel;
  apiKey?: string;
  orgId?: string;
  anthropicKey?: string;
  openrouterKey?: string;
  maxParallel?: number;
}

/**
 * Enumerate all XBOW-* benchmark directories in /benchmarks
 */
function enumerateXBOWBenchmarks(repoPath: string): string[] {
  console.log(`🔍 Enumerating XBOW benchmarks in ${repoPath}/benchmarks...`);

  const benchmarksDir = path.join(repoPath, "benchmarks");

  if (!existsSync(benchmarksDir)) {
    throw new Error(`Benchmarks directory not found: ${benchmarksDir}`);
  }

  try {
    const entries = readdirSync(benchmarksDir);

    const xbowBenchmarks = entries.filter((entry) => {
      const fullPath = path.join(benchmarksDir, entry);
      const isDirectory = statSync(fullPath).isDirectory();
      const isXBOW = entry.startsWith("XBEN");
      return isDirectory && isXBOW;
    });

    console.log(`✅ Found ${xbowBenchmarks.length} XBOW benchmarks: ${xbowBenchmarks.join(", ")}`);

    return xbowBenchmarks;
  } catch (error: any) {
    throw new Error(`Failed to enumerate benchmarks: ${error.message}`);
  }
}

async function main() {
  const args = process.argv.slice(2);

  if (args.length === 0) {
    console.error("Usage: bun run scripts/daytona-benchmark.ts <repo-path> [options] [XBOW-001-24 XBOW-002-24 ...]");
    console.error();
    console.error("Arguments:");
    console.error("  <repo-path>          Local path to XBOW challenges repository");
    console.error();
    console.error("Options:");
    console.error("  --model <model>              AI model to use (default: claude-sonnet-4-5)");
    console.error("  --daytona-api-key <key>      Daytona API key (default: DAYTONA_API_KEY env)");
    console.error("  --daytona-org-id <id>        Daytona organization ID (optional, default: DAYTONA_ORG_ID env)");
    console.error("  --anthropic-key <key>        Anthropic API key (default: ANTHROPIC_API_KEY env)");
    console.error("  --openrouter-key <key>       OpenRouter API key (default: OPENROUTER_API_KEY env)");
    console.error("  --max-parallel <num>         Max concurrent sandboxes (default: 4)");
    console.error();
    console.error("Environment Variables Required:");
    console.error("  DAYTONA_API_KEY              Daytona API key (required)");
    console.error("  ANTHROPIC_API_KEY            Anthropic API key (or --anthropic-key)");
    console.error("  OPENROUTER_API_KEY           OpenRouter API key (or --openrouter-key)");
    console.error();
    console.error("Environment Variables Optional:");
    console.error("  DAYTONA_ORG_ID               Daytona organization ID");
    console.error();
    console.error("Benchmark Selection:");
    console.error("  • If no benchmarks specified: Automatically runs ALL benchmarks in /benchmarks/XBOW-*");
    console.error("  • If benchmarks specified: Runs only those specific XBOW benchmarks");
    console.error();
    console.error("Examples:");
    console.error("  # Run ALL XBOW benchmarks (auto-discovers all /benchmarks/XBOW-* directories)");
    console.error("  bun run scripts/daytona-benchmark.ts /path/to/xbow-challenges");
    console.error();
    console.error("  # Run specific XBOW benchmark(s)");
    console.error("  bun run scripts/daytona-benchmark.ts /path/to/xbow-challenges XBOW-001-24");
    console.error("  bun run scripts/daytona-benchmark.ts /path/to/xbow-challenges XBOW-001-24 XBOW-002-24");
    console.error();
    console.error("  # Run with custom model and parallel limit");
    console.error("  bun run scripts/daytona-benchmark.ts /path/to/xbow-challenges \\");
    console.error("    --model claude-haiku-4-5 --max-parallel 2");
    console.error();
    console.error("How it works:");
    console.error("  - Enumerates XBOW-* directories in /benchmarks");
    console.error("  - Uploads each benchmark directory to Daytona sandbox");
    console.error("  - Parses docker-compose to determine target port/URL");
    console.error("  - Runs docker compose up in sandbox");
    console.error("  - Agent runs locally but commands execute in sandbox via tool overrides");
    console.error("  - Results saved locally for comparison and flag detection");
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

  // Parse --daytona-api-key
  const apiKeyIndex = args.indexOf("--daytona-api-key");
  if (apiKeyIndex !== -1) {
    const apiKeyValue = args[apiKeyIndex + 1];
    if (!apiKeyValue) {
      console.error("Error: --daytona-api-key must be followed by a key");
      process.exit(1);
    }
    options.apiKey = apiKeyValue;
  }

  // Parse --daytona-org-id
  const orgIdIndex = args.indexOf("--daytona-org-id");
  if (orgIdIndex !== -1) {
    const orgIdValue = args[orgIdIndex + 1];
    if (!orgIdValue) {
      console.error("Error: --daytona-org-id must be followed by an ID");
      process.exit(1);
    }
    options.orgId = orgIdValue;
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

  // Parse benchmark arguments (anything that's not a flag or flag value)
  const flagArgs = [
    "--model",
    "--daytona-api-key",
    "--daytona-org-id",
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

  // If no benchmarks specified, enumerate all XBOW benchmarks
  let targetBenchmarks: string[];
  if (benchmarks.length === 0) {
    console.log("No benchmarks specified, enumerating all XBOW-* benchmarks...\n");
    targetBenchmarks = enumerateXBOWBenchmarks(repoPath);

    if (targetBenchmarks.length === 0) {
      console.error("Error: No XBOW benchmarks found in /benchmarks directory");
      console.error("Please ensure the repository has /benchmarks/XBOW-* directories");
      console.error("Or specify benchmarks manually as arguments");
      process.exit(1);
    }
  } else {
    targetBenchmarks = benchmarks;
    console.log(`Using specified benchmarks: ${targetBenchmarks.join(", ")}\n`);
  }

  options.benchmarks = targetBenchmarks;

  // Validate environment variables
  const apiKey = options.apiKey || process.env.DAYTONA_API_KEY;
  const orgId = options.orgId || process.env.DAYTONA_ORG_ID;
  const anthropicKey = options.anthropicKey || process.env.ANTHROPIC_API_KEY;
  const openrouterKey = options.openrouterKey || process.env.OPENROUTER_API_KEY;

  if (!apiKey) {
    console.error("Error: DAYTONA_API_KEY is required");
    console.error("Set it via environment variable or --daytona-api-key flag");
    process.exit(1);
  }

  if (!anthropicKey && !openrouterKey) {
    console.error("Error: At least one AI API key is required");
    console.error("Set ANTHROPIC_API_KEY or OPENROUTER_API_KEY environment variable");
    console.error("Or use --anthropic-key or --openrouter-key flag");
    process.exit(1);
  }

  // Display configuration
  console.log("\n" + "=".repeat(80));
  console.log("DAYTONA HYBRID BENCHMARK RUNNER");
  console.log("=".repeat(80));
  console.log(`Repository: ${options.repoPath}`);
  console.log(`Benchmarks: ${targetBenchmarks.join(", ")}`);
  console.log(`Total Benchmarks: ${targetBenchmarks.length}`);
  console.log(`Model: ${options.model || "claude-sonnet-4-5"}`);
  console.log(`Max Parallel: ${options.maxParallel || 4}`);
  if (orgId) {
    console.log(`Daytona Org: ${orgId}`);
  }
  console.log(`AI Keys: ${anthropicKey ? "Anthropic ✓" : ""} ${openrouterKey ? "OpenRouter ✓" : ""}`);
  console.log("=".repeat(80));
  console.log();
  console.log("Architecture:");
  console.log("  • Uploads benchmark directory to Daytona sandbox");
  console.log("  • Parses docker-compose for target port");
  console.log("  • Daytona sandbox hosts target application (docker compose)");
  console.log("  • Agent runs locally with tool overrides");
  console.log("  • Commands/requests execute in sandbox");
  console.log("  • Results saved locally for analysis");
  console.log("=".repeat(80) + "\n");

  try {
    if (targetBenchmarks.length === 1) {
      // Single benchmark - run directly
      console.log(`Running single benchmark: ${targetBenchmarks[0]}`);
      const benchmarkPath = path.join(repoPath, "benchmarks", targetBenchmarks[0]!);
      await runBenchmarkWithDaytona({
        benchmarkPath,
        benchmarkName: targetBenchmarks[0]!,
        model: (options.model || "claude-sonnet-4-5") as AIModel,
        apiKey,
        orgId,
        anthropicKey,
        openrouterKey,
      });
    } else {
      // Multiple benchmarks - run in parallel
      console.log(`Running parallel benchmark for ${targetBenchmarks.length} benchmarks`);
      await runMultipleBenchmarks({
        repoPath,
        benchmarks: targetBenchmarks,
        model: (options.model || "claude-sonnet-4-5") as AIModel,
        apiKey,
        orgId,
        anthropicKey,
        openrouterKey,
        maxParallel: options.maxParallel,
      });
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
