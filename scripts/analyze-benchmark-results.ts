#!/usr/bin/env tsx

import { readdirSync, existsSync, readFileSync, statSync } from "fs";
import path from "path";

interface FlagDetection {
  detected: boolean;
  flagValue: string | null;
  foundIn: string[];
  locations: Array<{
    file: string;
    line: number;
    context: string;
  }>;
  searchLocations: string[];
}

interface PocResult {
  pocFile: string;
  pocName: string;
  exitCode: number | null;
  success: boolean;
  duration: number;
  error?: string;
}

interface PocRunSummary {
  total: number;
  passed: number;
  failed: number;
  skipped: number;
  results: PocResult[];
}

interface BenchmarkResult {
  repoPath: string;
  branch: string;
  targetUrl: string;
  sessionId: string;
  sessionPath: string;
  flagDetection: FlagDetection;
  expectedFlag: string | null;
  expectedResults: any[];
  actualResults: any[];
  comparison: {
    totalExpected: number;
    totalActual: number;
    matched: any[];
    missed: any[];
    extra: any[];
    accuracy: number;
    recall: number;
    precision: number;
  };
  pocRunSummary?: PocRunSummary;
  timestamp: string;
}

interface AnalysisResults {
  totalBenchmarks: number;
  flagsDetected: number;
  flagsMissed: number;
  detectionRate: number;
  pocStats: {
    totalPocs: number;
    passedPocs: number;
    failedPocs: number;
    skippedPocs: number;
    passRate: number;
  };
  benchmarkDetails: Array<{
    id: string;
    detected: boolean;
    expectedFlag: string | null;
    actualFlag: string | null;
    foundIn: string[];
    pocPassed?: number;
    pocTotal?: number;
    timestamp: string;
  }>;
  detectedBenchmarks: string[];
  missedBenchmarks: string[];
}

function loadBenchmarkResults(resultsDir: string): Map<string, BenchmarkResult> {
  const results = new Map<string, BenchmarkResult>();

  if (!existsSync(resultsDir)) {
    console.error(`Results directory not found: ${resultsDir}`);
    process.exit(1);
  }

  const entries = readdirSync(resultsDir);

  for (const entry of entries) {
    const fullPath = path.join(resultsDir, entry);

    // Skip non-directories and __MACOSX
    if (!statSync(fullPath).isDirectory() || entry === "__MACOSX") {
      continue;
    }

    // Look for benchmark_results.json
    const resultsFile = path.join(fullPath, "benchmark_results.json");
    if (!existsSync(resultsFile)) {
      console.warn(`Warning: No benchmark_results.json in ${entry}`);
      continue;
    }

    try {
      const content = readFileSync(resultsFile, "utf-8");
      const result = JSON.parse(content) as BenchmarkResult;

      // Extract XBEN ID from directory name or branch
      const match = entry.match(/benchmark-(XBEN-\d+-\d+)-/);
      const id = match ? match[1] : result.branch || entry;

      results.set(id, result);
    } catch (error: any) {
      console.warn(`Warning: Failed to parse ${resultsFile}: ${error.message}`);
    }
  }

  return results;
}

function analyzeResults(results: Map<string, BenchmarkResult>): AnalysisResults {
  const benchmarkDetails: AnalysisResults["benchmarkDetails"] = [];
  const detectedBenchmarks: string[] = [];
  const missedBenchmarks: string[] = [];

  let totalPocs = 0;
  let passedPocs = 0;
  let failedPocs = 0;
  let skippedPocs = 0;

  // Sort by benchmark ID
  const sortedIds = Array.from(results.keys()).sort((a, b) => {
    const numA = parseInt(a.match(/\d+/)?.[0] || "0");
    const numB = parseInt(b.match(/\d+/)?.[0] || "0");
    return numA - numB;
  });

  for (const id of sortedIds) {
    const result = results.get(id)!;
    const detected = result.flagDetection?.detected || false;

    if (detected) {
      detectedBenchmarks.push(id);
    } else {
      missedBenchmarks.push(id);
    }

    // POC stats
    if (result.pocRunSummary) {
      totalPocs += result.pocRunSummary.total;
      passedPocs += result.pocRunSummary.passed;
      failedPocs += result.pocRunSummary.failed;
      skippedPocs += result.pocRunSummary.skipped;
    }

    benchmarkDetails.push({
      id,
      detected,
      expectedFlag: result.expectedFlag,
      actualFlag: result.flagDetection?.flagValue || null,
      foundIn: result.flagDetection?.foundIn || [],
      pocPassed: result.pocRunSummary?.passed,
      pocTotal: result.pocRunSummary?.total,
      timestamp: result.timestamp,
    });
  }

  const totalBenchmarks = results.size;
  const flagsDetected = detectedBenchmarks.length;
  const flagsMissed = missedBenchmarks.length;

  return {
    totalBenchmarks,
    flagsDetected,
    flagsMissed,
    detectionRate: totalBenchmarks > 0 ? (flagsDetected / totalBenchmarks) * 100 : 0,
    pocStats: {
      totalPocs,
      passedPocs,
      failedPocs,
      skippedPocs,
      passRate: totalPocs > 0 ? (passedPocs / totalPocs) * 100 : 0,
    },
    benchmarkDetails,
    detectedBenchmarks,
    missedBenchmarks,
  };
}

function printReport(analysis: AnalysisResults): void {
  const width = 80;
  const divider = "═".repeat(width);
  const thinDivider = "─".repeat(width);

  console.log("\n" + divider);
  console.log("                    BENCHMARK ANALYSIS REPORT");
  console.log(divider);

  // Summary stats
  console.log("\n📊 SUMMARY STATISTICS\n");
  console.log(`  Total Benchmarks:      ${analysis.totalBenchmarks}`);
  console.log(`  Flags Detected:        ${analysis.flagsDetected} ✅`);
  console.log(`  Flags Missed:          ${analysis.flagsMissed} ❌`);
  console.log(`  Detection Rate:        ${analysis.detectionRate.toFixed(1)}%`);

  // Visual bar
  const barWidth = 40;
  const filledWidth = Math.round((analysis.detectionRate / 100) * barWidth);
  const emptyWidth = barWidth - filledWidth;
  const bar = "█".repeat(filledWidth) + "░".repeat(emptyWidth);
  console.log(`  Progress:              [${bar}]`);

  // POC stats
  if (analysis.pocStats.totalPocs > 0) {
    console.log("\n📝 POC EXECUTION STATISTICS\n");
    console.log(`  Total POCs:            ${analysis.pocStats.totalPocs}`);
    console.log(`  Passed:                ${analysis.pocStats.passedPocs} ✅`);
    console.log(`  Failed:                ${analysis.pocStats.failedPocs} ❌`);
    console.log(`  Skipped (HTML):        ${analysis.pocStats.skippedPocs} ⏭️`);
    console.log(`  Pass Rate:             ${analysis.pocStats.passRate.toFixed(1)}%`);
  }

  // Detected benchmarks
  console.log("\n" + thinDivider);
  console.log("\n✅ FLAGS DETECTED (" + analysis.detectedBenchmarks.length + ")\n");

  if (analysis.detectedBenchmarks.length > 0) {
    for (const id of analysis.detectedBenchmarks) {
      const detail = analysis.benchmarkDetails.find(d => d.id === id)!;
      const pocInfo = detail.pocTotal !== undefined
        ? ` [POC: ${detail.pocPassed}/${detail.pocTotal}]`
        : "";
      console.log(`  ✓ ${id}${pocInfo}`);
      if (detail.foundIn.length > 0) {
        const locations = detail.foundIn.slice(0, 2).map(f => path.basename(f)).join(", ");
        const more = detail.foundIn.length > 2 ? ` +${detail.foundIn.length - 2} more` : "";
        console.log(`      Found in: ${locations}${more}`);
      }
    }
  } else {
    console.log("  (none)");
  }

  // Missed benchmarks
  console.log("\n" + thinDivider);
  console.log("\n❌ FLAGS MISSED (" + analysis.missedBenchmarks.length + ")\n");

  if (analysis.missedBenchmarks.length > 0) {
    for (const id of analysis.missedBenchmarks) {
      const detail = analysis.benchmarkDetails.find(d => d.id === id)!;
      const pocInfo = detail.pocTotal !== undefined
        ? ` [POC: ${detail.pocPassed}/${detail.pocTotal}]`
        : "";
      console.log(`  ✗ ${id}${pocInfo}`);
      if (detail.expectedFlag) {
        console.log(`      Expected: ${detail.expectedFlag.substring(0, 30)}...`);
      }
    }
  } else {
    console.log("  (none)");
  }

  // Full details table
  console.log("\n" + thinDivider);
  console.log("\n📋 DETAILED RESULTS\n");

  // Table header
  console.log("  " + "ID".padEnd(15) + "Status".padEnd(10) + "POCs".padEnd(12) + "Timestamp");
  console.log("  " + "-".repeat(15) + "-".repeat(10) + "-".repeat(12) + "-".repeat(20));

  for (const detail of analysis.benchmarkDetails) {
    const status = detail.detected ? "✅ FOUND" : "❌ MISS";
    const pocs = detail.pocTotal !== undefined
      ? `${detail.pocPassed}/${detail.pocTotal}`
      : "N/A";
    const timestamp = detail.timestamp
      ? new Date(detail.timestamp).toLocaleDateString()
      : "N/A";

    console.log(`  ${detail.id.padEnd(15)}${status.padEnd(10)}${pocs.padEnd(12)}${timestamp}`);
  }

  console.log("\n" + divider);
  console.log("                         END OF REPORT");
  console.log(divider + "\n");
}

function printJsonReport(analysis: AnalysisResults): void {
  const jsonReport = {
    summary: {
      totalBenchmarks: analysis.totalBenchmarks,
      flagsDetected: analysis.flagsDetected,
      flagsMissed: analysis.flagsMissed,
      detectionRate: `${analysis.detectionRate.toFixed(1)}%`,
    },
    pocStats: analysis.pocStats.totalPocs > 0 ? {
      totalPocs: analysis.pocStats.totalPocs,
      passedPocs: analysis.pocStats.passedPocs,
      failedPocs: analysis.pocStats.failedPocs,
      skippedPocs: analysis.pocStats.skippedPocs,
      passRate: `${analysis.pocStats.passRate.toFixed(1)}%`,
    } : undefined,
    detected: analysis.detectedBenchmarks,
    missed: analysis.missedBenchmarks,
    details: analysis.benchmarkDetails,
  };

  console.log(JSON.stringify(jsonReport, null, 2));
}

async function main() {
  const args = process.argv.slice(2);

  // Default results directory
  let resultsDir = path.join(process.cwd(), "tmp", "benchmark-results");
  let outputFormat = "text";

  // Parse arguments
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg === "--json") {
      outputFormat = "json";
    } else if (arg === "--dir" && args[i + 1]) {
      resultsDir = args[i + 1]!;
      i++;
    } else if (arg === "--help" || arg === "-h") {
      console.log("Usage: bun run scripts/analyze-benchmark-results.ts [options]");
      console.log("");
      console.log("Options:");
      console.log("  --dir <path>    Directory containing benchmark results (default: tmp/benchmark-results)");
      console.log("  --json          Output results in JSON format");
      console.log("  --help, -h      Show this help message");
      console.log("");
      console.log("Examples:");
      console.log("  bun run scripts/analyze-benchmark-results.ts");
      console.log("  bun run scripts/analyze-benchmark-results.ts --json");
      console.log("  bun run scripts/analyze-benchmark-results.ts --dir /path/to/results");
      process.exit(0);
    } else if (!arg?.startsWith("-")) {
      resultsDir = arg!;
    }
  }

  console.log(`Loading benchmark results from: ${resultsDir}`);

  const results = loadBenchmarkResults(resultsDir);

  if (results.size === 0) {
    console.error("No benchmark results found!");
    process.exit(1);
  }

  console.log(`Loaded ${results.size} benchmark results\n`);

  const analysis = analyzeResults(results);

  if (outputFormat === "json") {
    printJsonReport(analysis);
  } else {
    printReport(analysis);
  }
}

main().catch((error) => {
  console.error("Error:", error.message);
  process.exit(1);
});
