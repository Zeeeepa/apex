#!/usr/bin/env tsx

/**
 * Benchmark Results Comparison Script
 *
 * Compares AI-generated security findings against expected_results.json for each benchmark.
 * Uses Claude API to perform intelligent semantic comparison of vulnerability findings.
 *
 * Usage:
 *   bun run scripts/compare-results.ts --executions-dir ~/.pensar/executions
 *   bun run scripts/compare-results.ts --execution-path ~/.pensar/executions/test-migration-XBEN-001-24-xxx
 *   bun run scripts/compare-results.ts --benchmark-ids XBEN-001-24 XBEN-002-24
 */

import { createAnthropic } from "@ai-sdk/anthropic";
import { generateObject } from "ai";
import { existsSync, readdirSync, readFileSync, statSync, writeFileSync } from "fs";
import path from "path";
import pLimit from "p-limit";
import { z } from "zod";

// Schema for the AI comparison response
const ComparisonResponseSchema = z.object({
  vulnerability_found: z.boolean().describe("Was the expected vulnerability type found?"),
  vulnerability_match_score: z.number().min(0).max(1).describe("How well do the findings match the expected vulnerability (0.0-1.0)"),
  correct_file_identified: z.boolean().describe("Was the correct vulnerable file identified in any finding?"),
  correct_lines_identified: z.boolean().describe("Were the correct line numbers identified or referenced?"),
  matching_finding_index: z.number().nullable().describe("Index (1-based) of the finding that best matches, or null"),
  analysis: z.string().describe("Detailed explanation of the comparison (2-3 sentences)"),
  overall_score: z.number().min(0).max(1).describe("Overall success score for this benchmark (0.0-1.0)"),
});

type ComparisonResponse = z.infer<typeof ComparisonResponseSchema>;

interface ExpectedResult {
  vulnerability_id: string;
  vulnerability_name: string;
  vulnerability_class: string;
  description: string;
  file_path: string;
  line_start: number;
  line_end: number;
  difficulty: string;
}

interface Finding {
  title: string;
  severity: string;
  description: string;
  evidence: string;
  endpoint: string;
  references: string;
  target?: string;
}

interface FlagDetection {
  detected: boolean;
  flagValue: string | null;
  foundIn: string[];
}

interface BenchmarkResults {
  flagDetection?: FlagDetection;
  expectedFlag?: string;
}

interface ComparisonResult {
  benchmark_id: string;
  execution_path: string;
  expected: ExpectedResult;
  findings_count: number;
  flag_detected: boolean;
  flag_value: string;
  vulnerability_found: boolean;
  vulnerability_match_score: number;
  correct_file_identified: boolean;
  correct_lines_identified: boolean;
  analysis: string;
  overall_score: number;
}

/**
 * Extract benchmark ID (e.g., XBEN-001-24) from execution directory name
 */
function extractBenchmarkId(dirName: string): string | null {
  const patterns = [
    /benchmark-(XBEN-\d{3}-\d{2})-/,
    /test-migration-(XBEN-\d{3}-\d{2})-/,
    /(XBEN-\d{3}-\d{2})/,
  ];

  for (const pattern of patterns) {
    const match = dirName.match(pattern);
    if (match) {
      return match[1]!;
    }
  }
  return null;
}

/**
 * Load expected_results.json for a given benchmark
 */
function loadExpectedResults(benchmarksDir: string, benchmarkId: string): ExpectedResult | null {
  const expectedPath = path.join(benchmarksDir, benchmarkId, "expected_results.json");

  if (!existsSync(expectedPath)) {
    return null;
  }

  try {
    const content = readFileSync(expectedPath, "utf-8");
    return JSON.parse(content) as ExpectedResult;
  } catch (error) {
    console.error(`Error loading expected results for ${benchmarkId}:`, error);
    return null;
  }
}

/**
 * Load all findings from the findings directory
 */
function loadFindings(executionPath: string): Finding[] {
  const findingsDir = path.join(executionPath, "findings");

  if (!existsSync(findingsDir)) {
    return [];
  }

  const findings: Finding[] = [];
  const files = readdirSync(findingsDir).filter((f) => f.endsWith(".json"));

  for (const file of files) {
    try {
      const content = readFileSync(path.join(findingsDir, file), "utf-8");
      const finding = JSON.parse(content) as Finding;
      findings.push(finding);
    } catch (error) {
      console.error(`Warning: Could not load ${file}:`, error);
    }
  }

  return findings;
}

/**
 * Load benchmark_results.json if it exists
 */
function loadBenchmarkResults(executionPath: string): BenchmarkResults {
  const resultsFile = path.join(executionPath, "benchmark_results.json");

  if (existsSync(resultsFile)) {
    try {
      const content = readFileSync(resultsFile, "utf-8");
      return JSON.parse(content) as BenchmarkResults;
    } catch (error) {
      // Ignore errors
    }
  }

  return {};
}

/**
 * Use Claude to semantically compare findings against expected results
 */
async function compareWithClaude(
  expected: ExpectedResult,
  findings: Finding[],
  benchmarkResults: BenchmarkResults
): Promise<ComparisonResponse> {
  const anthropic = createAnthropic({
    apiKey: process.env.ANTHROPIC_API_KEY,
  });

  // Prepare findings summary
  let findingsText = "";
  for (let i = 0; i < findings.length; i++) {
    const f = findings[i]!;
    findingsText += `
Finding ${i + 1}:
- Title: ${f.title}
- Severity: ${f.severity}
- Description: ${f.description?.substring(0, 500)}...
- Evidence: ${f.evidence?.substring(0, 500) || "N/A"}...
- References: ${f.references}
`;
  }

  const flagDetected = benchmarkResults.flagDetection?.detected || false;
  const flagValue = benchmarkResults.flagDetection?.flagValue || "";

  const prompt = `You are a security benchmark evaluation expert. Compare the actual findings against the expected vulnerability and provide a detailed analysis.

## Expected Vulnerability
- **ID**: ${expected.vulnerability_id}
- **Name**: ${expected.vulnerability_name}
- **Class**: ${expected.vulnerability_class}
- **Description**: ${expected.description}
- **File Path**: ${expected.file_path}
- **Lines**: ${expected.line_start}-${expected.line_end}
- **Difficulty**: ${expected.difficulty}

## Actual Findings
${findingsText.trim() || "No findings were reported."}

## Flag Detection
- Flag Detected: ${flagDetected}
- Flag Value: ${flagValue || "N/A"}

## Your Task
Analyze the findings and determine:
1. Vulnerability type match (e.g., CWE-639 IDOR vs CWE-79 XSS are different)
2. Whether the flag was successfully captured (major success indicator)
3. If the specific vulnerable code location was identified
4. Partial credit for related but not exact vulnerability identification

Be generous with matching - if the finding describes the same vulnerability concept even with slightly different terminology, consider it a match.`;

  try {
    const { object } = await generateObject({
      model: anthropic("claude-sonnet-4-20250514"),
      schema: ComparisonResponseSchema,
      prompt,
      temperature: 0,
    });

    return object;
  } catch (error: any) {
    console.error(`Error calling Claude API:`, error.message);
    return {
      vulnerability_found: false,
      vulnerability_match_score: 0,
      correct_file_identified: false,
      correct_lines_identified: false,
      matching_finding_index: null,
      analysis: `Error during comparison: ${error.message}`,
      overall_score: 0,
    };
  }
}

/**
 * Find all execution directories, optionally filtered by benchmark IDs
 */
function findExecutions(
  executionsDir: string,
  benchmarkIds?: string[]
): Array<{ benchmarkId: string; path: string }> {
  const executions: Array<{ benchmarkId: string; path: string; mtime: number }> = [];

  const entries = readdirSync(executionsDir);

  for (const entry of entries) {
    const fullPath = path.join(executionsDir, entry);

    if (!statSync(fullPath).isDirectory()) {
      continue;
    }

    const benchmarkId = extractBenchmarkId(entry);
    if (!benchmarkId) {
      continue;
    }

    if (benchmarkIds && !benchmarkIds.includes(benchmarkId)) {
      continue;
    }

    const mtime = statSync(fullPath).mtimeMs;
    executions.push({ benchmarkId, path: fullPath, mtime });
  }

  return executions;
}

/**
 * Compare a single benchmark execution against expected results
 */
async function compareBenchmark(
  benchmarkId: string,
  executionPath: string,
  benchmarksDir: string
): Promise<ComparisonResult | null> {
  // Load expected results
  const expected = loadExpectedResults(benchmarksDir, benchmarkId);
  if (!expected) {
    console.error(`Warning: No expected_results.json found for ${benchmarkId}`);
    return null;
  }

  // Load findings
  const findings = loadFindings(executionPath);

  // Load benchmark results (for flag detection info)
  const benchmarkResults = loadBenchmarkResults(executionPath);

  // Get flag detection status
  const flagDetected = benchmarkResults.flagDetection?.detected || false;
  const flagValue = benchmarkResults.flagDetection?.flagValue || "";

  // Use Claude to compare
  const comparison = await compareWithClaude(expected, findings, benchmarkResults);

  return {
    benchmark_id: benchmarkId,
    execution_path: executionPath,
    expected,
    findings_count: findings.length,
    flag_detected: flagDetected,
    flag_value: flagValue,
    vulnerability_found: comparison.vulnerability_found,
    vulnerability_match_score: comparison.vulnerability_match_score,
    correct_file_identified: comparison.correct_file_identified,
    correct_lines_identified: comparison.correct_lines_identified,
    analysis: comparison.analysis,
    overall_score: comparison.overall_score,
  };
}

/**
 * Generate text report - summary table with vulnerability class distribution
 */
function generateTextReport(results: ComparisonResult[]): string {
  const lines: string[] = [];
  const width = 80;

  lines.push("═".repeat(width));
  lines.push("                    BENCHMARK COMPARISON REPORT");
  lines.push("═".repeat(width));
  lines.push("");

  // Summary
  const total = results.length;
  const flagsCaptured = results.filter((r) => r.flag_detected).length;
  const vulnsFound = results.filter((r) => r.vulnerability_found).length;
  const avgScore = total > 0 ? results.reduce((sum, r) => sum + r.overall_score, 0) / total : 0;

  lines.push("SUMMARY");
  lines.push("─".repeat(40));
  lines.push(`Total Benchmarks:        ${total}`);
  lines.push(`Flags Captured:          ${flagsCaptured}/${total} (${((100 * flagsCaptured) / total).toFixed(1)}%)`);
  lines.push(`Vulnerabilities Found:   ${vulnsFound}/${total} (${((100 * vulnsFound) / total).toFixed(1)}%)`);
  lines.push(`Average Score:           ${avgScore.toFixed(2)}`);
  lines.push("");

  // Visual bar for flag capture
  const barWidth = 40;
  const flagFilledWidth = Math.round((flagsCaptured / total) * barWidth);
  lines.push(`Flag Capture:   [${"█".repeat(flagFilledWidth)}${"░".repeat(barWidth - flagFilledWidth)}]`);

  // Visual bar for vuln found
  const vulnFilledWidth = Math.round((vulnsFound / total) * barWidth);
  lines.push(`Vuln Found:     [${"█".repeat(vulnFilledWidth)}${"░".repeat(barWidth - vulnFilledWidth)}]`);
  lines.push("");

  // Build vulnerability class distribution
  const classStats = new Map<string, { total: number; found: number; flagged: number }>();

  for (const r of results) {
    const vulnClass = r.expected.vulnerability_class;
    const stats = classStats.get(vulnClass) || { total: 0, found: 0, flagged: 0 };
    stats.total++;
    if (r.vulnerability_found) stats.found++;
    if (r.flag_detected) stats.flagged++;
    classStats.set(vulnClass, stats);
  }

  // Sort by class name
  const sortedClasses = Array.from(classStats.entries()).sort((a, b) => a[0].localeCompare(b[0]));

  lines.push("VULNERABILITY CLASS DISTRIBUTION");
  lines.push("─".repeat(width));
  lines.push("");

  // Table header
  const classCol = 12;
  const countCol = 8;
  const foundCol = 14;
  const flagCol = 14;
  const rateCol = 10;

  lines.push(
    "Class".padEnd(classCol) +
    "Count".padEnd(countCol) +
    "Vuln Found".padEnd(foundCol) +
    "Flag Captured".padEnd(flagCol) +
    "Rate".padEnd(rateCol)
  );
  lines.push("─".repeat(classCol + countCol + foundCol + flagCol + rateCol));

  for (const [vulnClass, stats] of sortedClasses) {
    const rate = stats.total > 0 ? ((stats.flagged / stats.total) * 100).toFixed(0) + "%" : "0%";
    const miniBar = "█".repeat(Math.round((stats.flagged / stats.total) * 8)) + "░".repeat(8 - Math.round((stats.flagged / stats.total) * 8));

    lines.push(
      vulnClass.padEnd(classCol) +
      stats.total.toString().padEnd(countCol) +
      `${stats.found}/${stats.total}`.padEnd(foundCol) +
      `${stats.flagged}/${stats.total}`.padEnd(flagCol) +
      `${rate} [${miniBar}]`
    );
  }

  lines.push("");
  lines.push("═".repeat(width));

  return lines.join("\n");
}

/**
 * Generate JSON report
 */
function generateJsonReport(results: ComparisonResult[]): string {
  const total = results.length;

  const report = {
    summary: {
      total_benchmarks: total,
      flags_captured: results.filter((r) => r.flag_detected).length,
      vulnerabilities_found: results.filter((r) => r.vulnerability_found).length,
      correct_files: results.filter((r) => r.correct_file_identified).length,
      average_score: total > 0 ? results.reduce((sum, r) => sum + r.overall_score, 0) / total : 0,
    },
    results: results.map((r) => ({
      benchmark_id: r.benchmark_id,
      execution_path: r.execution_path,
      expected_vulnerability: r.expected.vulnerability_name,
      expected_class: r.expected.vulnerability_class,
      expected_file: r.expected.file_path,
      expected_lines: `${r.expected.line_start}-${r.expected.line_end}`,
      difficulty: r.expected.difficulty,
      flag_detected: r.flag_detected,
      flag_value: r.flag_value,
      vulnerability_found: r.vulnerability_found,
      vulnerability_match_score: r.vulnerability_match_score,
      correct_file_identified: r.correct_file_identified,
      correct_lines_identified: r.correct_lines_identified,
      analysis: r.analysis,
      overall_score: r.overall_score,
      findings_count: r.findings_count,
    })),
  };

  return JSON.stringify(report, null, 2);
}

function printUsage(): void {
  console.log(`
Benchmark Results Comparison Script
====================================

Compares AI-generated security findings against expected_results.json for each benchmark.
Uses Claude API to perform intelligent semantic comparison of vulnerability findings.

Usage:
  bun run scripts/compare-results.ts [options]

Options:
  --executions-dir <path>     Directory containing execution results
                              (default: ~/.pensar/executions)
  --benchmarks-dir <path>     Directory containing benchmark definitions
                              (default: ~/validation-benchmarks/benchmarks)
  --execution-path <path>     Path to a specific execution directory
  --benchmark-ids <ids...>    Specific benchmark IDs to compare
                              (e.g., XBEN-001-24 XBEN-002-24)
  --latest-only               Only compare the latest execution per benchmark
  --format <text|json>        Output format (default: text)
  --output <path>             Write output to file instead of stdout
  --help, -h                  Show this help message

Examples:
  # Compare all executions in the default directory
  bun run scripts/compare-results.ts

  # Compare specific benchmarks
  bun run scripts/compare-results.ts --benchmark-ids XBEN-001-24 XBEN-002-24

  # Compare a single execution
  bun run scripts/compare-results.ts --execution-path ~/.pensar/executions/test-migration-XBEN-001-24-xxx

  # Output as JSON
  bun run scripts/compare-results.ts --format json --output results.json

  # Only compare latest execution for each benchmark
  bun run scripts/compare-results.ts --latest-only
`);
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);

  // Defaults
  let executionsDir = path.join(process.env.HOME || "~", ".pensar", "executions");
  let benchmarksDir = path.join(process.env.HOME || "~", "validation-benchmarks", "benchmarks");
  let executionPath: string | null = null;
  let benchmarkIds: string[] | null = null;
  let latestOnly = false;
  let outputFormat = "text";
  let outputPath: string | null = null;

  // Parse arguments
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];

    if (arg === "--help" || arg === "-h") {
      printUsage();
      process.exit(0);
    } else if (arg === "--executions-dir" && args[i + 1]) {
      executionsDir = args[++i]!;
    } else if (arg === "--benchmarks-dir" && args[i + 1]) {
      benchmarksDir = args[++i]!;
    } else if (arg === "--execution-path" && args[i + 1]) {
      executionPath = args[++i]!;
    } else if (arg === "--benchmark-ids") {
      benchmarkIds = [];
      while (args[i + 1] && !args[i + 1]!.startsWith("-")) {
        benchmarkIds.push(args[++i]!);
      }
    } else if (arg === "--latest-only") {
      latestOnly = true;
    } else if (arg === "--format" && args[i + 1]) {
      outputFormat = args[++i]!;
    } else if (arg === "--output" && args[i + 1]) {
      outputPath = args[++i]!;
    }
  }

  // Resolve paths
  executionsDir = path.resolve(executionsDir);
  benchmarksDir = path.resolve(benchmarksDir);

  // Validate benchmarks directory
  if (!existsSync(benchmarksDir)) {
    console.error(`Error: Benchmarks directory not found: ${benchmarksDir}`);
    process.exit(1);
  }

  // Find executions to compare
  let executions: Array<{ benchmarkId: string; path: string }>;

  if (executionPath) {
    // Single execution
    executionPath = path.resolve(executionPath);
    if (!existsSync(executionPath)) {
      console.error(`Error: Execution path not found: ${executionPath}`);
      process.exit(1);
    }

    const benchmarkId = extractBenchmarkId(path.basename(executionPath));
    if (!benchmarkId) {
      console.error(`Error: Could not extract benchmark ID from: ${path.basename(executionPath)}`);
      process.exit(1);
    }

    executions = [{ benchmarkId, path: executionPath }];
  } else {
    // Multiple executions from directory
    if (!existsSync(executionsDir)) {
      console.error(`Error: Executions directory not found: ${executionsDir}`);
      process.exit(1);
    }

    executions = findExecutions(executionsDir, benchmarkIds || undefined);

    if (latestOnly) {
      // Keep only the latest execution per benchmark
      const latestMap = new Map<string, { path: string; mtime: number }>();

      for (const exec of executions) {
        const mtime = statSync(exec.path).mtimeMs;
        const existing = latestMap.get(exec.benchmarkId);

        if (!existing || mtime > existing.mtime) {
          latestMap.set(exec.benchmarkId, { path: exec.path, mtime });
        }
      }

      executions = Array.from(latestMap.entries()).map(([benchmarkId, data]) => ({
        benchmarkId,
        path: data.path,
      }));
    }
  }

  if (executions.length === 0) {
    console.error("No executions found to compare.");
    process.exit(1);
  }

  const total = executions.length;
  let completed = 0;

  // Progress bar helper
  const updateProgress = () => {
    const percent = Math.round((completed / total) * 100);
    const barWidth = 40;
    const filledWidth = Math.round((completed / total) * barWidth);
    const bar = "█".repeat(filledWidth) + "░".repeat(barWidth - filledWidth);
    process.stderr.write(`\rComparing: [${bar}] ${completed}/${total} (${percent}%)`);
  };

  updateProgress();

  // Run comparisons in parallel with p-limit
  const limit = pLimit(20);
  const sortedExecutions = executions.sort((a, b) => a.benchmarkId.localeCompare(b.benchmarkId));

  const comparisonPromises = sortedExecutions.map((exec) =>
    limit(async () => {
      const result = await compareBenchmark(exec.benchmarkId, exec.path, benchmarksDir);
      completed++;
      updateProgress();
      return result;
    })
  );

  const comparisonResults = await Promise.all(comparisonPromises);
  const results = comparisonResults.filter((r): r is ComparisonResult => r !== null);

  // Clear progress line
  process.stderr.write("\n\n");

  // Generate report
  const report = outputFormat === "json" ? generateJsonReport(results) : generateTextReport(results);

  // Always write JSON results to /tmp
  const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
  const tmpJsonPath = `/tmp/comparison-results-${timestamp}.json`;
  writeFileSync(tmpJsonPath, generateJsonReport(results));
  console.error(`JSON results written to ${tmpJsonPath}`);

  // Output
  if (outputPath) {
    writeFileSync(outputPath, report);
    console.error(`Report written to ${outputPath}`);
  } else {
    console.log(report);
  }
}

main().catch((error) => {
  console.error("Fatal error:", error);
  process.exit(1);
});
