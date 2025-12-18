/**
 * POC Generation and Finding Documentation Tools
 *
 * These tools enable the MetaTestingAgent to:
 * 1. Create and execute POC scripts (bash preferred, python supported)
 * 2. Document confirmed vulnerabilities with evidence
 */

import { tool } from "ai";
import { z } from "zod";
import { join } from "path";
import { promisify } from "util";
import { exec } from "child_process";
import {
  existsSync,
  writeFileSync,
  chmodSync,
  unlinkSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  appendFileSync,
} from "fs";
import { nanoid } from "nanoid";
import { Logger } from "../logger";
import type { Session } from "../../session";
import type {
  CreatePocInput,
  CreatePocResult,
  DocumentFindingInput,
  DocumentFindingResult,
  MetaTestingSessionInfo,
} from "./types";
import { CreatePocSchema, DocumentFindingSchema } from "./types";
import type { ExecuteCommandOpts, ExecuteCommandResult } from "../tools";

const execAsync = promisify(exec);

/**
 * Maximum POC attempts before giving up on an approach
 */
const MAX_POC_ATTEMPTS = 3;

/**
 * Sanitize a string for use in filenames
 */
function sanitizeFilename(str: string): string {
  return str
    .toLowerCase()
    .replace(/[^a-z0-9_-]/g, "_")
    .replace(/_+/g, "_")
    .replace(/^_|_$/g, "")
    .substring(0, 50);
}

/**
 * Create the create_poc tool for generating and testing POC scripts
 */
export function createPocTool(
  session: MetaTestingSessionInfo,
  logger: Logger,
  toolOverride?: {
    execute_command?: (
      opts: ExecuteCommandOpts
    ) => Promise<ExecuteCommandResult>;
  }
) {
  // Track POC attempts per approach
  const pocAttempts = new Map<string, number>();
  const pocPaths: string[] = [];

  const create_poc = tool({
    description: `Create and test a Proof-of-Concept script.

**Primarily use bash scripts** - they are automatically executed and tested.
Python scripts are also supported for complex scenarios requiring libraries.

This tool:
1. Creates the POC file in the pocs/ directory
2. For bash: Makes executable (chmod +x) and runs it
3. For python: Runs with python3
4. Returns execution output for analysis
5. **Deletes the file if execution fails**

POC requirements:
- Bash: Start with #!/bin/bash, exit 0 on success (vuln confirmed), 1 on failure
- Python: Use requests library, print clear success/failure indicators, sys.exit(0/1)
- Include rate limiting (sleep between requests)
- Include authentication if required
- Print clear evidence of exploitation

Max ${MAX_POC_ATTEMPTS} attempts per approach before pivoting.`,
    inputSchema: CreatePocSchema,
    execute: async (poc: CreatePocInput): Promise<CreatePocResult> => {
      // Track attempts for this approach
      const approachKey = `${poc.pocName}_${poc.description.substring(0, 30)}`;
      const currentAttempts = (pocAttempts.get(approachKey) || 0) + 1;
      pocAttempts.set(approachKey, currentAttempts);

      logger.info(
        `POC attempt ${currentAttempts}/${MAX_POC_ATTEMPTS}: ${poc.pocName} (${poc.pocType})`
      );

      try {
        // Ensure pocs directory exists
        const pocsPath = session.pocsPath;
        if (!existsSync(pocsPath)) {
          mkdirSync(pocsPath, { recursive: true });
        }

        const extension = poc.pocType === "bash" ? ".sh" : ".py";
        const sanitizedName = sanitizeFilename(poc.pocName);
        const filename = `poc_${sanitizedName}${extension}`;
        const pocPath = join(pocsPath, filename);
        const relativePocPath = `pocs/${filename}`;

        let pocContent = poc.pocContent.trim();

        // Add appropriate header if missing
        if (poc.pocType === "bash") {
          if (!pocContent.startsWith("#!")) {
            pocContent = "#!/bin/bash\n" + pocContent;
          }
          // Add header comment if not present
          if (!pocContent.includes("# POC:")) {
            const header = `#!/bin/bash
# POC: ${poc.description}
# Created: ${new Date().toISOString()}
# Attempt: ${currentAttempts}/${MAX_POC_ATTEMPTS}

set -e  # Exit on error

`;
            pocContent = header + pocContent.replace(/^#!\/bin\/bash\s*\n/, "");
          }
        } else {
          // Python
          if (!pocContent.startsWith("#!") && !pocContent.startsWith("#!/")) {
            pocContent = "#!/usr/bin/env python3\n" + pocContent;
          }
          // Add header comment if not present
          if (!pocContent.includes("# POC:")) {
            const header = `#!/usr/bin/env python3
# POC: ${poc.description}
# Created: ${new Date().toISOString()}
# Attempt: ${currentAttempts}/${MAX_POC_ATTEMPTS}

`;
            pocContent = header + pocContent.replace(/^#!.*\n/, "");
          }
        }

        // Write POC file
        writeFileSync(pocPath, pocContent);
        logger.info(`POC written to: ${relativePocPath}`);

        // Execute the POC
        let stdout = "";
        let stderr = "";
        let exitCode = 0;

        try {
          if (poc.pocType === "bash") {
            chmodSync(pocPath, 0o755);
          }

          // Use sandboxed execute_command if available (for benchmark/remote execution)
          if (toolOverride?.execute_command) {
            // For sandbox execution, pass the POC content directly
            const pocBase64 = Buffer.from(pocContent).toString("base64");
            const execCommand =
              poc.pocType === "bash"
                ? `echo '${pocBase64}' | base64 -d | bash`
                : `echo '${pocBase64}' | base64 -d | python3`;

            const execResult = await toolOverride.execute_command({
              command: execCommand,
              timeout: 60000, // 60 second timeout for POCs
              toolCallDescription: `Executing ${poc.pocType} POC: ${poc.pocName}`,
            });

            stdout = execResult.stdout || "";
            stderr = execResult.stderr || "";

            if (!execResult.success || execResult.error) {
              throw {
                message: execResult.error || "POC execution failed",
                code: 1,
                stdout,
                stderr,
              };
            }
          } else {
            // Local execution
            const execCommand =
              poc.pocType === "bash" ? pocPath : `python3 ${pocPath}`;

            const result = await execAsync(execCommand, {
              timeout: 60000,
              maxBuffer: 1024 * 1024,
              cwd: session.rootPath,
            });

            stdout = result.stdout;
            stderr = result.stderr;
          }

          // Success - POC executed without error
          logger.info(`POC executed successfully: ${filename}`);
          pocPaths.push(relativePocPath);

          return {
            success: true,
            pocPath: relativePocPath,
            execution: {
              success: true,
              exitCode: 0,
              stdout: stdout || "(no output)",
              stderr: stderr || "(no errors)",
            },
            message: `POC created and executed successfully at: ${relativePocPath}

**Execution Output:**
STDOUT:
\`\`\`
${stdout || "(no output)"}
\`\`\`

STDERR:
\`\`\`
${stderr || "(no errors)"}
\`\`\`

**VALIDATION REQUIRED:** Analyze the output above.
- If output confirms vulnerability exploitation → call document_finding with pocPath: "${relativePocPath}"
- If output shows failure or inconclusive → create improved POC or pivot approach

Remember to update your confidence based on this result:
VALIDATION: Outcome: [yes/no + evidence] | Confidence: BEFORE [X%] → AFTER [Y%]`,
          };
        } catch (execError: any) {
          // Execution failed - delete the POC file
          logger.info(`POC execution failed, deleting: ${filename}`);
          try {
            unlinkSync(pocPath);
          } catch (e) {
            // Ignore deletion errors
          }

          exitCode = execError.code || 1;
          stdout = execError.stdout || "";
          stderr = execError.stderr || execError.message;

          const attemptsRemaining = MAX_POC_ATTEMPTS - currentAttempts;

          return {
            success: false,
            error: execError.message,
            execution: {
              success: false,
              exitCode,
              stdout,
              stderr,
            },
            message: `POC execution FAILED (attempt ${currentAttempts}/${MAX_POC_ATTEMPTS})

**Error:** ${execError.message}

STDOUT:
\`\`\`
${stdout || "(none)"}
\`\`\`

STDERR:
\`\`\`
${stderr}
\`\`\`

${
  attemptsRemaining > 0
    ? `**Next Steps:**
- Analyze the error and create an improved POC
- Consider: syntax errors, missing dependencies, wrong assumptions
- ${attemptsRemaining} attempts remaining for this approach
- Call store_adaptation with worked=false and constraint_learned if you identified a blocker`
    : `**Max attempts reached for this approach.**
- Call store_adaptation with worked=false to record this dead end
- PIVOT to a different technique or vulnerability class
- Do NOT retry the same approach`
}`,
          };
        }
      } catch (error: any) {
        logger.error(`POC creation error: ${error.message}`);
        return {
          success: false,
          error: error.message,
          message: `Failed to create POC: ${error.message}

This is a system error, not an exploitation failure. Check:
- File permissions
- Disk space
- Script syntax`,
        };
      }
    },
  });

  return { create_poc, pocPaths };
}

/**
 * Create the document_finding tool for recording confirmed vulnerabilities
 */
export function createDocumentFindingTool(
  session: MetaTestingSessionInfo,
  logger: Logger,
  target: string
) {
  const findingPaths: string[] = [];

  const document_finding = tool({
    description: `Document a confirmed vulnerability with evidence.

**Requirements:**
- POC must exist at the specified pocPath
- Include evidence from POC execution output
- Only call AFTER confirming exploitation via create_poc

This tool:
1. Validates POC exists
2. Checks for duplicate findings
3. Saves finding JSON to session
4. Updates findings summary

**Call this when:**
- POC executed successfully AND
- Output confirms vulnerability exploitation AND
- Confidence > 80%`,
    inputSchema: DocumentFindingSchema,
    execute: async (
      finding: DocumentFindingInput
    ): Promise<DocumentFindingResult> => {
      logger.info(
        `Documenting finding: ${finding.title} [${finding.severity}]`
      );

      try {
        // Ensure findings directory exists
        if (!existsSync(session.findingsPath)) {
          mkdirSync(session.findingsPath, { recursive: true });
        }

        // Validate POC exists
        const fullPocPath = join(session.rootPath, finding.pocPath);
        if (!existsSync(fullPocPath)) {
          return {
            success: false,
            error: "POC_NOT_FOUND",
            message: `POC not found at: ${finding.pocPath}

Create POC first using create_poc tool, then call document_finding.`,
          };
        }

        // Check for duplicates
        const existingFindings = loadExistingFindings(session.findingsPath);
        const isDuplicate = existingFindings.some(
          (f) =>
            f.title?.toLowerCase() === finding.title.toLowerCase() ||
            (f.endpoint === finding.endpoint &&
              f.description
                ?.toLowerCase()
                .includes(finding.title.toLowerCase().split(" ")[0]))
        );

        if (isDuplicate) {
          logger.info(`Duplicate finding detected: ${finding.title}`);
          return {
            success: false,
            error: "DUPLICATE",
            message: `Duplicate finding - already documented.

Continue testing for OTHER vulnerabilities at different endpoints.`,
          };
        }

        // Create finding with metadata
        const timestamp = new Date().toISOString();
        const id = nanoid(8);

        const findingWithMeta = {
          ...finding,
          id,
          timestamp,
          sessionId: session.id,
          target,
        };

        // Save finding JSON
        const safeTitle = sanitizeFilename(finding.title);
        const filename = `${timestamp.split("T")[0]}-${safeTitle}.json`;
        const filepath = join(session.findingsPath, filename);

        writeFileSync(filepath, JSON.stringify(findingWithMeta, null, 2));
        findingPaths.push(filepath);

        // Update findings summary
        const summaryPath = join(session.rootPath, "findings-summary.md");
        const summaryEntry = `\n- **[${finding.severity}]** ${finding.title}\n  - Endpoint: \`${finding.endpoint}\`\n  - POC: \`${finding.pocPath}\`\n  - Finding: \`findings/${filename}\`\n`;

        try {
          if (existsSync(summaryPath)) {
            appendFileSync(summaryPath, summaryEntry);
          } else {
            const header = `# Findings Summary

**Target:** ${target}
**Session:** ${session.id}
**Generated:** ${timestamp}

## Confirmed Vulnerabilities
${summaryEntry}`;
            writeFileSync(summaryPath, header);
          }
        } catch (e) {
          logger.error(`Failed to update findings summary: ${e}`);
        }

        logger.info(`Finding documented: ${filename}`);

        return {
          success: true,
          findingPath: filepath,
          message: `Finding documented successfully!

**[${finding.severity}]** ${finding.title}
- Saved to: findings/${filename}
- POC: ${finding.pocPath}

**Next Steps:**
1. Call store_adaptation with worked=true to record successful approach
2. Continue testing for additional vulnerabilities
3. Consider testing related endpoints or similar attack vectors`,
        };
      } catch (error: any) {
        logger.error(`Document finding error: ${error.message}`);
        return {
          success: false,
          error: error.message,
          message: `Failed to document finding: ${error.message}`,
        };
      }
    },
  });

  return { document_finding, findingPaths };
}

/**
 * Load existing findings from the findings directory
 */
function loadExistingFindings(findingsPath: string): any[] {
  if (!existsSync(findingsPath)) {
    return [];
  }

  try {
    const files = readdirSync(findingsPath).filter((f) => f.endsWith(".json"));
    return files
      .map((f) => {
        try {
          return JSON.parse(readFileSync(join(findingsPath, f), "utf-8"));
        } catch {
          return null;
        }
      })
      .filter(Boolean);
  } catch {
    return [];
  }
}
