import { tool } from "ai";
import { z } from "zod";
import { join } from "path";
import { existsSync, mkdirSync, readFileSync, writeFileSync, appendFileSync } from "fs";
import { executeScript, executeScriptPersistent } from "./repl";
import type { SubAgentSession, AttackPlan, VerificationCriteria, Finding, PlanPhase } from "./types";
import { AttackPlanSchema, VerificationCriteriaSchema, FindingSchema, PlanPhaseSchema } from "./types";
import { createPentestTools } from "../tools";
import type { Session } from "../../session";
import { Memory } from "../../memory";
import { nanoid } from "nanoid";

export function createInitAgentTools(subagentSession: SubAgentSession) {
  const { id, config, rootPath, planPath, verificationPath } = subagentSession;

  const read_file = tool({
    description: "Read a file from the filesystem",
    inputSchema: z.object({
      path: z.string().describe("Absolute path to the file"),
    }),
    execute: async ({ path }) => {
      try {
        const content = readFileSync(path, "utf-8");
        return { success: true, content };
      } catch (error: any) {
        return { success: false, error: error.message };
      }
    },
  });

  const search_code = tool({
    description: "Search source code using grep pattern (whitebox mode only)",
    inputSchema: z.object({
      pattern: z.string().describe("Regex pattern to search for"),
      path: z.string().optional().describe("Directory to search in"),
      filePattern: z.string().optional().describe("File glob pattern, e.g. *.ts"),
    }),
    execute: async ({ pattern, path, filePattern }) => {
      if (!config.whiteboxMode) {
        return { success: false, error: "Code search only available in whitebox mode" };
      }
      const searchPath = path || config.sourceCodePath || ".";
      const glob = filePattern || "**/*";
      try {
        const proc = Bun.spawn(
          ["rg", "--json", pattern, "-g", glob, searchPath],
          { stdout: "pipe", stderr: "pipe" }
        );
        const stdout = await new Response(proc.stdout).text();
        const matches = stdout
          .split("\n")
          .filter((l) => l.trim())
          .map((l) => {
            try {
              return JSON.parse(l);
            } catch {
              return null;
            }
          })
          .filter((m) => m?.type === "match")
          .slice(0, 50);
        return { success: true, matches };
      } catch (error: any) {
        return { success: false, error: error.message };
      }
    },
  });

  const http_request = tool({
    description: "Make an HTTP request to probe the endpoint",
    inputSchema: z.object({
      url: z.string().describe("URL to request"),
      method: z.enum(["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"]).default("GET"),
      headers: z.record(z.string(), z.string()).optional(),
      body: z.string().optional(),
    }),
    execute: async ({ url, method, headers, body }) => {
      try {
        const response = await fetch(url, {
          method,
          headers,
          body: body || undefined,
        });
        const text = await response.text();
        return {
          success: true,
          status: response.status,
          headers: Object.fromEntries(response.headers.entries()),
          body: text.slice(0, 5000),
        };
      } catch (error: any) {
        return { success: false, error: error.message };
      }
    },
  });

  const write_plan = tool({
    description: "Write the attack plan for this sub-agent",
    inputSchema: z.object({
      summary: z.string().describe("Summary of the attack approach"),
      phases: z.array(PlanPhaseSchema).describe("Attack phases"),
      contextGathered: z.record(z.string(), z.any()).optional().describe("Context gathered during init"),
    }),
    execute: async ({ summary, phases, contextGathered }) => {
      const plan: AttackPlan = {
        subagentId: id,
        endpoint: config.endpoint,
        vulnerabilityClass: config.vulnerabilityClass,
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
        summary,
        phases,
        contextGathered,
        notes: [],
      };
      writeFileSync(planPath, JSON.stringify(plan, null, 2));
      return { success: true, planPath };
    },
  });

  const write_verification_criteria = tool({
    description: "Write verification criteria for validating findings",
    inputSchema: z.object({
      successIndicators: z.array(z.string()).describe("Indicators that confirm vulnerability"),
      failureIndicators: z.array(z.string()).describe("Indicators that rule out vulnerability"),
      verificationSteps: z.array(
        z.object({
          description: z.string(),
          expectedOutcome: z.string(),
          method: z.enum(["response_contains", "status_code", "timing", "script", "manual"]),
          value: z.string().optional(),
        })
      ).describe("Steps to verify a finding"),
      minimumConfidence: z.number().optional().describe("Minimum confidence threshold (0-100)"),
    }),
    execute: async ({ successIndicators, failureIndicators, verificationSteps, minimumConfidence }) => {
      const criteria: VerificationCriteria = {
        subagentId: id,
        vulnerabilityClass: config.vulnerabilityClass,
        createdAt: new Date().toISOString(),
        successIndicators,
        failureIndicators,
        verificationSteps,
        minimumConfidence: minimumConfidence || 80,
      };
      writeFileSync(verificationPath, JSON.stringify(criteria, null, 2));
      return { success: true, verificationPath };
    },
  });

  const complete_init = tool({
    description: "Signal that initialization is complete. Call after writing plan and verification criteria.",
    inputSchema: z.object({
      summary: z.string().describe("Summary of init phase findings"),
    }),
    execute: async ({ summary }) => {
      return { success: true, complete: true, summary };
    },
  });

  return {
    read_file,
    search_code,
    http_request,
    write_plan,
    write_verification_criteria,
    complete_init,
  };
}

export function createAttackAgentTools(
  subagentSession: SubAgentSession,
  session: Session.SessionInfo,
  workspace: string,
  toolOverride?: {
    execute_command?: (opts: any) => Promise<any>;
  }
) {
  const { id, config, rootPath, planPath, verificationPath, findingsPath, scriptsPath } = subagentSession;

  const pentestTools = createPentestTools(session, undefined, toolOverride);
  const {
    execute_command,
    http_request: pentest_http_request,
    fuzz_endpoint,
    mutate_payload,
    smart_enumerate,
    cve_lookup,
  } = pentestTools;

  const read_file = tool({
    description: "Read a file from the filesystem",
    inputSchema: z.object({
      path: z.string().describe("Absolute path to the file"),
    }),
    execute: async ({ path }) => {
      try {
        const content = readFileSync(path, "utf-8");
        return { success: true, content };
      } catch (error: any) {
        return { success: false, error: error.message };
      }
    },
  });

  const write_file = tool({
    description: "Write content to a file",
    inputSchema: z.object({
      path: z.string().describe("Absolute path to the file"),
      content: z.string().describe("Content to write"),
    }),
    execute: async ({ path, content }) => {
      try {
        const dir = path.substring(0, path.lastIndexOf("/"));
        if (!existsSync(dir)) {
          mkdirSync(dir, { recursive: true });
        }
        writeFileSync(path, content);
        return { success: true, path };
      } catch (error: any) {
        return { success: false, error: error.message };
      }
    },
  });

  const append_file = tool({
    description: "Append content to a file",
    inputSchema: z.object({
      path: z.string().describe("Absolute path to the file"),
      content: z.string().describe("Content to append"),
    }),
    execute: async ({ path, content }) => {
      try {
        appendFileSync(path, content);
        return { success: true, path };
      } catch (error: any) {
        return { success: false, error: error.message };
      }
    },
  });

  const search_code = tool({
    description: "Search source code (whitebox mode only)",
    inputSchema: z.object({
      pattern: z.string().describe("Regex pattern to search"),
      path: z.string().optional(),
      filePattern: z.string().optional(),
    }),
    execute: async ({ pattern, path, filePattern }) => {
      if (!config.whiteboxMode) {
        return { success: false, error: "Code search only available in whitebox mode" };
      }
      const searchPath = path || config.sourceCodePath || ".";
      const glob = filePattern || "**/*";
      try {
        const proc = Bun.spawn(
          ["rg", "--json", pattern, "-g", glob, searchPath],
          { stdout: "pipe", stderr: "pipe" }
        );
        const stdout = await new Response(proc.stdout).text();
        const matches = stdout
          .split("\n")
          .filter((l) => l.trim())
          .map((l) => {
            try {
              return JSON.parse(l);
            } catch {
              return null;
            }
          })
          .filter((m) => m?.type === "match")
          .slice(0, 50);
        return { success: true, matches };
      } catch (error: any) {
        return { success: false, error: error.message };
      }
    },
  });

  const read_plan = tool({
    description: "Read the current attack plan",
    inputSchema: z.object({}),
    execute: async () => {
      try {
        const plan = JSON.parse(readFileSync(planPath, "utf-8")) as AttackPlan;
        return { success: true, plan };
      } catch (error: any) {
        return { success: false, error: error.message };
      }
    },
  });

  const append_plan = tool({
    description: "Append notes or update phases in the attack plan",
    inputSchema: z.object({
      note: z.string().optional().describe("Note to append"),
      phaseUpdate: z
        .object({
          phaseName: z.string(),
          completed: z.boolean().optional(),
          notes: z.string().optional(),
        })
        .optional(),
    }),
    execute: async ({ note, phaseUpdate }) => {
      try {
        const plan = JSON.parse(readFileSync(planPath, "utf-8")) as AttackPlan;
        if (note) {
          plan.notes.push(`[${new Date().toISOString()}] ${note}`);
        }
        if (phaseUpdate) {
          const phase = plan.phases.find((p) => p.name === phaseUpdate.phaseName);
          if (phase) {
            if (phaseUpdate.completed !== undefined) phase.completed = phaseUpdate.completed;
            if (phaseUpdate.notes) phase.notes = phaseUpdate.notes;
          }
        }
        plan.updatedAt = new Date().toISOString();
        writeFileSync(planPath, JSON.stringify(plan, null, 2));
        return { success: true };
      } catch (error: any) {
        return { success: false, error: error.message };
      }
    },
  });

  const execute_script = tool({
    description: `Execute a bun (TypeScript) or python script. Use this to write custom tools, exploits, or testing scripts.
The script will be saved to the scripts directory and executed. Output is captured.`,
    inputSchema: z.object({
      name: z.string().describe("Name for the script"),
      language: z.enum(["bun", "python"]).describe("Script language"),
      code: z.string().describe("Script code to execute"),
      timeout: z.number().optional().describe("Timeout in ms (default 60000)"),
      saveToMemory: z.boolean().optional().describe("Save script to workspace memory for reuse"),
      description: z.string().optional().describe("Description if saving to memory"),
      tags: z.array(z.string()).optional().describe("Tags if saving to memory"),
    }),
    execute: async ({ name, language, code, timeout, saveToMemory, description, tags }) => {
      const result = await executeScriptPersistent({
        language,
        code,
        timeout,
        scriptName: name,
        persistDir: scriptsPath,
        workingDir: rootPath,
      });

      if (saveToMemory && result.success && description) {
        try {
          await Memory.storeTool(workspace, {
            name,
            code,
            language,
            description,
            tags: tags || [],
            createdAt: new Date().toISOString(),
            usageCount: 1,
          });
        } catch {}
      }

      return result;
    },
  });

  const get_memory_tool = tool({
    description: "Retrieve a reusable tool from workspace memory",
    inputSchema: z.object({
      name: z.string().describe("Tool name"),
    }),
    execute: async ({ name }) => {
      const tool = await Memory.getTool(workspace, name);
      if (tool) {
        await Memory.incrementToolUsage(workspace, name);
        return { success: true, tool };
      }
      return { success: false, error: "Tool not found" };
    },
  });

  const search_memory = tool({
    description: "Search workspace memory for tools, techniques, or findings",
    inputSchema: z.object({
      query: z.string().describe("Search query"),
      types: z.array(z.enum(["tool", "technique", "finding"])).optional(),
      limit: z.number().optional(),
    }),
    execute: async ({ query, types, limit }) => {
      const results = await Memory.search(workspace, query, { types, limit });
      return { success: true, results };
    },
  });

  const read_verification_criteria = tool({
    description: "Read the verification criteria for this sub-agent",
    inputSchema: z.object({}),
    execute: async () => {
      try {
        const criteria = JSON.parse(readFileSync(verificationPath, "utf-8")) as VerificationCriteria;
        return { success: true, criteria };
      } catch (error: any) {
        return { success: false, error: error.message };
      }
    },
  });

  const verify_finding = tool({
    description: "Verify a potential finding against the verification criteria",
    inputSchema: z.object({
      evidence: z.string().describe("Evidence collected"),
      confidence: z.number().describe("Confidence level 0-100"),
    }),
    execute: async ({ evidence, confidence }) => {
      try {
        const criteria = JSON.parse(readFileSync(verificationPath, "utf-8")) as VerificationCriteria;
        const evidenceLower = evidence.toLowerCase();

        const successMatches = criteria.successIndicators.filter((i) =>
          evidenceLower.includes(i.toLowerCase())
        );
        const failureMatches = criteria.failureIndicators.filter((i) =>
          evidenceLower.includes(i.toLowerCase())
        );

        const passed =
          confidence >= criteria.minimumConfidence &&
          successMatches.length > 0 &&
          failureMatches.length === 0;

        return {
          success: true,
          passed,
          successMatches,
          failureMatches,
          confidenceThreshold: criteria.minimumConfidence,
          reason: passed
            ? `Verification passed: ${successMatches.length} success indicators matched`
            : failureMatches.length > 0
            ? `Verification failed: failure indicators matched (${failureMatches.join(", ")})`
            : confidence < criteria.minimumConfidence
            ? `Confidence ${confidence}% below threshold ${criteria.minimumConfidence}%`
            : "No success indicators matched",
        };
      } catch (error: any) {
        return { success: false, error: error.message };
      }
    },
  });

  const document_finding = tool({
    description: "Document a verified vulnerability finding with POC",
    inputSchema: z.object({
      title: z.string(),
      severity: z.enum(["critical", "high", "medium", "low", "info"]),
      description: z.string(),
      impact: z.string(),
      evidence: z.string(),
      pocPath: z.string().optional(),
      remediation: z.string(),
    }),
    execute: async ({ title, severity, description, impact, evidence, pocPath, remediation }) => {
      const findingId = nanoid(8);
      const finding: Finding = {
        id: findingId,
        subagentId: id,
        title,
        severity,
        vulnerabilityClass: config.vulnerabilityClass,
        endpoint: config.endpoint,
        description,
        impact,
        evidence,
        pocPath,
        remediation,
        verificationPassed: true,
        createdAt: new Date().toISOString(),
      };

      const findingPath = join(findingsPath, `${findingId}.json`);
      writeFileSync(findingPath, JSON.stringify(finding, null, 2));

      try {
        await Memory.storeFinding(workspace, {
          id: findingId,
          title,
          vulnerabilityClass: config.vulnerabilityClass,
          endpoint: config.endpoint,
          severity,
          technique: description.slice(0, 100),
          createdAt: finding.createdAt,
        });
      } catch {}

      return { success: true, findingId, findingPath };
    },
  });

  const complete_attack = tool({
    description: "Signal that attack phase is complete",
    inputSchema: z.object({
      summary: z.string().describe("Summary of attack phase results"),
      findingsCount: z.number().describe("Number of findings documented"),
    }),
    execute: async ({ summary, findingsCount }) => {
      return { success: true, complete: true, summary, findingsCount };
    },
  });

  return {
    execute_command,
    http_request: pentest_http_request,
    fuzz_endpoint,
    mutate_payload,
    smart_enumerate,
    cve_lookup,
    read_file,
    write_file,
    append_file,
    search_code,
    read_plan,
    append_plan,
    execute_script,
    get_memory_tool,
    search_memory,
    read_verification_criteria,
    verify_finding,
    document_finding,
    complete_attack,
  };
}
