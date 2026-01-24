import { tool, hasToolCall } from "ai";
import { z } from "zod";
import { join } from "path";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "fs";
import { streamResponse, type AIModel } from "../../ai";
import type { OrchestratorInput, OrchestratorResult, SpawnSubagentInput } from "./newTypes";
import { SpawnSubagentSchema } from "./newTypes";
import type { SubAgentManifest, SubAgentConfig, VulnerabilityClass } from "../subagent/types";
import { VulnerabilityClassSchema } from "../subagent/types";
import type { AttackSurfaceAnalysisResults } from "../attackSurfaceAgent/types";
import { nanoid } from "nanoid";

const ORCHESTRATOR_SYSTEM_PROMPT = `You are a security testing orchestrator. Your job is to analyze the attack surface and intelligently spawn sub-agents to test for vulnerabilities.

## Your Role

1. Read and analyze the attack surface JSON
2. Understand each endpoint's purpose, parameters, and potential vulnerabilities
3. Decide which sub-agents to spawn for each endpoint
4. Consider which vulnerability classes are most relevant based on:
   - Endpoint functionality (auth endpoints → authentication bypass, sqli)
   - Parameter types (file paths → lfi, URLs → ssrf)
   - Technology stack (identified frameworks, databases)
   - Objective hints from attack surface analysis

## Vulnerability Classes

Available vulnerability classes to test:
- sql_injection: SQL/NoSQL injection
- xss: Cross-site scripting
- command_injection: OS command injection
- ssti: Server-side template injection
- path_traversal: LFI/path traversal
- ssrf: Server-side request forgery
- idor: Insecure direct object references
- authentication_bypass: Auth/session vulnerabilities
- jwt_vulnerabilities: JWT attacks
- deserialization: Insecure deserialization
- xxe: XML external entity
- crypto: Cryptographic weaknesses
- business_logic: Logic flaws
- generic: Other vulnerabilities

## Sub-agent Strategy

For each endpoint, consider spawning multiple sub-agents with different vulnerability focuses. For example:
- Login endpoint → authentication_bypass, sql_injection
- File download → path_traversal, idor
- User profile → idor, xss

Prioritize based on:
- critical: RCE potential (command_injection, ssti, deserialization)
- high: Data access (sql_injection, idor, path_traversal)
- medium: XSS, SSRF, crypto
- low: Info disclosure, generic

## Process

1. Call read_attack_surface to load the attack surface data
2. Optionally use search_source_code (if whitebox mode) to understand handlers
3. Build your sub-agent manifest by calling spawn_subagent for each test
4. Call finalize_manifest when done

Be thorough but intelligent - spawn sub-agents for likely vulnerabilities based on context.`;

function createOrchestratorTools(
  input: OrchestratorInput,
  subagents: SubAgentConfig[]
) {
  const { attackSurfacePath, session, whiteboxMode, sourceCodePath } = input;

  const read_attack_surface = tool({
    description: "Read the attack surface JSON file",
    inputSchema: z.object({}),
    execute: async () => {
      try {
        const content = readFileSync(attackSurfacePath, "utf-8");
        const data = JSON.parse(content) as AttackSurfaceAnalysisResults;
        return { success: true, data };
      } catch (error: any) {
        return { success: false, error: error.message };
      }
    },
  });

  const read_file = tool({
    description: "Read a file from the filesystem",
    inputSchema: z.object({
      path: z.string().describe("Absolute path to the file"),
    }),
    execute: async ({ path }) => {
      try {
        const content = readFileSync(path, "utf-8");
        return { success: true, content: content.slice(0, 10000) };
      } catch (error: any) {
        return { success: false, error: error.message };
      }
    },
  });

  const search_source_code = tool({
    description: "Search source code for patterns (whitebox mode only)",
    inputSchema: z.object({
      pattern: z.string().describe("Regex pattern to search"),
      filePattern: z.string().optional().describe("File glob pattern"),
    }),
    execute: async ({ pattern, filePattern }) => {
      if (!whiteboxMode) {
        return { success: false, error: "Source code search only available in whitebox mode" };
      }
      const searchPath = sourceCodePath || ".";
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
          .slice(0, 30);
        return { success: true, matches };
      } catch (error: any) {
        return { success: false, error: error.message };
      }
    },
  });

  const spawn_subagent = tool({
    description: "Add a sub-agent to the manifest for spawning",
    inputSchema: SpawnSubagentSchema,
    execute: async ({ endpoint, vulnerabilityClass, context, priority, rationale }) => {
      const validClass = VulnerabilityClassSchema.safeParse(vulnerabilityClass);
      if (!validClass.success) {
        return {
          success: false,
          error: `Invalid vulnerability class: ${vulnerabilityClass}. Use one of: sql_injection, nosql_injection, xss, command_injection, ssti, path_traversal, ssrf, idor, authentication_bypass, jwt_vulnerabilities, deserialization, xxe, crypto, business_logic, generic`
        };
      }

      const subagentId = `subagent-${nanoid(6)}`;
      const config: SubAgentConfig = {
        id: subagentId,
        endpoint,
        vulnerabilityClass: validClass.data,
        context: { ...context, rationale },
        priority,
        whiteboxMode: whiteboxMode || false,
        sourceCodePath,
      };

      subagents.push(config);

      return {
        success: true,
        subagentId,
        message: `Sub-agent ${subagentId} added: ${vulnerabilityClass} testing for ${endpoint}`,
      };
    },
  });

  const finalize_manifest = tool({
    description: "Finalize the sub-agent manifest. Call when done adding all sub-agents.",
    inputSchema: z.object({
      summary: z.string().describe("Summary of the orchestration decisions"),
    }),
    execute: async ({ summary }) => {
      return {
        success: true,
        complete: true,
        totalSubagents: subagents.length,
        summary
      };
    },
  });

  return {
    read_attack_surface,
    read_file,
    search_source_code,
    spawn_subagent,
    finalize_manifest,
  };
}

export async function runOrchestrator(
  input: OrchestratorInput,
  model: AIModel
): Promise<OrchestratorResult> {
  const { session, attackSurfacePath, whiteboxMode, focusEndpoint, abortSignal } = input;

  const orchestratorDir = join(session.rootPath, "orchestrator");
  if (!existsSync(orchestratorDir)) {
    mkdirSync(orchestratorDir, { recursive: true });
  }

  const subagents: SubAgentConfig[] = [];
  const tools = createOrchestratorTools(input, subagents);

  let userPrompt = `Analyze the attack surface and create a sub-agent manifest for security testing.

Attack surface file: ${attackSurfacePath}`;

  if (whiteboxMode) {
    userPrompt += `\n\nThis is a WHITEBOX test. You have access to source code via search_source_code.
Use it to understand handlers, find SQL queries, identify dangerous functions, etc.`;
  }

  if (focusEndpoint) {
    userPrompt += `\n\nFocus specifically on this endpoint: ${focusEndpoint}
Spawn multiple sub-agents with different vulnerability classes for thorough testing.`;
  } else {
    userPrompt += `\n\nAnalyze ALL endpoints in the attack surface.
Spawn appropriate sub-agents for each endpoint based on its functionality.`;
  }

  userPrompt += `\n\nProcess:
1. Read the attack surface
2. Analyze each endpoint (${focusEndpoint ? "focusing on " + focusEndpoint : "all endpoints"})
3. Spawn sub-agents using spawn_subagent for each relevant vulnerability test
4. Call finalize_manifest when complete`;

  try {
    const streamResult = streamResponse({
      prompt: userPrompt,
      system: ORCHESTRATOR_SYSTEM_PROMPT,
      model,
      tools,
      stopWhen: hasToolCall("finalize_manifest"),
      abortSignal,
      silent: true,
    });

    for await (const chunk of streamResult.fullStream) {
      if (chunk.type === "error") {
        throw (chunk as any).error;
      }
    }

    const manifest: SubAgentManifest = {
      sessionId: session.id,
      createdAt: new Date().toISOString(),
      attackSurfacePath,
      whiteboxMode: whiteboxMode || false,
      subagents,
    };

    const manifestPath = join(orchestratorDir, "subagent-manifest.json");
    writeFileSync(manifestPath, JSON.stringify(manifest, null, 2));

    return {
      success: true,
      manifest,
      manifestPath,
    };
  } catch (error: any) {
    const manifest: SubAgentManifest = {
      sessionId: session.id,
      createdAt: new Date().toISOString(),
      attackSurfacePath,
      whiteboxMode: whiteboxMode || false,
      subagents,
    };

    return {
      success: false,
      manifest,
      manifestPath: "",
      error: error.message,
    };
  }
}
