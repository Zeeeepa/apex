import { streamResponse, type AIModel } from "../../ai";
import { hasToolCall } from "ai";
import type { SubAgentSession, AttackAgentResult, Finding, AttackPlan, VerificationCriteria } from "./types";
import { createAttackAgentTools } from "./tools";
import type { Session } from "../../session";
import { existsSync, readFileSync, readdirSync } from "fs";
import { join } from "path";

const ATTACK_SYSTEM_PROMPT = `You are a security testing attack agent. Your job is to execute the attack plan and find vulnerabilities.

Target: {endpoint}
Vulnerability Class: {vulnerabilityClass}

## Your Tools

You have access to:
- **execute_command**: Run shell commands (nmap, curl, etc.)
- **http_request**: Make HTTP requests with full control
- **fuzz_endpoint**: Fuzz parameters for IDOR
- **mutate_payload**: Generate encoding variants for filter bypass
- **cve_lookup**: Search for known CVEs
- **execute_script**: Write and run custom bun/python scripts (KEY TOOL)
- **read_file/write_file/append_file**: File operations
- **search_code**: Search source code (whitebox only)
- **read_plan/append_plan**: Access and update your attack plan
- **search_memory/get_memory_tool**: Access workspace memory for reusable tools
- **verify_finding**: Validate findings against criteria
- **document_finding**: Record confirmed vulnerabilities

## Attack Approach

1. Read the plan and verification criteria
2. Execute each phase systematically
3. Use execute_script to write custom tools when needed
4. When you find something, verify it against criteria before documenting
5. Update the plan with your progress and findings

## Script Writing

The execute_script tool is powerful. Use it to:
- Write multi-step exploits
- Create parallel request scripts
- Build custom payload generators
- Parse complex responses
- Implement timing attacks

Example bun script:
\`\`\`typescript
const response = await fetch("http://target/api", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ user: "admin'--" })
});
const text = await response.text();
console.log(text);
if (text.includes("error in your SQL")) {
  console.log("VULNERABLE: SQL Injection confirmed");
  process.exit(0);
}
process.exit(1);
\`\`\`

## Verification

Before documenting any finding:
1. Call read_verification_criteria to understand success/failure indicators
2. Call verify_finding with your evidence and confidence
3. Only document if verification passes

Call complete_attack when testing is done.`;

export async function runAttackAgent(
  subagentSession: SubAgentSession,
  session: Session.SessionInfo,
  workspace: string,
  model: AIModel,
  abortSignal?: AbortSignal,
  toolOverride?: {
    execute_command?: (opts: any) => Promise<any>;
  }
): Promise<AttackAgentResult> {
  const { config, planPath, verificationPath, findingsPath } = subagentSession;

  const tools = createAttackAgentTools(subagentSession, session, workspace, toolOverride);

  const systemPrompt = ATTACK_SYSTEM_PROMPT
    .replace("{endpoint}", config.endpoint)
    .replace("{vulnerabilityClass}", config.vulnerabilityClass);

  let plan: AttackPlan | null = null;
  let verificationCriteria: VerificationCriteria | null = null;

  if (existsSync(planPath)) {
    plan = JSON.parse(readFileSync(planPath, "utf-8"));
  }
  if (existsSync(verificationPath)) {
    verificationCriteria = JSON.parse(readFileSync(verificationPath, "utf-8"));
  }

  let userPrompt = `Execute the attack plan for ${config.endpoint} targeting ${config.vulnerabilityClass}.`;

  if (plan) {
    userPrompt += `\n\n## Attack Plan\n${JSON.stringify(plan, null, 2)}`;
  }

  if (verificationCriteria) {
    userPrompt += `\n\n## Verification Criteria\n${JSON.stringify(verificationCriteria, null, 2)}`;
  }

  if (config.context) {
    userPrompt += `\n\n## Additional Context\n${JSON.stringify(config.context, null, 2)}`;
  }

  userPrompt += `\n\nExecute the plan phases, verify any findings, and document confirmed vulnerabilities.
Call complete_attack when done.`;

  try {
    const streamResult = streamResponse({
      prompt: userPrompt,
      system: systemPrompt,
      model,
      tools,
      stopWhen: hasToolCall("complete_attack"),
      abortSignal,
      silent: true,
    });

    let summary = "";
    for await (const chunk of streamResult.fullStream) {
      if (chunk.type === "error") {
        throw (chunk as any).error;
      }
    }

    const findings: Finding[] = [];
    if (existsSync(findingsPath)) {
      const files = readdirSync(findingsPath).filter((f) => f.endsWith(".json"));
      for (const file of files) {
        try {
          const finding = JSON.parse(readFileSync(join(findingsPath, file), "utf-8"));
          findings.push(finding);
        } catch {}
      }
    }

    return {
      success: true,
      findings,
      summary: `Attack phase complete. Found ${findings.length} vulnerabilities.`,
    };
  } catch (error: any) {
    const findings: Finding[] = [];
    if (existsSync(findingsPath)) {
      const files = readdirSync(findingsPath).filter((f) => f.endsWith(".json"));
      for (const file of files) {
        try {
          const finding = JSON.parse(readFileSync(join(findingsPath, file), "utf-8"));
          findings.push(finding);
        } catch {}
      }
    }

    return {
      success: false,
      findings,
      summary: `Attack phase terminated with error: ${error.message}`,
      error: error.message,
    };
  }
}
