import { streamResponse, type AIModel } from "../../ai";
import { hasToolCall } from "ai";
import type { SubAgentSession, InitAgentResult, AttackPlan, VerificationCriteria } from "./types";
import { createInitAgentTools } from "./tools";
import { existsSync, readFileSync } from "fs";

const INIT_SYSTEM_PROMPT = `You are a security testing initialization agent. Your job is to:

1. Gather context about the target endpoint
2. Analyze the attack surface and understand the application
3. Create a structured attack plan with phases
4. Define clear verification criteria for validating findings

You are testing for: {vulnerabilityClass}
Target endpoint: {endpoint}

## Your Process

1. **Reconnaissance**: Probe the endpoint, understand its behavior, identify parameters
2. **Context Gathering**: If whitebox mode, search source code for relevant handlers
3. **Plan Creation**: Create a phased attack plan with specific techniques
4. **Verification Criteria**: Define what constitutes a successful exploit vs false positive

## Plan Structure

Your plan should have phases like:
- Recon: Initial probing and parameter discovery
- Fingerprinting: Identify technologies, frameworks, protections
- Testing: Specific vulnerability tests
- Exploitation: Confirmed exploit techniques
- Validation: Verify the finding is real

## Verification Criteria

Define clear success/failure indicators. For example:
- SQL Injection success: Database error messages, UNION results, time delays
- SQL Injection failure: Input sanitized, parameterized queries, WAF blocking

Call complete_init when you have created both the plan and verification criteria.`;

export async function runInitAgent(
  subagentSession: SubAgentSession,
  model: AIModel,
  abortSignal?: AbortSignal
): Promise<InitAgentResult> {
  const { config, planPath, verificationPath } = subagentSession;

  const tools = createInitAgentTools(subagentSession);

  const systemPrompt = INIT_SYSTEM_PROMPT
    .replace("{vulnerabilityClass}", config.vulnerabilityClass)
    .replace("{endpoint}", config.endpoint);

  let userPrompt = `Initialize testing for ${config.endpoint} targeting ${config.vulnerabilityClass} vulnerabilities.`;

  if (config.context) {
    userPrompt += `\n\nAdditional context provided:\n${JSON.stringify(config.context, null, 2)}`;
  }

  if (config.whiteboxMode && config.sourceCodePath) {
    userPrompt += `\n\nThis is a whitebox test. Source code is available at: ${config.sourceCodePath}
Use search_code to find relevant handlers, validation logic, and database queries.`;
  }

  userPrompt += `\n\nCreate a plan and verification criteria, then call complete_init.`;

  try {
    const streamResult = streamResponse({
      prompt: userPrompt,
      system: systemPrompt,
      model,
      tools,
      stopWhen: hasToolCall("complete_init"),
      abortSignal,
      silent: true,
    });

    for await (const chunk of streamResult.fullStream) {
      if (chunk.type === "error") {
        throw (chunk as any).error;
      }
    }

    let plan: AttackPlan | null = null;
    let verificationCriteria: VerificationCriteria | null = null;

    if (existsSync(planPath)) {
      plan = JSON.parse(readFileSync(planPath, "utf-8"));
    }
    if (existsSync(verificationPath)) {
      verificationCriteria = JSON.parse(readFileSync(verificationPath, "utf-8"));
    }

    if (!plan || !verificationCriteria) {
      return {
        success: false,
        plan: plan || ({} as AttackPlan),
        verificationCriteria: verificationCriteria || ({} as VerificationCriteria),
        error: "Init agent did not create required artifacts",
      };
    }

    return {
      success: true,
      plan,
      verificationCriteria,
    };
  } catch (error: any) {
    return {
      success: false,
      plan: {} as AttackPlan,
      verificationCriteria: {} as VerificationCriteria,
      error: error.message,
    };
  }
}
