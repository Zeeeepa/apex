import { streamResponse, type AIModel } from "../../ai";
import { hasToolCall } from "ai";
import type { SubAgentSession, InitAgentResult, AttackPlan, VerificationCriteria } from "./types";
import { createInitAgentTools } from "./tools";
import { existsSync, readFileSync, appendFileSync } from "fs";
import { join } from "path";
import { Messages } from "../../messages";

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

function logToFile(logsPath: string, message: string): void {
  const timestamp = new Date().toISOString();
  const logEntry = `${timestamp} - ${message}\n`;
  try {
    appendFileSync(join(logsPath, "init.log"), logEntry, "utf8");
  } catch {}
}

export async function runInitAgent(
  subagentSession: SubAgentSession,
  model: AIModel,
  abortSignal?: AbortSignal
): Promise<InitAgentResult> {
  const { config, planPath, verificationPath, logsPath, rootPath } = subagentSession;

  logToFile(logsPath, `[INFO] Starting init phase for endpoint: ${config.endpoint}`);
  logToFile(logsPath, `[INFO] Vulnerability class: ${config.vulnerabilityClass}`);
  logToFile(logsPath, `[INFO] Whitebox mode: ${config.whiteboxMode}`);

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
      onStepFinish: (step) => {
        for (const toolCall of step.toolCalls) {
          logToFile(logsPath, `[INFO] Tool call: ${toolCall.toolName}`);
        }
        for (const toolResult of step.toolResults) {
          logToFile(logsPath, `[INFO] Tool result: ${toolResult.toolName} - completed`);
        }
      },
    });

    for await (const chunk of streamResult.fullStream) {
      if (chunk.type === "error") {
        throw (chunk as any).error;
      }
    }

    // Capture and save messages
    try {
      const response = await streamResult.response;
      const messages = response.messages;
      Messages.saveSubagentPhaseMessages(rootPath, "init", messages);
      logToFile(logsPath, `[INFO] Saved ${messages.length} messages to init-messages.json`);
    } catch (msgError: any) {
      logToFile(logsPath, `[WARN] Failed to save messages: ${msgError.message}`);
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
      logToFile(logsPath, `[ERROR] Init agent did not create required artifacts`);
      return {
        success: false,
        plan: plan || ({} as AttackPlan),
        verificationCriteria: verificationCriteria || ({} as VerificationCriteria),
        error: "Init agent did not create required artifacts",
      };
    }

    logToFile(logsPath, `[INFO] Init phase completed successfully`);
    logToFile(logsPath, `[INFO] Plan phases: ${plan.phases?.length || 0}`);
    return {
      success: true,
      plan,
      verificationCriteria,
    };
  } catch (error: any) {
    logToFile(logsPath, `[ERROR] Init phase failed: ${error.message}`);
    return {
      success: false,
      plan: {} as AttackPlan,
      verificationCriteria: {} as VerificationCriteria,
      error: error.message,
    };
  }
}
