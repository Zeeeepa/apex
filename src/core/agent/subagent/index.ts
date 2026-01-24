import { join } from "path";
import { existsSync, mkdirSync } from "fs";
import type { AIModel } from "../../ai";
import type { Session } from "../../session";
import type { SubAgentConfig, SubAgentSession, InitAgentResult, AttackAgentResult, Finding } from "./types";
import { runInitAgent } from "./initAgent";
import { runAttackAgent } from "./attackAgent";
import { nanoid } from "nanoid";

export interface RunSubAgentInput {
  config: SubAgentConfig;
  session: Session.SessionInfo;
  workspace: string;
  model: AIModel;
  abortSignal?: AbortSignal;
  /** Tool override for sandboxing execute_command */
  toolOverride?: {
    execute_command?: (opts: any) => Promise<any>;
  };
  onInitComplete?: (result: InitAgentResult) => void;
  onAttackComplete?: (result: AttackAgentResult) => void;
}

export interface RunSubAgentResult {
  subagentId: string;
  initResult: InitAgentResult;
  attackResult: AttackAgentResult;
  findings: Finding[];
  success: boolean;
}

function createSubAgentSession(
  config: SubAgentConfig,
  session: Session.SessionInfo
): SubAgentSession {
  const subagentId = config.id || `subagent-${nanoid(6)}`;
  const rootPath = join(session.rootPath, "subagents", subagentId);

  mkdirSync(rootPath, { recursive: true });
  mkdirSync(join(rootPath, "scripts"), { recursive: true });
  mkdirSync(join(rootPath, "findings"), { recursive: true });

  return {
    id: subagentId,
    sessionId: session.id,
    config,
    rootPath,
    planPath: join(rootPath, "plan.json"),
    verificationPath: join(rootPath, "verification.json"),
    findingsPath: join(rootPath, "findings"),
    scriptsPath: join(rootPath, "scripts"),
  };
}

export async function runSubAgent(input: RunSubAgentInput): Promise<RunSubAgentResult> {
  const { config, session, workspace, model, abortSignal, toolOverride, onInitComplete, onAttackComplete } = input;

  const subagentSession = createSubAgentSession(config, session);

  const initResult = await runInitAgent(subagentSession, model, abortSignal);
  onInitComplete?.(initResult);

  if (!initResult.success) {
    return {
      subagentId: subagentSession.id,
      initResult,
      attackResult: {
        success: false,
        findings: [],
        summary: "Init phase failed, attack not started",
        error: initResult.error,
      },
      findings: [],
      success: false,
    };
  }

  const attackResult = await runAttackAgent(subagentSession, session, workspace, model, abortSignal, toolOverride);
  onAttackComplete?.(attackResult);

  return {
    subagentId: subagentSession.id,
    initResult,
    attackResult,
    findings: attackResult.findings,
    success: attackResult.success && attackResult.findings.length >= 0,
  };
}

export async function runSubAgentsParallel(
  inputs: RunSubAgentInput[],
  concurrencyLimit: number = 10
): Promise<RunSubAgentResult[]> {
  const { default: pLimit } = await import("p-limit");
  const limit = pLimit(concurrencyLimit);

  const promises = inputs.map((input) =>
    limit(() => runSubAgent(input))
  );

  return Promise.all(promises);
}

/**
 * Run sub-agents in parallel with a callback for each completion
 */
export async function runSubAgentsParallelWithCallbacks(
  inputs: RunSubAgentInput[],
  concurrencyLimit: number = 10,
  onComplete?: (result: RunSubAgentResult) => void
): Promise<RunSubAgentResult[]> {
  const { default: pLimit } = await import("p-limit");
  const limit = pLimit(concurrencyLimit);

  const results: RunSubAgentResult[] = [];

  const promises = inputs.map((input) =>
    limit(async () => {
      const result = await runSubAgent(input);
      results.push(result);
      onComplete?.(result);
      return result;
    })
  );

  await Promise.all(promises);
  return results;
}

export * from "./types";
export * from "./repl";
export { runInitAgent } from "./initAgent";
export { runAttackAgent } from "./attackAgent";
