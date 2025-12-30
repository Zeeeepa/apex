/**
 * MetaTestingAgent
 *
 * A cognitive security testing agent inspired by CyberAutoAgent architecture.
 * Key patterns:
 * - Single agent with meta capabilities (vs multi-agent pipeline)
 * - Confidence-driven reasoning (KNOW → THINK → TEST → VALIDATE)
 * - Plans as external working memory with checkpoint protocol
 * - Meta-prompting for runtime optimization
 * - POC-driven vulnerability validation
 */

import { tool, hasToolCall, type StreamTextOnStepFinishCallback, type ToolSet } from 'ai';
import { z } from 'zod';
import { streamResponse, type AIModel } from '../../ai';
import { createPentestTools, type ExecuteCommandOpts, type ExecuteCommandResult, type HttpRequestOpts, type HttpRequestResult } from '../tools';
import { Logger } from '../logger';
import { Session } from '../../session';
import { join } from 'path';
import { existsSync, mkdirSync, writeFileSync, readdirSync, readFileSync } from 'fs';

// Import our custom tools and prompts
import type {
  MetaTestingAgentInput,
  MetaTestingAgentResult,
  MetaTestingProgressStatus,
  MetaTestingSessionInfo,
  CognitiveState,
} from './types';
import { createPocTool, createDocumentFindingTool } from './pocTools';
import { createPlanMemoryTools, loadPlan, loadAdaptations } from './planMemory';
import { createPromptOptimizerTool, loadOptimizedPrompt } from './promptOptimizer';
import { buildMetaTestingPrompt, buildUserPrompt } from './prompts/execution';
import { createAuthBypassTool } from './authBypassAgent';

/**
 * Retry configuration for API overload errors
 */
const RETRY_CONFIG = {
  maxRetries: 5,
  initialDelayMs: 1000,
  maxDelayMs: 60000,
  backoffMultiplier: 2,
};

/**
 * Check if error is an API overload/rate limit error
 */
function isOverloadedError(error: any): boolean {
  const message = error?.message?.toLowerCase() || '';
  const status = error?.status || error?.statusCode;

  return (
    status === 429 ||
    status === 529 ||
    status === 503 ||
    message.includes('overloaded') ||
    message.includes('rate limit') ||
    message.includes('too many requests') ||
    message.includes('capacity') ||
    message.includes('temporarily unavailable')
  );
}

/**
 * Sleep helper
 */
function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

/**
 * Save agent messages to subagents directory
 */
function saveAgentMessages(
  sessionRootPath: string,
  agentName: string,
  messages: any[],
  metadata?: Record<string, any>
): string {
  const subagentsDir = join(sessionRootPath, 'subagents');
  if (!existsSync(subagentsDir)) {
    mkdirSync(subagentsDir, { recursive: true });
  }

  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
  const sanitizedName = agentName.toLowerCase().replace(/[^a-z0-9-]/g, '-');
  const filename = `${sanitizedName}-${timestamp}.json`;
  const filepath = join(subagentsDir, filename);

  const data = {
    agentName,
    timestamp: new Date().toISOString(),
    ...metadata,
    messages,
  };

  writeFileSync(filepath, JSON.stringify(data, null, 2));
  return filepath;
}

/**
 * Count findings in the findings directory
 */
function countFindings(findingsPath: string): number {
  if (!existsSync(findingsPath)) {
    return 0;
  }

  try {
    return readdirSync(findingsPath).filter(f => f.endsWith('.json')).length;
  } catch {
    return 0;
  }
}

/**
 * Run the MetaTestingAgent
 *
 * This agent replaces the PentestOrchestrator + VulnerabilityTestAgents
 * with a single cognitive-loop-driven agent.
 */
export async function runMetaTestingAgent(
  input: MetaTestingAgentInput
): Promise<MetaTestingAgentResult> {
  const {
    targets,
    model,
    session,
    sessionConfig,
    onProgress,
    abortSignal,
    toolOverride,
  } = input;

  // Create logger
  const logger = new Logger(session, 'meta-testing-agent.log');
  logger.info(`Starting MetaTestingAgent for ${targets.length} targets`);

  // Ensure directories exist
  const pocsPath = join(session.rootPath, 'pocs');
  if (!existsSync(pocsPath)) {
    mkdirSync(pocsPath, { recursive: true });
  }

  // Create session info for tools
  const sessionInfo: MetaTestingSessionInfo = {
    id: session.id,
    rootPath: session.rootPath,
    findingsPath: session.findingsPath,
    logsPath: session.logsPath,
    pocsPath,
  };

  // Get outcome guidance
  const outcomeGuidance = sessionConfig?.outcomeGuidance || session.config?.outcomeGuidance || Session.DEFAULT_OUTCOME_GUIDANCE;

  // Get base pentest tools (execute_command, http_request)
  const baseTools = createPentestTools(
    session,
    model,
    toolOverride
  );

  // Create our specialized tools
  const { create_poc, pocPaths } = createPocTool(sessionInfo, logger, toolOverride);
  const { document_finding, findingPaths } = createDocumentFindingTool(sessionInfo, logger, targets[0]?.target || 'unknown');
  const { store_plan, get_plan, store_adaptation } = createPlanMemoryTools(sessionInfo, logger);
  const { optimize_prompt } = createPromptOptimizerTool(sessionInfo, logger);
  const auth_bypass_test = createAuthBypassTool(sessionInfo, logger, model, toolOverride);

  // Create completion tool
  const complete_testing = tool({
    description: `Signal that testing is complete.

Call this when:
- All targets have been tested
- All phases are complete or blocked
- Maximum budget reached
- No more productive approaches available

Provide a summary of what was tested and found.`,
    inputSchema: z.object({
      summary: z.string().describe('Summary of testing performed and results'),
      vulnerabilitiesFound: z.boolean().describe('Whether any vulnerabilities were confirmed'),
      confidenceInCoverage: z.number().min(0).max(100).describe('How confident you are that testing was thorough (0-100)'),
    }),
    execute: async (result) => {
      logger.info(`Testing complete: ${result.vulnerabilitiesFound ? 'Vulnerabilities found' : 'No vulnerabilities found'}`);
      return {
        success: true,
        message: 'Testing session completed.',
      };
    },
  });

  // Combine all tools
  const tools = {
    // Base pentest tools
    execute_command: baseTools.execute_command,
    http_request: baseTools.http_request,
    fuzz_endpoint: baseTools.fuzz_endpoint,
    mutate_payload: baseTools.mutate_payload,
    smart_enumerate: baseTools.smart_enumerate,
    cve_lookup: baseTools.cve_lookup,

    // POC tools
    create_poc,
    document_finding,

    // Plan memory tools
    store_plan,
    get_plan,
    store_adaptation,

    // Meta-prompting
    optimize_prompt,

    // Specialized subagents
    auth_bypass_test,

    // Completion
    complete_testing,
  };

  // Build prompts
  const systemPrompt = buildMetaTestingPrompt(outcomeGuidance);
  const userPrompt = buildUserPrompt({
    targets: targets.map(t => ({
      target: t.target,
      objective: t.objective,
      authenticationInfo: t.authenticationInfo,
    })),
    authenticationInstructions: sessionConfig?.authenticationInstructions || session.config?.authenticationInstructions,
  });

  // Report progress helper
  const reportProgress = (status: Partial<MetaTestingProgressStatus>) => {
    const plan = loadPlan(session.rootPath);
    const findingsCount = countFindings(session.findingsPath);

    onProgress?.({
      phase: 'testing',
      message: '',
      currentPhase: plan?.current_phase,
      totalPhases: plan?.total_phases,
      budgetUsed: plan?.budget_used,
      findingsCount,
      ...status,
    });
  };

  reportProgress({
    phase: 'planning',
    message: `Starting meta testing for ${targets.length} targets`,
  });

  // Run the agent with retry logic
  let attempt = 0;
  let lastError: any = null;

  while (attempt < RETRY_CONFIG.maxRetries) {
    attempt++;

    try {
      logger.info(`Running MetaTestingAgent (attempt ${attempt}/${RETRY_CONFIG.maxRetries})`);

      let stepCount = 0;
      let toolCallCount = 0;

      const streamResult = streamResponse({
        prompt: userPrompt,
        system: systemPrompt,
        model,
        tools,
        onStepFinish: (step) => {
          stepCount++;

          if (step.toolCalls && step.toolCalls.length > 0) {
            toolCallCount += step.toolCalls.length;

            for (const toolCall of step.toolCalls) {
              const toolName = toolCall.toolName;
              logger.info(`[Step ${stepCount}] Tool: ${toolName}`);
            }
          }

          // Log text output (cognitive loop reasoning)
          if (step.text && step.text.trim()) {
            const trimmedText = step.text.trim().substring(0, 300);
            if (trimmedText.length > 0) {
              // Check for hypothesis/validation markers
              if (trimmedText.includes('HYPOTHESIS') || trimmedText.includes('VALIDATION')) {
                logger.info(`[Step ${stepCount}] ${trimmedText}...`);
              }
            }
          }

          // Update progress
          reportProgress({
            phase: 'testing',
            message: `Step ${stepCount}, ${toolCallCount} tool calls`,
          });
        },
        stopWhen: hasToolCall('complete_testing'),
        abortSignal,
        silent: true,
      });

      // Consume the stream
      for await (const chunk of streamResult.fullStream) {
        if (chunk.type === 'tool-call') {
          const toolName = chunk.toolName || 'unknown';
          logger.info(`[Tool Call] ${toolName}`);

          reportProgress({
            phase: 'testing',
            message: `Executing: ${toolName}`,
          });
        } else if (chunk.type === 'error') {
          const error = (chunk as any).error;
          logger.error(`Stream error: ${error?.message || 'Unknown error'}`);

          if (isOverloadedError(error)) {
            throw error;
          }
        }
      }

      logger.info(`MetaTestingAgent finished. Steps: ${stepCount}, Tool calls: ${toolCallCount}`);

      // Save agent messages
      try {
        const response = await streamResult.response;
        if (response.messages && response.messages.length > 0) {
          const savedPath = saveAgentMessages(
            session.rootPath,
            'meta-testing-agent',
            response.messages,
            {
              targets: targets.map(t => t.target),
              stepCount,
              toolCallCount,
              findingsCount: findingPaths.length,
            }
          );
          logger.info(`Agent messages saved to: ${savedPath}`);
        }
      } catch (e: any) {
        logger.error(`Failed to save agent messages: ${e.message}`);
      }

      // Load final state
      const finalPlan = loadPlan(session.rootPath);
      const finalAdaptations = loadAdaptations(session.rootPath);
      const finalFindingsCount = countFindings(session.findingsPath);

      const cognitiveState: CognitiveState = {
        confidence: finalPlan?.budget_used ? 100 - finalPlan.budget_used : 50,
        current_hypothesis: 'Testing complete',
        evidence: finalAdaptations.filter(a => a.worked).map(a => a.approach),
        constraints_learned: finalAdaptations.filter(a => a.constraint_learned).map(a => a.constraint_learned!),
        step_count: stepCount,
        budget_used: finalPlan?.budget_used || 100,
      };

      reportProgress({
        phase: 'complete',
        message: `Testing complete. ${finalFindingsCount} findings documented.`,
        findingsCount: finalFindingsCount,
      });

      return {
        success: true,
        session,
        totalFindings: finalFindingsCount,
        pocPaths,
        findingPaths,
        summary: `MetaTestingAgent completed testing of ${targets.length} targets. Found ${finalFindingsCount} vulnerabilities across ${stepCount} steps.`,
        cognitiveState,
      };

    } catch (error: any) {
      lastError = error;

      if (isOverloadedError(error) && attempt < RETRY_CONFIG.maxRetries) {
        const delay = Math.min(
          RETRY_CONFIG.initialDelayMs * Math.pow(RETRY_CONFIG.backoffMultiplier, attempt - 1),
          RETRY_CONFIG.maxDelayMs
        );

        logger.info(`API overloaded, retrying in ${delay / 1000}s... (attempt ${attempt}/${RETRY_CONFIG.maxRetries})`);

        reportProgress({
          phase: 'testing',
          message: `API overloaded, retrying in ${delay / 1000}s...`,
        });

        await sleep(delay);
        continue;
      }

      // Not recoverable
      logger.error(`MetaTestingAgent error: ${error.message}`);
      throw error;
    }
  }

  // Max retries exhausted
  logger.error(`MetaTestingAgent failed after ${RETRY_CONFIG.maxRetries} attempts: ${lastError?.message}`);

  return {
    success: false,
    session,
    totalFindings: countFindings(session.findingsPath),
    pocPaths,
    findingPaths,
    summary: `MetaTestingAgent failed after ${RETRY_CONFIG.maxRetries} attempts.`,
    error: `Max retries exhausted. Last error: ${lastError?.message}`,
  };
}
