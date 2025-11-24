// Braintrust Factory Pattern
//
// Provides factory functions for creating auto-traced agents and tools.
// This eliminates the need for manual traceAgent/traceToolCall wrapping at call sites.
//
// The factory pattern allows you to wrap functions once at definition time,
// making the integration feel more like a decorator (similar to Python's @trace_agent).
//
// Usage:
//   const myAgent = createTracedAgent('agent-name', agentImpl, (args) => ({ metadata }));
//   await myAgent(args); // Automatically traced
//
// This keeps Braintrust integration isolated while making it trivial to add tracing
// to new agents and tools.

import { traceAgent, traceToolCall, traceAICall } from './tracer';
import { isBraintrustEnabled } from './config';
import { getConfigFromContext } from './context';
import type { AgentSpanMetadata, ToolSpanMetadata, AISpanMetadata } from './types';
import type { Config } from '../config/config';

// Registry for tracking what's been instrumented (useful for debugging and testing)
const REGISTERED_AGENTS = new Map<string, any>();
const REGISTERED_TOOLS = new Map<string, any>();

/**
 * Type for metadata extractor functions.
 * Takes the function arguments and returns the metadata to log.
 */
type MetadataExtractor<TArgs, TMeta> = (args: TArgs) => TMeta;

/**
 * Type for the metadata updater callback provided to traced functions.
 * Allows updating span metadata during execution.
 */
type MetadataUpdater<TMeta> = (updates: Partial<TMeta>) => void;

/**
 * Creates a Braintrust-traced agent wrapper.
 *
 * This factory eliminates manual traceAgent() calls and config threading.
 * The wrapped function automatically traces execution when Braintrust is enabled.
 *
 * @param agentName - Name for the agent span (appears as `agent:<name>` in Braintrust)
 * @param agentFn - The agent implementation function
 * @param getMetadata - Function to extract metadata from agent arguments
 * @returns Wrapped agent function with automatic tracing
 *
 * @example
 * ```typescript
 * // Define your agent implementation
 * async function pentestAgentImpl(args: RunAgentProps): Promise<RunAgentResult> {
 *   // ... agent logic
 * }
 *
 * // Wrap it with automatic tracing
 * export const runAgent = createTracedAgent(
 *   'pentest',
 *   pentestAgentImpl,
 *   (args) => ({
 *     agent_type: 'pentest',
 *     session_id: args.session?.id || '',
 *     target: args.target,
 *     model: args.model,
 *   })
 * );
 *
 * // Use it normally - tracing happens automatically
 * const result = await runAgent({ target: 'example.com', model: 'gpt-4' });
 * ```
 */
export function createTracedAgent<TArgs extends Record<string, any>, TResult>(
  agentName: string,
  agentFn: (args: TArgs & { updateMetadata?: MetadataUpdater<AgentSpanMetadata> }) => Promise<TResult>,
  getMetadata: MetadataExtractor<TArgs, AgentSpanMetadata>
): (args: TArgs) => Promise<TResult> {
  const wrappedAgent = async (args: TArgs): Promise<TResult> => {
    // Get config from context (set by withConfigContext at entry points)
    const appConfig = getConfigFromContext();

    // If no config or disabled, execute without tracing
    if (!appConfig || !isBraintrustEnabled(appConfig)) {
      return await agentFn(args);
    }

    const metadata = getMetadata(args);

    return await traceAgent(
      appConfig,
      agentName,
      metadata,
      async (updateMetadata) => {
        // Pass updateMetadata callback to agent implementation
        return await agentFn({ ...args, updateMetadata });
      }
    );
  };

  // Register for visibility
  REGISTERED_AGENTS.set(agentName, wrappedAgent);

  return wrappedAgent;
}

/**
 * Creates a Braintrust-traced tool wrapper.
 *
 * This factory eliminates manual traceToolCall() wrapping and conditional checks.
 * The wrapped function automatically traces execution when Braintrust is enabled.
 *
 * @param toolName - Name for the tool span (appears as `tool:<name>` in Braintrust)
 * @param toolFn - The tool implementation function
 * @param getMetadata - Function to extract metadata from tool arguments
 * @returns Wrapped tool function with automatic tracing
 *
 * @example
 * ```typescript
 * // Define your tool implementation
 * async function executeCommandImpl(opts: ExecuteCommandOpts): Promise<ExecuteCommandResult> {
 *   // ... command execution logic
 * }
 *
 * // Wrap it with automatic tracing
 * export const executeCommand = createTracedTool(
 *   'execute-command',
 *   executeCommandImpl,
 *   (opts) => ({
 *     tool_name: 'execute_command',
 *     endpoint: opts.endpoint,
 *     command: opts.command,
 *   })
 * );
 *
 * // Use it normally - tracing happens automatically
 * const result = await executeCommand({ endpoint: '192.168.1.1', command: 'ls' });
 * ```
 */
export function createTracedTool<TArgs, TResult>(
  toolName: string,
  toolFn: (args: TArgs) => Promise<TResult>,
  getMetadata: MetadataExtractor<TArgs, ToolSpanMetadata>
): (args: TArgs) => Promise<TResult> {
  const wrappedTool = async (args: TArgs): Promise<TResult> => {
    // Get config from context
    const appConfig = getConfigFromContext();

    // If no config or disabled, execute without tracing (early return for performance)
    if (!appConfig || !isBraintrustEnabled(appConfig)) {
      return await toolFn(args);
    }

    const metadata = getMetadata(args);

    return await traceToolCall(
      appConfig,
      toolName,
      metadata,
      async (updateMetadata) => {
        try {
          const result = await toolFn(args);
          // Auto-capture success
          updateMetadata({ success: true });
          return result;
        } catch (error) {
          // Auto-capture failure
          updateMetadata({
            success: false,
            error: error instanceof Error ? error.message : String(error)
          });
          throw error;
        }
      }
    );
  };

  // Register for visibility
  REGISTERED_TOOLS.set(toolName, wrappedTool);

  return wrappedTool;
}

/**
 * Creates a Braintrust-traced AI call wrapper.
 *
 * This factory wraps AI model calls with automatic tracing.
 * Less commonly used directly (usually wrapped via onStepFinish callbacks).
 *
 * @param callName - Name for the AI call span (appears as `ai:<name>` in Braintrust)
 * @param callFn - The AI call implementation function
 * @param getMetadata - Function to extract metadata from call arguments
 * @returns Wrapped AI call function with automatic tracing
 */
export function createTracedAICall<TArgs, TResult>(
  callName: string,
  callFn: (args: TArgs) => Promise<TResult>,
  getMetadata: MetadataExtractor<TArgs, AISpanMetadata>
): (args: TArgs) => Promise<TResult> {
  return async (args: TArgs): Promise<TResult> => {
    const appConfig = getConfigFromContext();

    if (!appConfig || !isBraintrustEnabled(appConfig)) {
      return await callFn(args);
    }

    const metadata = getMetadata(args);

    return await traceAICall(
      appConfig,
      callName,
      metadata,
      async (updateMetadata) => {
        const result = await callFn(args);
        return result;
      }
    );
  };
}

/**
 * Gets list of registered agent names (for debugging/testing).
 */
export function getRegisteredAgents(): string[] {
  return Array.from(REGISTERED_AGENTS.keys());
}

/**
 * Gets list of registered tool names (for debugging/testing).
 */
export function getRegisteredTools(): string[] {
  return Array.from(REGISTERED_TOOLS.keys());
}

/**
 * Clears all registrations (for testing).
 */
export function clearRegistry(): void {
  REGISTERED_AGENTS.clear();
  REGISTERED_TOOLS.clear();
}
