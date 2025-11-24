// Braintrust Context Management
//
// Provides AsyncLocalStorage-based context for config propagation.
// This eliminates the need to thread `appConfig` through function signatures.
//
// The context is set once at entry points (TUI hooks, scripts, etc.) and
// automatically propagates through the entire async call tree.
//
// Usage:
//   // At entry point (e.g., TUI hook):
//   const appConfig = await config.get();
//   await withConfigContext(appConfig, async () => {
//     await runAgent({ target, model }); // No appConfig param needed!
//   });
//
//   // In traced functions (automatic via factories):
//   const appConfig = getConfigFromContext(); // Gets config from context

import { AsyncLocalStorage } from 'async_hooks';
import type { Config } from '../config/config';
import { config } from '../config';

// AsyncLocalStorage for maintaining config context across async operations
const configStorage = new AsyncLocalStorage<Config>();

/**
 * Provides config context for an entire async call tree.
 *
 * This should be called at entry points (TUI hooks, CLI scripts, etc.)
 * to establish the config context for all downstream operations.
 *
 * The context automatically propagates through:
 * - Async/await calls
 * - Promise chains
 * - Callbacks
 * - Nested function calls
 *
 * This enables traced functions to access config without it being passed
 * explicitly through every function signature.
 *
 * @param appConfig - The config object to provide in context
 * @param fn - The async function to run with config context
 * @returns The result of the function
 *
 * @example
 * ```typescript
 * // In a TUI hook or script entry point:
 * async function beginExecution() {
 *   const appConfig = await config.get();
 *
 *   await withConfigContext(appConfig, async () => {
 *     // All code inside here has access to config via getConfigFromContext()
 *     const result = await runAgent({ target: 'example.com' });
 *     // No need to pass appConfig!
 *   });
 * }
 * ```
 */
export function withConfigContext<T>(
  appConfig: Config,
  fn: () => Promise<T>
): Promise<T> {
  return configStorage.run(appConfig, fn);
}

/**
 * Gets the config from the current async context.
 *
 * This is used internally by traced functions (via factories) to access
 * the config without it being passed explicitly.
 *
 * If no context is active, this will attempt to fetch config synchronously
 * as a fallback. However, this should be avoided as it may not maintain
 * AsyncLocalStorage context properly.
 *
 * @returns The config from context, or null if no context is active
 *
 * @example
 * ```typescript
 * // Inside a traced function (this happens automatically via factories):
 * async function myTracedFunction() {
 *   const appConfig = getConfigFromContext();
 *   if (appConfig && isBraintrustEnabled(appConfig)) {
 *     // Create span...
 *   }
 * }
 * ```
 */
export function getConfigFromContext(): Config | null {
  const contextConfig = configStorage.getStore();

  if (contextConfig) {
    return contextConfig;
  }

  // Fallback: if no context is active, return null
  // The caller should handle this by either:
  // 1. Fetching config (but this breaks AsyncLocalStorage nesting)
  // 2. Skipping tracing gracefully
  return null;
}

/**
 * Gets config from context with async fallback.
 *
 * This version will fetch config if not in context, but should be used
 * sparingly as it may break AsyncLocalStorage nesting for spans.
 *
 * Prefer using withConfigContext at entry points instead.
 *
 * @returns The config from context or fetched
 */
export async function getConfigFromContextOrFetch(): Promise<Config> {
  const contextConfig = getConfigFromContext();
  if (contextConfig) {
    return contextConfig;
  }

  // Fallback to fetching (but warn about it)
  console.warn(
    '[Braintrust] Config accessed outside of withConfigContext. ' +
    'Span nesting may not work correctly. ' +
    'Consider wrapping entry point with withConfigContext().'
  );

  return await config.get();
}

/**
 * Checks if currently running within a config context.
 *
 * Useful for debugging context propagation issues.
 *
 * @returns true if context is active, false otherwise
 */
export function hasConfigContext(): boolean {
  return configStorage.getStore() !== undefined;
}
