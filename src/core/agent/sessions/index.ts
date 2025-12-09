/**
 * @deprecated This module is deprecated. Use `core/session` instead.
 *
 * Migration guide:
 * - Import { Session } from '../../session' (or '../session' depending on path)
 * - Use Session.ExecutionSession type instead of Session
 * - Use await Session.createExecution({...}) instead of createSession(...)
 * - Use Session.DEFAULT_OUTCOME_GUIDANCE instead of DEFAULT_OUTCOME_GUIDANCE
 * - Use Session.BENCHMARK_OUTCOME_GUIDANCE instead of BENCHMARK_OUTCOME_GUIDANCE
 * - Use Session.getOffensiveHeaders(session) instead of getOffensiveHeaders(session)
 *
 * This module will be removed in a future version.
 */

// Re-export from new location for backward compatibility
import { Session } from "../../session";

/**
 * @deprecated Use Session.ExecutionSession from 'core/session' instead
 */
export type Session = Session.ExecutionSession;

/**
 * @deprecated Use Session.SessionConfig from 'core/session' instead
 */
export type SessionConfig = Session.SessionConfig;

/**
 * @deprecated Use Session.AuthCredentials from 'core/session' instead
 */
export type AuthCredentials = Session.AuthCredentials;

/**
 * @deprecated Use Session.OffensiveHeadersConfig from 'core/session' instead
 */
export type OffensiveHeadersConfig = Session.OffensiveHeadersConfig;

/**
 * @deprecated Use Session.ScopeConstraints from 'core/session' instead
 */
export type ScopeConstraints = Session.ScopeConstraints;

/**
 * @deprecated Use Session.DEFAULT_OFFENSIVE_HEADERS from 'core/session' instead
 */
export const DEFAULT_OFFENSIVE_HEADERS = Session.DEFAULT_OFFENSIVE_HEADERS;

/**
 * @deprecated Use Session.DEFAULT_OUTCOME_GUIDANCE from 'core/session' instead
 */
export const DEFAULT_OUTCOME_GUIDANCE = Session.DEFAULT_OUTCOME_GUIDANCE;

/**
 * @deprecated Use Session.BENCHMARK_OUTCOME_GUIDANCE from 'core/session' instead
 */
export const BENCHMARK_OUTCOME_GUIDANCE = Session.BENCHMARK_OUTCOME_GUIDANCE;

/**
 * @deprecated Use Session.getPensarDir() from 'core/session' instead
 */
export const getPensarDir = Session.getPensarDir;

/**
 * @deprecated Use Session.getExecutionsDir() from 'core/session' instead
 */
export const getExecutionsDir = Session.getExecutionsDir;

/**
 * @deprecated Use await Session.createExecution({...}) from 'core/session' instead.
 * Note: The new function is async and has a different signature.
 *
 * Migration:
 * Old: createSession(target, objective, prefix, config)
 * New: await Session.createExecution({ target, objective, prefix, config })
 */
export function createSession(
  target: string,
  objective?: string,
  prefix?: string,
  config?: Session.SessionConfig
): never {
  throw new Error(
    "createSession is deprecated. Use await Session.createExecution({...}) from 'core/session' instead. " +
    "See migration guide in core/agent/sessions/index.ts"
  );
}

/**
 * @deprecated Use Session.getOffensiveHeaders(session) from 'core/session' instead
 */
export const getOffensiveHeaders = Session.getOffensiveHeaders;
