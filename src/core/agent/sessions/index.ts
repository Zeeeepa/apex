<<<<<<< HEAD
import {
  mkdirSync,
  existsSync,
  writeFileSync,
  readFileSync,
  readdirSync,
  statSync,
  rmSync,
} from "fs";
import { join } from "path";
import { homedir } from "os";
import { randomBytes } from "crypto";
import { RateLimiter, type RateLimiterConfig } from '../../services/rateLimiter';

=======
>>>>>>> design-update
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
<<<<<<< HEAD
export interface SessionConfig {
  offensiveHeaders?: OffensiveHeadersConfig;
  rateLimiter?: RateLimiterConfig;
}
=======
export type Session = Session.ExecutionSession;
>>>>>>> design-update

/**
 * @deprecated Use Session.SessionConfig from 'core/session' instead
 */
<<<<<<< HEAD
export const DEFAULT_OFFENSIVE_HEADERS: Record<string, string> = {
  'User-Agent': 'pensar-apex',
};

export interface Session {
  id: string;
  rootPath: string;
  findingsPath: string;
  scratchpadPath: string;
  logsPath: string;
  target: string;
  objective: string;
  startTime: string;
  config?: SessionConfig;
  _rateLimiter?: RateLimiter;
}
=======
export type SessionConfig = Session.SessionConfig;
>>>>>>> design-update

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
<<<<<<< HEAD
  config?: SessionConfig
): Session {
  const sessionId = generateSessionId(prefix);
  const rootPath = join(getExecutionsDir(), sessionId);
  const findingsPath = join(rootPath, "findings");
  const scratchpadPath = join(rootPath, "scratchpad");
  const logsPath = join(rootPath, "logs");

  // Create directory structure
  ensureDirectoryExists(rootPath);
  ensureDirectoryExists(findingsPath);
  ensureDirectoryExists(scratchpadPath);
  ensureDirectoryExists(logsPath);

  const session: Session = {
    id: sessionId,
    rootPath,
    findingsPath,
    scratchpadPath,
    logsPath,
    target,
    objective: objective ?? "",
    startTime: new Date().toISOString(),
    config,
  };

  // Initialize rate limiter eagerly to prevent race conditions
  // when multiple agents access the session simultaneously
  if (config?.rateLimiter) {
    session._rateLimiter = new RateLimiter(config.rateLimiter);
  }

  // Write session metadata
  const metadataPath = join(rootPath, "session.json");
  writeFileSync(metadataPath, JSON.stringify(session, null, 2));

  // Create initial README
  const readmePath = join(rootPath, "README.md");
  const readme = `# Penetration Test Session

**Session ID:** ${sessionId}
**Target:** ${target}
**Objective:** ${objective}
**Started:** ${session.startTime}

## Directory Structure

- \`findings/\` - Security findings and vulnerabilities
- \`scratchpad/\` - Notes and temporary data during testing
- \`logs/\` - Execution logs and command outputs
- \`session.json\` - Session metadata

## Findings

Security findings will be documented in the \`findings/\` directory as individual files.

## Status

Testing in progress...
`;

  writeFileSync(readmePath, readme);

  return session;
=======
  config?: Session.SessionConfig
): never {
  throw new Error(
    "createSession is deprecated. Use await Session.createExecution({...}) from 'core/session' instead. " +
    "See migration guide in core/agent/sessions/index.ts"
  );
>>>>>>> design-update
}

/**
 * @deprecated Use Session.getOffensiveHeaders(session) from 'core/session' instead
 */
<<<<<<< HEAD
function ensureDirectoryExists(path: string): void {
  if (!existsSync(path)) {
    mkdirSync(path, { recursive: true });
  }
}

/**
 * Get a session by ID
 */
export function getSession(sessionId: string): Session | null {
  const sessionPath = join(getExecutionsDir(), sessionId);
  const metadataPath = join(sessionPath, "session.json");

  if (!existsSync(metadataPath)) {
    return null;
  }

  const metadata = JSON.parse(readFileSync(metadataPath, "utf-8"));
  return metadata as Session;
}

/**
 * Extract timestamp from session ID for sorting
 * Session IDs are in format: "timestamp" or "prefix-timestamp" (base36)
 */
function extractTimestamp(sessionId: string): number {
  const parts = sessionId.split('-');
  const timestampBase36 = parts[parts.length - 1];
  return parseInt(timestampBase36 || '', 36);
}

/**
 * List all sessions, sorted by creation time (newest first)
 */
export function listSessions(): string[] {
  const executionsDir = getExecutionsDir();

  if (!existsSync(executionsDir)) {
    return [];
  }

  const entries = readdirSync(executionsDir);

  const directories = entries.filter((entry: string) => {
    const fullPath = join(executionsDir, entry);
    return statSync(fullPath).isDirectory();
  });

  // Sort by timestamp embedded in session ID (newest first)
  // O(n log n) time, O(1) extra space, no file I/O
  return directories.sort((a, b) => {
    const timestampA = extractTimestamp(a);
    const timestampB = extractTimestamp(b);
    return timestampB - timestampA; // Descending order
  });

}

/**
 * Clean up old sessions (optional utility)
 */
export function cleanupOldSessions(daysOld: number = 30): number {
  const executionsDir = getExecutionsDir();

  if (!existsSync(executionsDir)) {
    return 0;
  }

  const entries = readdirSync(executionsDir);
  const now = Date.now();
  const cutoff = now - daysOld * 24 * 60 * 60 * 1000;
  let cleaned = 0;

  for (const entry of entries) {
    const fullPath = join(executionsDir, entry);
    const stats = statSync(fullPath);

    if (stats.isDirectory() && stats.mtimeMs < cutoff) {
      rmSync(fullPath, { recursive: true, force: true });
      cleaned++;
    }
  }

  return cleaned;
}

/**
 * Resolve offensive headers based on session config
 */
export function getOffensiveHeaders(session: Session): Record<string, string> | undefined {
  const config = session.config?.offensiveHeaders;

  if (!config || config.mode === 'none') {
    return undefined;
  }

  if (config.mode === 'default') {
    return DEFAULT_OFFENSIVE_HEADERS;
  }

  if (config.mode === 'custom' && config.headers) {
    return config.headers;
  }

  return undefined;
}
=======
export const getOffensiveHeaders = Session.getOffensiveHeaders;
>>>>>>> design-update
