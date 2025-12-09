import z from "zod";
import path from "path";
import os from "os";
import { Identifier } from "../id/id";
import { Installation } from "../installation";
import { Storage } from "../storage";
import type { Message } from "../messages/types";
import { Messages } from "../messages";

export namespace Session {

    /**
     * Default outcome guidance (safe, non-destructive)
     */
    export const DEFAULT_OUTCOME_GUIDANCE =
    "Prove the exploit can be run but do not exfiltrate data or cause any harm to the system. " +
    "Create proof-of-concept exploits that demonstrate the vulnerability exists without causing damage.";

    /**
     * Benchmark outcome guidance (extract flags)
     */
    export const BENCHMARK_OUTCOME_GUIDANCE =
    "Exfiltrate data to extract the flag value. " +
    "Create proof-of-concept exploits that successfully extract the flag from the target system.";

    /**
     * Default headers for pensar-apex
     */
    export const DEFAULT_OFFENSIVE_HEADERS: Record<string, string> = {
        'User-Agent': 'pensar-apex',
    };


    const AuthCredentialsObject = z.object({
        username: z.string(),
        password: z.string(),
        loginUrl: z.string().optional(),
        additionalFields: z.record(z.string(), z.string()).optional()
    });

    export type AuthCredentials = z.infer<typeof AuthCredentialsObject>;

    const ScopeConstraintsObject = z.object({
        allowedHosts: z.string().array().optional(),
        allowedPorts: z.number().array().optional(),
        strictScope: z.boolean().optional()
    });

    export type ScopeConstraints = z.infer<typeof ScopeConstraintsObject>;

    const OffensiveHeadersConfigObject = z.object({
        mode: z.enum(["none", "default", "custom"]),
        headers: z.record(z.string(), z.string()).optional()
    });

    export type OffensiveHeadersConfig = z.infer<typeof OffensiveHeadersConfigObject>;

    const SessionConfigObject = z.object({
        offensiveHeaders: OffensiveHeadersConfigObject.optional(),
        mode: z.enum(['auto', 'plan']).optional(),
        outcomeGuidance: z.string().optional(),
        scopeConstraints: ScopeConstraintsObject.optional(),
        authCredentials: AuthCredentialsObject.optional(),
        authenticationInstructions: z.string().optional()
    });

    export type SessionConfig = z.infer<typeof SessionConfigObject>;

    // ============================================================================
    // ExecutionSession - Legacy-compatible session interface for agent consumption
    // ============================================================================

    /**
     * Legacy-compatible session interface that provides directory paths
     * for agent artifact storage (findings, POCs, logs, etc.)
     *
     * This replaces the old core/agent/sessions module with safe Storage writes.
     */
    export interface ExecutionSession {
        /** Unique session identifier (format: {prefix}-ses_{timestamp}_{random}) */
        id: string;
        /** Root path for all session artifacts (~/.pensar/executions/{id}) */
        rootPath: string;
        /** Path for security findings (~/.pensar/executions/{id}/findings) */
        findingsPath: string;
        /** Path for agent scratchpad notes (~/.pensar/executions/{id}/scratchpad) */
        scratchpadPath: string;
        /** Path for execution logs (~/.pensar/executions/{id}/logs) */
        logsPath: string;
        /** Path for proof-of-concept scripts (~/.pensar/executions/{id}/pocs) */
        pocsPath: string;
        /** Target URL or system being tested */
        target: string;
        /** Testing objective description */
        objective: string;
        /** ISO timestamp when session was created */
        startTime: string;
        /** Session configuration */
        config?: SessionConfig;
    }

    /**
     * Input for creating an execution session
     */
    export interface CreateExecutionInput {
        /** Target URL or system to test */
        target: string;
        /** Testing objective description */
        objective?: string;
        /** Optional prefix for session ID (e.g., "benchmark-XBEN-001-24") */
        prefix?: string;
        /** Session configuration */
        config?: SessionConfig;
    }

    /**
     * Get the base Pensar directory path
     */
    export function getPensarDir(): string {
        return path.join(os.homedir(), ".pensar");
    }

    /**
     * Get the executions directory path
     */
    export function getExecutionsDir(): string {
        return path.join(getPensarDir(), "executions");
    }

    /**
     * Get the root path for a session's execution directory
     */
    export function getExecutionRoot(id: string): string {
        return path.join(getExecutionsDir(), id);
    }

    /**
     * Create a new execution session with directory structure for agent artifacts.
     * Uses Storage namespace for safe writes with locking.
     *
     * Directory structure created:
     * ~/.pensar/executions/{id}/
     * ├── session.json      # Session metadata
     * ├── README.md         # Session documentation
     * ├── findings/         # Security findings
     * ├── scratchpad/       # Agent notes
     * ├── logs/             # Execution logs
     * └── pocs/             # Proof-of-concept scripts
     */
    export async function createExecution(input: CreateExecutionInput): Promise<ExecutionSession> {
        // Generate ID with proper separator: {prefix}-ses_{timestamp}_{random}
        const baseId = Identifier.descending('session');
        const id = input.prefix ? `${input.prefix}-${baseId}` : baseId;

        // Calculate paths
        const rootPath = getExecutionRoot(id);
        const findingsPath = path.join(rootPath, "findings");
        const scratchpadPath = path.join(rootPath, "scratchpad");
        const logsPath = path.join(rootPath, "logs");
        const pocsPath = path.join(rootPath, "pocs");

        // Create directory structure with locking
        await Storage.createDir(["executions", id]);
        await Storage.createDir(["executions", id, "findings"]);
        await Storage.createDir(["executions", id, "scratchpad"]);
        await Storage.createDir(["executions", id, "logs"]);
        await Storage.createDir(["executions", id, "pocs"]);

        const startTime = new Date().toISOString();

        const session: ExecutionSession = {
            id,
            rootPath,
            findingsPath,
            scratchpadPath,
            logsPath,
            pocsPath,
            target: input.target,
            objective: input.objective || "",
            startTime,
            config: {
                ...input.config,
                outcomeGuidance: input.config?.outcomeGuidance || DEFAULT_OUTCOME_GUIDANCE,
            },
        };

        // Store session metadata with locking
        const sessionMetadata = {
            ...session,
            version: await Installation.getVersion(),
            time: {
                created: Date.now(),
                updated: Date.now(),
            },
        };

        await Storage.write(["executions", id, "session"], sessionMetadata);

        // Write README.md
        const readme = generateSessionReadme(session);
        await Storage.writeRaw(["executions", id, "README.md"], readme);

        console.info("created execution session", session.id);

        return session;
    }

    /**
     * Generate README.md content for a session
     */
    function generateSessionReadme(session: ExecutionSession): string {
        return `# Penetration Test Session

**Session ID:** ${session.id}
**Target:** ${session.target}
**Objective:** ${session.objective}
**Started:** ${session.startTime}

## Directory Structure

- \`findings/\` - Security findings and vulnerabilities
- \`scratchpad/\` - Notes and temporary data during testing
- \`logs/\` - Execution logs and command outputs
- \`pocs/\` - Proof-of-concept exploit scripts
- \`session.json\` - Session metadata

## Findings

Security findings will be documented in the \`findings/\` directory as individual files.

## Status

Testing in progress...
`;
    }

    /**
     * Get an execution session by ID
     */
    export async function getExecution(sessionId: string): Promise<ExecutionSession | null> {
        try {
            const metadata = await Storage.read<ExecutionSession & { version: string; time: { created: number; updated: number } }>(
                ["executions", sessionId, "session"]
            );
            return metadata;
        } catch (e) {
            if (e instanceof Storage.NotFoundError) {
                return null;
            }
            throw e;
        }
    }

    /**
     * Resolve offensive headers based on session config
     */
    export function getOffensiveHeaders(session: ExecutionSession): Record<string, string> | undefined {
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

    // ============================================================================
    // SessionInfo - Original session metadata interface
    // ============================================================================

    export const SessionInfoObject = z.object({
        id: Identifier.schema("session"),
        name: z.string(),
        version: z.string(),
        targets: z.array(z.string()).optional(),
        config: SessionConfigObject.optional(),
        time: z.object({
            created: z.number(),
            updated: z.number(),
        }),
    }).meta({
        ref: "Session"
    });

    export type SessionInfo = z.output<typeof SessionInfoObject>;

    interface CreateInputProps {
        id?: string;
        name: string;
        prefix?: string;
        mode?: Extract<SessionInfo, "mode">;
        offensiveHeaders?: OffensiveHeadersConfig;
        outcomeGuidance?: string;
    }

    export async function create(input: CreateInputProps) {
        const result: SessionInfo = {
            id: `${input.prefix ? input.prefix : ""}` + Identifier.descending('session', input.id),
            version: await Installation.getVersion(),
            name: input.name,
            time: {
                created: Date.now(),
                updated: Date.now()
            },
            config: {
                mode: input.mode || "auto",
                offensiveHeaders: input.offensiveHeaders || {
                    mode: "default",
                    headers: {
                        "User-Agent": "pensar-apex"
                    }
                },
                outcomeGuidance: input.outcomeGuidance || DEFAULT_OUTCOME_GUIDANCE
            }
        };

        console.info("created session", result);

        await Storage.write(["session", result.id], result);
        await Storage.createDir(["executions", result.id]);
        return result;
    }

    export const get = async (id: string) => {
        const read = await Storage.read<SessionInfo>(["session", id]);
        return read;
    }

    export const executionPath = (id: string) => Storage.locate(["executions", id], "");


    export async function update(id: string, editor: (session: SessionInfo) => void) {
        const result = await Storage.update<SessionInfo>(["session", id], (draft) => {
            editor(draft);
            draft.time.updated = Date.now()
        });
        console.info("updated session", result);
        return result;
    }

    const MessagesInput = z.object({
        sessionId: Identifier.schema("session"),
        limit: z.number().optional()
    });

    export const messages = async (input: z.output<typeof MessagesInput>) => {
        const result = [] as Message[];
        for await (const msg of Messages.stream(input)) {
            if(input.limit && result.length >= input.limit) break;
            result.push(msg);
        }
        result.reverse();
        return result;
    }

    export async function* list() {
        for (const item of await Storage.list(["session"])) {
            yield Storage.read<SessionInfo>(item);
        }
    }


    const RemoveInput = z.object({
        sessionId: Identifier.schema("session")
    });

    export const remove = async (input: z.output<typeof RemoveInput>) =>{
        try {
            const session = await get(input.sessionId);
            for (const msg of await Storage.list(["message", input.sessionId])) {
                await Storage.remove(msg);
            }
            await Storage.remove(["session", input.sessionId]);
        } catch(e) {
            console.error(e);
        }
    }

    export const updateMessage = async (msg: Message) => {
        await Storage.write(["message", msg.sessionId, msg.id], msg);
        return msg
    }

    const RemoveMsgInput = z.object({
        sessionId: Identifier.schema("session"),
        messageId: Identifier.schema("message")
    });

    export const removeMessage = async (input: z.output<typeof RemoveMsgInput>) => {
        await Storage.remove(["message", input.sessionId, input.messageId]);
        return input.messageId;
    }

}