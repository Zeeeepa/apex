import z from "zod";
import { Identifier } from "../id/id";
import { Installation } from "../installation";
import { Storage } from "../storage";
import type { Message } from "../messages/types";
import { Messages } from "../messages";

export namespace Session {

    const OffensiveHeadersConfig = z.object({
        mode: z.enum(["none", "default", "custom"]),
        headers: z.record(z.string(), z.string())
    });

    const SessionConfig = z.object({
        offensiveHeaders: OffensiveHeadersConfig.optional()
    });

    export const SessionInfo = z.object({
        id: Identifier.schema("session"),
        name: z.string(),
        version: z.string(),
        target: z.string().optional(),
        targets: z.array(z.string()).optional(),
        config: SessionConfig.optional(),
        time: z.object({
            created: z.number(),
            updated: z.number(),
        }),
    }).meta({
        ref: "Session"
    });

    export type SessionInfo = z.output<typeof SessionInfo>;

    export async function create(input: { id?: string; name: string }) {
        const result: SessionInfo = {
            id: Identifier.descending('session', input.id),
            version: await Installation.getVersion(),
            name: input.name,
            time: {
                created: Date.now(),
                updated: Date.now()
            }
        }

        console.info("created session", result);

        await Storage.write(["session", result.id], result);
        return result;
    }

    export const get = async (id: string) => {
        const read = await Storage.read<SessionInfo>(["session", id]);
        return read;
    }

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