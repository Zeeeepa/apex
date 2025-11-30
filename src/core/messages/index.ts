import type { Session } from "../agent/sessions";
import fs from "fs";
import { z } from 'zod';
import { ModelMessageObject } from "./types";
import type { ToolMessage, Message } from "./types";
import { Identifier } from "../id/id";
import { Storage } from "../storage";

export namespace Messages {

  const StreamInput = z.object({
    sessionId: Identifier.schema("session"),
  });

  export async function* stream (input: z.output<typeof StreamInput>) {
    const list = await Array.fromAsync(await Storage.list(["message", input.sessionId]));
    for (let i = list.length - 1; i  >= 0; i--) {
      yield await get({
        sessionId: input.sessionId,
        messageId: list[i][2]
      })
    }
  }

  const GetInput = z.object({
    sessionId: Identifier.schema("session"),
    messageId: Identifier.schema("message")
  });

  export const get = async (input: z.output<typeof GetInput>) => {
    return await Storage.read<Message>(["message", input.sessionId, input.messageId]);
  }
  
  export function save(session: Session, messages: Message[]) {
    fs.writeFileSync(
      session.rootPath + "/messages.json",
      JSON.stringify(messages, null, 2)
    );
  }
  
  export function saveSubagentMessages(
    orchestratorSession: Session,
    subagentId: string,
    messages: Message[]
  ) {
    const subagentDir = `${orchestratorSession.rootPath}/subagents/${subagentId}`;
  
    // Create subagents directory if it doesn't exist
    if (!fs.existsSync(`${orchestratorSession.rootPath}/subagents`)) {
      fs.mkdirSync(`${orchestratorSession.rootPath}/subagents`, {
        recursive: true,
      });
    }
  
    // Create subagent-specific directory if it doesn't exist
    if (!fs.existsSync(subagentDir)) {
      fs.mkdirSync(subagentDir, { recursive: true });
    }
  
    // Save messages
    fs.writeFileSync(
      `${subagentDir}/messages.json`,
      JSON.stringify(messages, null, 2)
    );
  }
}
