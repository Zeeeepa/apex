import { useState, useEffect } from "react";
import { useCommand } from "./command-provider";
import { useConfig } from "./context/config";
import { Session } from "../core/session";
import { AgentStatus } from "./components/footer";
import os from "os";

interface CommandInputProps {
  focused?: boolean;
  inputKey?: number;
}

export default function CommandInput({
  focused = true,
  inputKey = 0,
}: CommandInputProps) {
  const [command, setCommand] = useState("");
  const [recentSessions, setRecentSessions] = useState<Session.SessionInfo[]>([]);
  const { executeCommand } = useCommand();
  const config = useConfig();

  // Load recent sessions
  useEffect(() => {
    const loadRecentSessions = async () => {
      const sessions: Session.SessionInfo[] = [];
      for await (const session of Session.list()) {
        sessions.push(session);
        if (sessions.length >= 3) break; // Only show 3 most recent
      }
      // Sort by updated time (most recent first)
      sessions.sort((a, b) => b.time.updated - a.time.updated);
      setRecentSessions(sessions);
    };
    loadRecentSessions();
  }, []);

  const handleSubmit = async (value: string) => {
    const raw = value ?? "";
    if (raw.trim()) {
      await executeCommand(raw);
      setCommand("");
    }
  };

  const cwd = "~" + process.cwd().split(os.homedir()).pop() || "";

  return (
    <box width={"100%"} columnGap={1} flexDirection="row" height={3} border={["top", "bottom"]} borderColor={"green"} alignItems="center">
      <text height={1} fg={"white"}><span>{`>`}</span></text>
      <input
       placeholder="enter a command"
       focused
       width={"100%"}
       height={1}
       backgroundColor={"transparent"}
       value={command}
       onInput={setCommand}
      />
    </box>
  );
}
