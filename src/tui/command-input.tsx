import { useState } from "react";
import Autocomplete from "./components/autocomplete";
import { useCommand } from "./command-provider";
import { AsciiHeader } from "./components/ascii-header";
import { Installation } from "../core/installation";
import { useConfig } from "./context/config";

interface CommandInputProps {
  focused?: boolean;
  inputKey?: number;
}

export default function CommandInput({
  focused = true,
  inputKey = 0,
}: CommandInputProps) {
  const [command, setCommand] = useState("");
  const { autocompleteOptions, executeCommand } = useCommand();

  const config = useConfig();

  const handleSubmit = async (value: string) => {
    const raw = value ?? "";
    await executeCommand(raw);
    setCommand("");
  };

  return (
    <box
      flexDirection="column"
      justifyContent="center"
      alignItems="center"
      width={60}
      // flexGrow={1}
      gap={2}
    >
      <box>
      <AsciiHeader/>
      <text alignSelf={'flex-end'}>{config.data.version}</text>
      </box>
      <Autocomplete
        key={inputKey}
        label="Command"
        value={command}
        placeholder="Enter a command or / for suggestions..."
        focused={focused}
        options={autocompleteOptions}
        onInput={(value) => setCommand(value)}
        onSubmit={handleSubmit}
      />
    </box>
  );
}
