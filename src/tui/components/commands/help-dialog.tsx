import { useMemo } from "react";
import { useCommand } from "../../command-provider";
import { RGBA } from "@opentui/core";

export default function HelpDialog() {
  const { commands } = useCommand();

  const message = useMemo(() => {
    // Generate commands list
    const commandsList = commands
      .map((cmd) => {
        const aliases = cmd.aliases?.length
          ? ` (${cmd.aliases.map((a) => `/${a}`).join(", ")})`
          : "";
        return ` - /${cmd.name}${aliases}: ${
          cmd.description || "No description"
        }`;
      })
      .join("\n");

    return `Available Commands:\n${commandsList}`;
  }, [commands]);

  return (
      <box
          position="absolute"
          top={0}
          backgroundColor={RGBA.fromInts(0, 0, 0, 150)}
          left={0}
          zIndex={1000}
          width="100%"
          height="100%"
          justifyContent="center"
          alignItems="center"
        >
          <box
            width={50}
            border={true}
            borderColor="green"
            backgroundColor="black"
            flexDirection="column"
            padding={1}
          >
              <box marginBottom={1}>
                <text fg="green">Help</text>
              </box>
            <box flexDirection="column">
              <text fg="white">{message}</text>
            </box>
          </box>
        </box>
  );
}
