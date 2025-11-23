import { useEffect, useMemo, useState } from "react";
import AlertDialog from "../alert-dialog";
import { useCommand } from "../../command-provider";
import { config } from "../../../core/config";
import type { Config } from "../../../core/config/config";
import { useConfig } from "../../context/config";
import { useKeyboard } from "@opentui/react";
import { useRoute } from "../../context/route";

export default function ConfigDialog() {

  const appConfig = useConfig();
  const route = useRoute();

  useKeyboard((key) => {
    if(key.name === "escape") {
      route.navigate({
        type: "base",
        path: "home"
      });
    }
  });
  
  return (
    <ConfigForm appConfig={appConfig.data} />
  );
}

function ConfigForm({ appConfig }: { appConfig: Config | null }) {
  if (!appConfig) {
    return <text>Loading...</text>;
  }
  return (
    <box flexDirection="column">
      <text>
        {appConfig.openAiAPIKey ? "✓" : "✗"} OpenAI:{" "}
        {appConfig.openAiAPIKey ? "Configured" : "Not set"}
      </text>
      <text>
        {appConfig.anthropicAPIKey ? "✓" : "✗"} Anthropic:{" "}
        {appConfig.anthropicAPIKey ? "Configured" : "Not set"}
      </text>
      <text>
        {appConfig.openRouterAPIKey ? "✓" : "✗"} OpenRouter:{" "}
        {appConfig.openRouterAPIKey ? "Configured" : "Not set"}
      </text>
      <text>
        {appConfig.bedrockAPIKey ? "✓" : "✗"} Bedrock:{" "}
        {appConfig.bedrockAPIKey ? "Configured" : "Not set"}
      </text>
    </box>
  );
}
