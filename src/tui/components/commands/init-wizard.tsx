import { useState } from "react";
import { useKeyboard } from "@opentui/react";
import { RGBA } from "@opentui/core";
import Input from "../input";
import { useRoute } from "../../context/route";
import { useAgent } from "../../agentProvider";
import AgentDisplay from "../agent-display";
import { Session } from "../../../core/session";
import { runStreamlinedPentest, type StreamlinedPentestProgress } from "../../../core/agent/thoroughPentestAgent/streamlined";
import type { SubAgentSpawnInfo, SubAgentStreamEvent } from "../../../core/agent/pentestAgent/orchestrator";
import type { MetaVulnerabilityTestResult } from "../../../core/agent/metaTestingAgent";
import type { Message, ToolMessage } from "../../../core/messages/types";
import { existsSync } from "fs";
import { exec } from "child_process";

// Simplified wizard step types
type WizardStep = "target" | "configure" | "running";

// Random name generator (GitHub-style)
const adjectives = [
  "swift", "bright", "calm", "bold", "keen", "noble", "quick", "sharp",
  "vivid", "warm", "agile", "brave", "clever", "daring", "eager", "fierce",
  "gentle", "humble", "jolly", "lively", "merry", "nimble", "proud", "quiet",
  "rapid", "serene", "sturdy", "tender", "valiant", "witty", "zealous"
];

const nouns = [
  "falcon", "wolf", "hawk", "bear", "lion", "tiger", "eagle", "raven",
  "phoenix", "dragon", "panther", "cobra", "viper", "shark", "orca",
  "mantis", "spider", "scorpion", "hydra", "griffin", "sphinx", "kraken",
  "cipher", "nexus", "prism", "vector", "matrix", "pulse", "surge", "flux"
];

function generateRandomName(): string {
  const adj = adjectives[Math.floor(Math.random() * adjectives.length)]!;
  const noun = nouns[Math.floor(Math.random() * nouns.length)]!;
  return `${adj}-${noun}`;
}

// Simplified wizard state interface
interface WizardState {
  name: string;
  target: string;
  auth: {
    loginUrl: string;
    username: string;
    password: string;
    instructions: string;
  };
  scope: {
    allowedHosts: string[];
    allowedPorts: string[];
    strictScope: boolean;
  };
  headers: {
    mode: "none" | "default" | "custom";
    customHeaders: Record<string, string>;
  };
}

// Subagent type for tracking
type Subagent = {
  id: string;
  name: string;
  type: "attack-surface" | "pentest";
  target: string;
  messages: Message[];
  createdAt: Date;
  status: "pending" | "completed" | "failed";
};

// Home view color palette
const greenBullet = RGBA.fromInts(76, 175, 80, 255);
const creamText = RGBA.fromInts(255, 248, 220, 255);
const dimText = RGBA.fromInts(120, 120, 120, 255);

export default function InitWizard() {
  const route = useRoute();
  const { model, addTokens, setTokenCount, setThinking, isExecuting, setIsExecuting } = useAgent();

  // Wizard state
  const [currentStep, setCurrentStep] = useState<WizardStep>("target");
  const [state, setState] = useState<WizardState>(() => ({
    name: generateRandomName(),
    target: "",
    auth: {
      loginUrl: "",
      username: "",
      password: "",
      instructions: "",
    },
    scope: {
      allowedHosts: [],
      allowedPorts: [],
      strictScope: false,
    },
    headers: {
      mode: "default",
      customHeaders: {},
    },
  }));

  // UI state for target step
  const [targetFocusedField, setTargetFocusedField] = useState(0); // 0=name, 1=target

  // UI state for configure step
  const [focusedSection, setFocusedSection] = useState(0); // 0=auth, 1=scope, 2=headers
  const [focusedField, setFocusedField] = useState(0);
  const [hostInput, setHostInput] = useState("");
  const [portInput, setPortInput] = useState("");
  const [headerNameInput, setHeaderNameInput] = useState("");
  const [headerValueInput, setHeaderValueInput] = useState("");

  // Running state
  const [messages, setMessages] = useState<Message[]>([]);
  const [subagents, setSubagents] = useState<Subagent[]>([]);
  const [sessionPath, setSessionPath] = useState("");
  const [isCompleted, setIsCompleted] = useState(false);
  const [abortController, setAbortController] = useState<AbortController | null>(null);

  // Start the pentest
  async function startPentest() {
    if (!state.target.trim()) return;

    setCurrentStep("running");
    setIsExecuting(true);
    setThinking(true);

    const controller = new AbortController();
    setAbortController(controller);

    let currentDiscoveryText = "";

    try {
      // Build session config
      const sessionConfig: Session.SessionConfig = {};

      // Auth config
      if (state.auth.instructions || state.auth.username) {
        sessionConfig.authenticationInstructions = state.auth.instructions;
        if (state.auth.username) {
          sessionConfig.authCredentials = {
            username: state.auth.username,
            password: state.auth.password,
            loginUrl: state.auth.loginUrl || undefined,
          };
        }
      }

      // Scope constraints
      if (state.scope.allowedHosts.length > 0 || state.scope.allowedPorts.length > 0) {
        sessionConfig.scopeConstraints = {
          allowedHosts: state.scope.allowedHosts,
          allowedPorts: state.scope.allowedPorts.map(p => parseInt(p, 10)).filter(p => !isNaN(p)),
          strictScope: state.scope.strictScope,
        };
      }

      // Headers config
      if (state.headers.mode !== "default") {
        sessionConfig.offensiveHeaders = {
          mode: state.headers.mode,
          headers: state.headers.mode === "custom" ? state.headers.customHeaders : undefined,
        };
      }

      // Create session using new Session API
      const session = await Session.createExecution({
        target: state.target,
        objective: `Pentest: ${state.target}`,
        prefix: state.name || undefined,
        config: sessionConfig,
      });

      setSessionPath(session.rootPath);

      // Add initial user message
      const userMessage: Message = {
        role: "user",
        content: `Target: ${state.target}`,
        createdAt: new Date(),
      };
      setMessages([userMessage]);

      // Add discovery subagent
      setSubagents([{
        id: "attack-surface-discovery",
        name: "Attack Surface Discovery",
        type: "attack-surface",
        target: state.target,
        messages: [],
        status: "pending",
        createdAt: new Date(),
      }]);

      // Run streamlined pentest
      const result = await runStreamlinedPentest({
        target: state.target,
        model: model.id,
        session,
        sessionConfig,
        abortSignal: controller.signal,

        onDiscoveryStepFinish: (step) => {
          const stepTokens = (step.usage?.inputTokens ?? 0) + (step.usage?.outputTokens ?? 0);
          if (stepTokens > 0) setTokenCount(stepTokens);
        },

        onDiscoveryStream: (chunk) => {
          if (chunk.type === "text-delta") {
            currentDiscoveryText += chunk.textDelta;
            addTokens(1);

            setSubagents((prev) => {
              const idx = prev.findIndex((s) => s.id === "attack-surface-discovery");
              if (idx === -1) return prev;

              const updated = [...prev];
              const subagent = updated[idx]!;
              const lastMsg = subagent.messages[subagent.messages.length - 1];

              if (lastMsg && lastMsg.role === "assistant") {
                const newMessages = [...subagent.messages];
                newMessages[newMessages.length - 1] = { ...lastMsg, content: currentDiscoveryText };
                updated[idx] = { ...subagent, messages: newMessages };
              } else {
                updated[idx] = {
                  ...subagent,
                  messages: [...subagent.messages, { role: "assistant", content: currentDiscoveryText, createdAt: new Date() }],
                };
              }
              return updated;
            });
          } else if (chunk.type === "tool-call") {
            setThinking(false);
            currentDiscoveryText = "";

            const toolMessage: Message = {
              role: "tool",
              status: "pending",
              toolCallId: chunk.toolCallId,
              toolName: chunk.toolName,
              content: (chunk as any).input?.toolCallDescription || `Calling ${chunk.toolName}`,
              args: (chunk as any).input,
              createdAt: new Date(),
            };

            setSubagents((prev) => {
              const idx = prev.findIndex((s) => s.id === "attack-surface-discovery");
              if (idx === -1) return prev;
              const updated = [...prev];
              updated[idx] = { ...updated[idx]!, messages: [...updated[idx]!.messages, toolMessage] };
              return updated;
            });
          } else if (chunk.type === "tool-result") {
            setThinking(true);

            setSubagents((prev) => {
              const idx = prev.findIndex((s) => s.id === "attack-surface-discovery");
              if (idx === -1) return prev;
              const updated = [...prev];
              const subagent = updated[idx]!;
              const msgIdx = subagent.messages.findIndex(
                (m) => m.role === "tool" && (m as ToolMessage).toolCallId === chunk.toolCallId
              );
              if (msgIdx === -1) return prev;

              const newMessages = [...subagent.messages];
              const existingMsg = newMessages[msgIdx] as ToolMessage;
              newMessages[msgIdx] = {
                ...existingMsg,
                status: "completed",
                content: `✓ ${existingMsg.toolName || "tool"}`,
              };
              updated[idx] = { ...subagent, messages: newMessages };
              return updated;
            });
          }
        },

        onPentestAgentSpawn: (info: SubAgentSpawnInfo) => {
          setSubagents((prev) => {
            const updated = prev.map((s) =>
              s.id === "attack-surface-discovery" && s.status === "pending"
                ? { ...s, status: "completed" as const }
                : s
            );
            return [...updated, {
              id: info.id,
              name: info.name,
              type: "pentest" as const,
              target: info.target,
              messages: [],
              status: "pending" as const,
              createdAt: new Date(),
            }];
          });
        },

        onPentestAgentStream: (event: SubAgentStreamEvent) => {
          if (event.type === "step-finish" && event.data) {
            const { text, toolCalls, toolResults, usage } = event.data;

            if (usage) {
              const stepTokens = (usage.inputTokens ?? 0) + (usage.outputTokens ?? 0);
              if (stepTokens > 0) addTokens(stepTokens);
            }

            setSubagents((prev) => {
              const idx = prev.findIndex((s) => s.id === event.agentId);
              if (idx === -1) return prev;

              const updated = [...prev];
              const subagent = updated[idx]!;
              const newMessages = [...subagent.messages];

              if (text && text.trim()) {
                const lastMsg = newMessages[newMessages.length - 1];
                if (lastMsg && lastMsg.role === "assistant") {
                  newMessages[newMessages.length - 1] = { ...lastMsg, content: (lastMsg.content || "") + text };
                } else {
                  newMessages.push({ role: "assistant", content: text, createdAt: new Date() });
                }
              }

              if (toolCalls && toolCalls.length > 0) {
                for (const tc of toolCalls) {
                  newMessages.push({
                    role: "tool",
                    status: "pending",
                    toolCallId: tc.toolCallId,
                    toolName: tc.toolName,
                    content: tc.args?.toolCallDescription || `${tc.toolName}`,
                    args: tc.args,
                    createdAt: new Date(),
                  });
                }
              }

              if (toolResults && toolResults.length > 0) {
                for (const tr of toolResults) {
                  const msgIdx = newMessages.findIndex(
                    (m) => m.role === "tool" && (m as ToolMessage).toolCallId === tr.toolCallId
                  );
                  if (msgIdx !== -1) {
                    const existingMsg = newMessages[msgIdx] as ToolMessage;
                    newMessages[msgIdx] = { ...existingMsg, status: "completed", content: `✓ ${existingMsg.toolName || "tool"}` };
                  }
                }
              }

              updated[idx] = { ...subagent, messages: newMessages };
              return updated;
            });
          }
        },

        onPentestAgentComplete: (agentId: string, agentResult: MetaVulnerabilityTestResult) => {
          setSubagents((prev) =>
            prev.map((sub) =>
              sub.id === agentId
                ? {
                    ...sub,
                    status: agentResult.error ? "failed" : "completed",
                    messages: [...sub.messages, {
                      role: "assistant",
                      content: `${agentResult.findingsCount > 0 ? "✅" : "⚪"} ${agentResult.summary}`,
                      createdAt: new Date(),
                    }],
                  }
                : sub
            )
          );
        },

        onProgress: (status: StreamlinedPentestProgress) => {
          const phaseIcons: Record<string, string> = {
            discovery: "🔍",
            testing: "🔬",
            reporting: "📝",
            complete: "✅",
          };

          const icon = phaseIcons[status.phase] || "⏳";
          const progressContent = `${icon} [${status.phase.toUpperCase()}] ${status.message}`;

          setMessages((prev) => {
            const lastMsg = prev[prev.length - 1];
            if (lastMsg && lastMsg.role === "assistant" && lastMsg.content?.includes(`[${status.phase.toUpperCase()}]`)) {
              const updated = [...prev];
              updated[updated.length - 1] = { ...lastMsg, content: progressContent };
              return updated;
            }
            return [...prev, { role: "assistant", content: progressContent, createdAt: new Date() }];
          });
        },
      });

      // Handle completion
      if (result.success) {
        const completionMessage: Message = {
          role: "assistant",
          content: `✅ Penetration test complete!\n\n📊 Results:\n- Targets tested: ${result.targets.length}\n- Total findings: ${result.totalFindings}\n${result.reportPath ? `- Report: ${result.reportPath}` : ""}`,
          createdAt: new Date(),
        };
        setMessages((prev) => [...prev, completionMessage]);

        if ((result.reportPath && existsSync(result.reportPath)) || existsSync(result.session.rootPath + "/comprehensive-pentest-report.md")) {
          setIsCompleted(true);
        }
      } else {
        setMessages((prev) => [...prev, {
          role: "assistant",
          content: `⚠️ Pentest completed with error: ${result.error || "Unknown error"}`,
          createdAt: new Date(),
        }]);
      }

      setThinking(false);
      setIsExecuting(false);
    } catch (error) {
      setThinking(false);
      setIsExecuting(false);

      if (error instanceof Error && error.name === "AbortError") {
        setMessages((prev) => [...prev, { role: "assistant", content: "⚠️ Execution aborted by user", createdAt: new Date() }]);
      } else {
        setMessages((prev) => [...prev, {
          role: "assistant",
          content: `Error: ${error instanceof Error ? error.message : "Unknown error occurred"}`,
          createdAt: new Date(),
        }]);
      }
    }
  }

  function openReport() {
    if (sessionPath) {
      const reportPath = `${sessionPath}/comprehensive-pentest-report.md`;
      if (existsSync(reportPath)) {
        exec(`open "${reportPath}"`);
      } else {
        exec(`open "${sessionPath}"`);
      }
    }
  }

  // Keyboard handling
  useKeyboard((key) => {
    // ESC - Go back or close
    if (key.name === "escape") {
      if (currentStep === "running" && isExecuting && abortController) {
        abortController.abort();
        return;
      }
      if (currentStep === "configure") {
        setCurrentStep("target");
        setFocusedSection(0);
        setFocusedField(0);
        return;
      }
      route.navigate({ type: "base", path: "home" });
      return;
    }

    // Open report when completed
    if (isCompleted && key.name === "return") {
      openReport();
      return;
    }

    // Don't allow navigation during running
    if (currentStep === "running") return;

    // Target step: Enter to start, Tab to navigate/configure
    if (currentStep === "target") {
      // Tab navigation between name and target fields
      if (key.name === "tab") {
        if (key.shift) {
          // Shift+Tab: go to previous field or stay at 0
          setTargetFocusedField((prev) => Math.max(0, prev - 1));
        } else {
          // Tab: go to next field, or if at target field with value, go to configure
          if (targetFocusedField === 1 && state.target.trim()) {
            setCurrentStep("configure");
          } else {
            setTargetFocusedField((prev) => Math.min(1, prev + 1));
          }
        }
        return;
      }
      // Enter to start if target is filled
      if (key.name === "return" && state.target.trim()) {
        startPentest();
        return;
      }
      return;
    }

    // Configure step keyboard handling
    if (currentStep === "configure") {
      // Enter to start pentest
      if (key.name === "return") {
        // Check if we should add an item instead of starting
        if (focusedSection === 1 && focusedField === 0 && hostInput.trim()) {
          setState((prev) => ({
            ...prev,
            scope: { ...prev.scope, allowedHosts: [...prev.scope.allowedHosts, hostInput.trim()] },
          }));
          setHostInput("");
          return;
        }
        if (focusedSection === 1 && focusedField === 1 && portInput.trim()) {
          setState((prev) => ({
            ...prev,
            scope: { ...prev.scope, allowedPorts: [...prev.scope.allowedPorts, portInput.trim()] },
          }));
          setPortInput("");
          return;
        }
        if (focusedSection === 2 && state.headers.mode === "custom" && focusedField === 2 && headerNameInput.trim()) {
          setState((prev) => ({
            ...prev,
            headers: {
              ...prev.headers,
              customHeaders: { ...prev.headers.customHeaders, [headerNameInput.trim()]: headerValueInput },
            },
          }));
          setHeaderNameInput("");
          setHeaderValueInput("");
          return;
        }
        // Otherwise start pentest
        startPentest();
        return;
      }

      // Tab navigation between sections and fields
      if (key.name === "tab") {
        if (key.shift) {
          // Previous field/section
          if (focusedField > 0) {
            setFocusedField(focusedField - 1);
          } else if (focusedSection > 0) {
            setFocusedSection(focusedSection - 1);
            setFocusedField(getMaxFieldsForSection(focusedSection - 1) - 1);
          }
        } else {
          // Next field/section
          const maxFields = getMaxFieldsForSection(focusedSection);
          if (focusedField < maxFields - 1) {
            setFocusedField(focusedField + 1);
          } else if (focusedSection < 2) {
            setFocusedSection(focusedSection + 1);
            setFocusedField(0);
          }
        }
        return;
      }

      // Arrow keys for toggles
      if (key.name === "up" || key.name === "down") {
        // Scope strictScope toggle
        if (focusedSection === 1 && focusedField === 2) {
          setState((prev) => ({
            ...prev,
            scope: { ...prev.scope, strictScope: !prev.scope.strictScope },
          }));
          return;
        }
        // Headers mode toggle
        if (focusedSection === 2 && focusedField === 0) {
          const modes: Array<"none" | "default" | "custom"> = ["none", "default", "custom"];
          const currentIndex = modes.indexOf(state.headers.mode);
          const newIndex = key.name === "up"
            ? (currentIndex - 1 + modes.length) % modes.length
            : (currentIndex + 1) % modes.length;
          setState((prev) => ({
            ...prev,
            headers: { ...prev.headers, mode: modes[newIndex]! },
          }));
          return;
        }
      }
    }
  });

  function getMaxFieldsForSection(section: number): number {
    switch (section) {
      case 0: return 4; // Auth: loginUrl, username, password, instructions
      case 1: return 3; // Scope: host input, port input, strictScope toggle
      case 2: return state.headers.mode === "custom" ? 3 : 1; // Headers: mode, [name, value]
      default: return 1;
    }
  }

  // Render running state
  if (currentStep === "running") {
    return (
      <box
        flexDirection="column"
        width="100%"
        maxHeight="100%"
        alignItems="center"
        justifyContent="center"
        flexGrow={1}
        gap={1}
      >
        <AgentDisplay messages={messages} isStreaming={isExecuting} subagents={subagents}>
          {isCompleted && (
            <box flexDirection="column" gap={1} marginTop={1}>
              <text>
                <span fg={greenBullet}>█ </span>
                <span fg={creamText}>Pentest Completed</span>
              </text>
              <text fg={dimText}>  Report generated successfully</text>
              <box flexDirection="column" marginTop={1}>
                <text>
                  <span fg={greenBullet}>█ </span>
                  <span fg={dimText}>Press </span>
                  <span fg={creamText}>[Enter]</span>
                  <span fg={dimText}> to view report</span>
                </text>
                <text>
                  <span fg={greenBullet}>█ </span>
                  <span fg={dimText}>Press </span>
                  <span fg={creamText}>[ESC]</span>
                  <span fg={dimText}> to close</span>
                </text>
              </box>
              <text fg={dimText}>  {sessionPath}/comprehensive-pentest-report.md</text>
            </box>
          )}
        </AgentDisplay>
      </box>
    );
  }

  // Render target step
  if (currentStep === "target") {
    return (
      <box width="100%" flexDirection="column" gap={2} paddingLeft={4}>
        {/* Title */}
        <text fg={creamText}>Configure Penetration Test</text>

        {/* Name input */}
        <Input
          label="Session Name"
          description="Auto-generated, edit if desired"
          placeholder="swift-falcon"
          value={state.name}
          onInput={(v) => setState((prev) => ({ ...prev, name: v }))}
          focused={targetFocusedField === 0}
        />

        {/* Target input */}
        <Input
          label="Target URL"
          description="e.g., https://example.com"
          placeholder="https://example.com"
          value={state.target}
          onInput={(v) => setState((prev) => ({ ...prev, target: v }))}
          focused={targetFocusedField === 1}
        />

        {/* Action hints */}
        <box flexDirection="column" gap={0} marginTop={1}>
          <text>
            <span fg={greenBullet}>█ </span>
            <span fg={dimText}>Press </span>
            <span fg={creamText}>[Enter]</span>
            <span fg={dimText}> to start immediately</span>
          </text>
          <text>
            <span fg={greenBullet}>█ </span>
            <span fg={dimText}>Press </span>
            <span fg={creamText}>[Tab]</span>
            <span fg={dimText}> to configure options</span>
          </text>
          <text>
            <span fg={greenBullet}>█ </span>
            <span fg={dimText}>Press </span>
            <span fg={creamText}>[ESC]</span>
            <span fg={dimText}> to cancel</span>
          </text>
        </box>
      </box>
    );
  }

  // Render configure step
  return (
    <box width="100%" flexDirection="column" gap={2} paddingLeft={4}>
      {/* Title */}
      <box flexDirection="column">
        <text fg={creamText}>Optional Configuration</text>
        <text fg={dimText}>All fields are optional - configure only what you need</text>
      </box>

      {/* Auth Section */}
      <box flexDirection="column" gap={1}>
        <text>
          <span fg={greenBullet}>█ </span>
          <span fg={focusedSection === 0 ? creamText : dimText}>Authentication</span>
        </text>
        {focusedSection === 0 && (
          <box flexDirection="column" gap={1} paddingLeft={2}>
            <Input
              label="Login URL"
              placeholder="https://example.com/login"
              value={state.auth.loginUrl}
              onInput={(v) => setState((prev) => ({ ...prev, auth: { ...prev.auth, loginUrl: v } }))}
              focused={focusedField === 0}
            />
            <Input
              label="Username"
              placeholder="admin"
              value={state.auth.username}
              onInput={(v) => setState((prev) => ({ ...prev, auth: { ...prev.auth, username: v } }))}
              focused={focusedField === 1}
            />
            <Input
              label="Password"
              placeholder="••••••••"
              value={state.auth.password}
              onInput={(v) => setState((prev) => ({ ...prev, auth: { ...prev.auth, password: v } }))}
              focused={focusedField === 2}
            />
            <Input
              label="Auth Instructions"
              placeholder="Use OAuth flow, extract bearer token..."
              value={state.auth.instructions}
              onInput={(v) => setState((prev) => ({ ...prev, auth: { ...prev.auth, instructions: v } }))}
              focused={focusedField === 3}
            />
          </box>
        )}
      </box>

      {/* Scope Section */}
      <box flexDirection="column" gap={1}>
        <text>
          <span fg={greenBullet}>█ </span>
          <span fg={focusedSection === 1 ? creamText : dimText}>Scope Constraints</span>
        </text>
        {focusedSection === 1 && (
          <box flexDirection="column" gap={1} paddingLeft={2}>
            <Input
              label="Add Allowed Host"
              description="Press Enter to add"
              placeholder="example.com"
              value={hostInput}
              onInput={setHostInput}
              focused={focusedField === 0}
            />
            {state.scope.allowedHosts.length > 0 && (
              <box flexDirection="column" paddingLeft={2}>
                {state.scope.allowedHosts.map((h, i) => (
                  <text key={i} fg={dimText}>• {h}</text>
                ))}
              </box>
            )}
            <Input
              label="Add Allowed Port"
              description="Press Enter to add"
              placeholder="443"
              value={portInput}
              onInput={setPortInput}
              focused={focusedField === 1}
            />
            {state.scope.allowedPorts.length > 0 && (
              <box flexDirection="column" paddingLeft={2}>
                {state.scope.allowedPorts.map((p, i) => (
                  <text key={i} fg={dimText}>• {p}</text>
                ))}
              </box>
            )}
            <box flexDirection="row" gap={1}>
              <text fg={focusedField === 2 ? creamText : dimText}>Strict Scope:</text>
              <text fg={state.scope.strictScope ? greenBullet : dimText}>
                {state.scope.strictScope ? "● Enabled" : "○ Disabled"}
              </text>
              {focusedField === 2 && <text fg={dimText}>(↑/↓ to toggle)</text>}
            </box>
          </box>
        )}
      </box>

      {/* Headers Section */}
      <box flexDirection="column" gap={1}>
        <text>
          <span fg={greenBullet}>█ </span>
          <span fg={focusedSection === 2 ? creamText : dimText}>Request Headers</span>
        </text>
        {focusedSection === 2 && (
          <box flexDirection="column" gap={1} paddingLeft={2}>
            <box flexDirection="column">
              <text fg={state.headers.mode === "none" ? greenBullet : dimText}>
                {state.headers.mode === "none" ? "●" : "○"} None
              </text>
              <text fg={state.headers.mode === "default" ? greenBullet : dimText}>
                {state.headers.mode === "default" ? "●" : "○"} Default (User-Agent: pensar-apex)
              </text>
              <text fg={state.headers.mode === "custom" ? greenBullet : dimText}>
                {state.headers.mode === "custom" ? "●" : "○"} Custom
              </text>
            </box>
            {focusedField === 0 && <text fg={dimText}>Use ↑/↓ to select</text>}

            {state.headers.mode === "custom" && (
              <box flexDirection="column" gap={1}>
                <Input
                  label="Header Name"
                  placeholder="X-Custom-Header"
                  value={headerNameInput}
                  onInput={setHeaderNameInput}
                  focused={focusedField === 1}
                />
                <Input
                  label="Header Value"
                  placeholder="value"
                  value={headerValueInput}
                  onInput={setHeaderValueInput}
                  focused={focusedField === 2}
                />
                {Object.keys(state.headers.customHeaders).length > 0 && (
                  <box flexDirection="column">
                    {Object.entries(state.headers.customHeaders).map(([k, v]) => (
                      <text key={k} fg={dimText}>• {k}: {v}</text>
                    ))}
                  </box>
                )}
              </box>
            )}
          </box>
        )}
      </box>

      {/* Action hints */}
      <box flexDirection="column" gap={0} marginTop={1}>
        <text>
          <span fg={greenBullet}>█ </span>
          <span fg={dimText}>Press </span>
          <span fg={creamText}>[Enter]</span>
          <span fg={dimText}> to start pentest</span>
        </text>
        <text>
          <span fg={greenBullet}>█ </span>
          <span fg={dimText}>Press </span>
          <span fg={creamText}>[Tab]</span>
          <span fg={dimText}> to navigate fields</span>
        </text>
        <text>
          <span fg={greenBullet}>█ </span>
          <span fg={dimText}>Press </span>
          <span fg={creamText}>[ESC]</span>
          <span fg={dimText}> to go back</span>
        </text>
      </box>
    </box>
  );
}
