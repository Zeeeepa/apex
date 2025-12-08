import { useState } from "react";
import { useKeyboard } from "@opentui/react";
import Input from "../input";
import { useRoute } from "../../context/route";
import { useAgent } from "../../agentProvider";
import AgentDisplay from "../agent-display";
import { createSession, type SessionConfig } from "../../../core/agent/sessions";
import { runStreamlinedPentest, type StreamlinedPentestProgress } from "../../../core/agent/thoroughPentestAgent/streamlined";
import type { SubAgentSpawnInfo, SubAgentStreamEvent } from "../../../core/agent/pentestAgent/orchestrator";
import type { MetaVulnerabilityTestResult } from "../../../core/agent/metaTestingAgent";
import type { Message, ToolMessage } from "../../../core/messages/types";
import { existsSync } from "fs";
import { exec } from "child_process";

// Wizard step types
type WizardStep =
  | "select-type"
  | "target"
  | "auth"
  | "objective"
  | "scope"
  | "headers"
  | "confirm"
  | "running";

type PentestType = "quick" | "full";

// Wizard state interface
interface WizardState {
  pentestType: PentestType;
  target: string;
  auth: {
    loginUrl: string;
    username: string;
    password: string;
    instructions: string;
  };
  objectiveGuidance: string;
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

// Get steps for each pentest type
function getStepsForType(type: PentestType): WizardStep[] {
  if (type === "quick") {
    return ["select-type", "target", "auth", "scope", "confirm", "running"];
  }
  return ["select-type", "target", "auth", "objective", "scope", "headers", "confirm", "running"];
}

function getStepTitle(step: WizardStep): string {
  const titles: Record<WizardStep, string> = {
    "select-type": "Select Pentest Type",
    "target": "Enter Target",
    "auth": "Authentication",
    "objective": "Objective Guidance",
    "scope": "Scope Constraints",
    "headers": "Request Headers",
    "confirm": "Confirm Configuration",
    "running": "Running Pentest",
  };
  return titles[step];
}

export default function InitWizard() {
  const route = useRoute();
  const { model, addTokens, setTokenCount, setThinking, isExecuting, setIsExecuting } = useAgent();

  // Wizard state
  const [currentStep, setCurrentStep] = useState<WizardStep>("select-type");
  const [state, setState] = useState<WizardState>({
    pentestType: "quick",
    target: "",
    auth: {
      loginUrl: "",
      username: "",
      password: "",
      instructions: "",
    },
    objectiveGuidance: "",
    scope: {
      allowedHosts: [],
      allowedPorts: [],
      strictScope: false,
    },
    headers: {
      mode: "default",
      customHeaders: {},
    },
  });

  // UI state
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

  const steps = getStepsForType(state.pentestType);
  const currentStepIndex = steps.indexOf(currentStep);
  const totalSteps = steps.length - 1; // Exclude "running" from count

  // Navigation helpers
  const canGoBack = currentStepIndex > 0 && currentStep !== "running";
  const canSkip = ["auth", "objective", "scope", "headers"].includes(currentStep);

  function goToNextStep() {
    const nextIndex = currentStepIndex + 1;
    if (nextIndex < steps.length) {
      setCurrentStep(steps[nextIndex]!);
      setFocusedField(0);
    }
  }

  function goToPrevStep() {
    if (canGoBack) {
      setCurrentStep(steps[currentStepIndex - 1]!);
      setFocusedField(0);
    }
  }

  function skipStep() {
    if (canSkip) {
      goToNextStep();
    }
  }

  // Start the pentest
  async function startPentest() {
    setCurrentStep("running");
    setIsExecuting(true);
    setThinking(true);

    const controller = new AbortController();
    setAbortController(controller);

    let currentDiscoveryText = "";

    try {
      // Build session config
      const sessionConfig: SessionConfig = {};

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

      // Objective guidance
      if (state.objectiveGuidance) {
        sessionConfig.outcomeGuidance = state.objectiveGuidance;
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

      // Create session
      const session = createSession(
        state.target,
        `Pentest session for ${state.target}`,
        "pentest",
        sessionConfig
      );

      setSessionPath(session.rootPath);

      // Add initial user message
      const userMessage: Message = {
        role: "user",
        content: `Target: ${state.target}\n\nMode: ${state.pentestType === "quick" ? "Quick" : "Full"} Pentest`,
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
      if (canGoBack) {
        goToPrevStep();
      } else {
        route.navigate({ type: "base", path: "home" });
      }
      return;
    }

    // Open report when completed
    if (isCompleted && key.name === "return") {
      openReport();
      return;
    }

    // Don't allow navigation during running
    if (currentStep === "running") return;

    // TAB - Next field
    if (key.name === "tab" && !key.shift) {
      handleTabNext();
      return;
    }

    // Shift+TAB - Previous field
    if (key.name === "tab" && key.shift) {
      handleTabPrev();
      return;
    }

    // Arrow keys for select-type step
    if (currentStep === "select-type" && (key.name === "up" || key.name === "down")) {
      setState((prev) => ({
        ...prev,
        pentestType: prev.pentestType === "quick" ? "full" : "quick",
      }));
      return;
    }

    // Arrow keys for scope strictScope toggle
    if (currentStep === "scope" && focusedField === 2 && (key.name === "up" || key.name === "down")) {
      setState((prev) => ({
        ...prev,
        scope: { ...prev.scope, strictScope: !prev.scope.strictScope },
      }));
      return;
    }

    // Arrow keys for headers mode
    if (currentStep === "headers" && focusedField === 0 && (key.name === "up" || key.name === "down")) {
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

    // S or Right Arrow - Skip (on optional steps)
    if ((key.name === "s" || key.name === "right") && canSkip && !isInputFocused()) {
      skipStep();
      return;
    }

    // ENTER - Proceed
    if (key.name === "return") {
      handleEnter();
      return;
    }
  });

  function isInputFocused(): boolean {
    // Check if we're focused on a text input field
    if (currentStep === "target") return true;
    if (currentStep === "auth") return focusedField < 4;
    if (currentStep === "objective") return true;
    if (currentStep === "scope") return focusedField < 2;
    if (currentStep === "headers" && state.headers.mode === "custom") return focusedField > 0;
    return false;
  }

  function handleTabNext() {
    const maxFields = getMaxFieldsForStep();
    setFocusedField((prev) => (prev + 1) % maxFields);
  }

  function handleTabPrev() {
    const maxFields = getMaxFieldsForStep();
    setFocusedField((prev) => (prev - 1 + maxFields) % maxFields);
  }

  function getMaxFieldsForStep(): number {
    switch (currentStep) {
      case "select-type": return 1;
      case "target": return 1;
      case "auth": return 4;
      case "objective": return 1;
      case "scope": return 3;
      case "headers": return state.headers.mode === "custom" ? 3 : 1;
      case "confirm": return 1;
      default: return 1;
    }
  }

  function handleEnter() {
    // Handle specific step logic
    if (currentStep === "select-type") {
      goToNextStep();
      return;
    }

    if (currentStep === "target") {
      if (state.target.trim()) {
        goToNextStep();
      }
      return;
    }

    if (currentStep === "scope" && focusedField === 0 && hostInput.trim()) {
      // Add host
      setState((prev) => ({
        ...prev,
        scope: { ...prev.scope, allowedHosts: [...prev.scope.allowedHosts, hostInput.trim()] },
      }));
      setHostInput("");
      return;
    }

    if (currentStep === "scope" && focusedField === 1 && portInput.trim()) {
      // Add port
      setState((prev) => ({
        ...prev,
        scope: { ...prev.scope, allowedPorts: [...prev.scope.allowedPorts, portInput.trim()] },
      }));
      setPortInput("");
      return;
    }

    if (currentStep === "headers" && state.headers.mode === "custom" && focusedField === 2 && headerNameInput.trim()) {
      // Add header
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

    if (currentStep === "confirm") {
      startPentest();
      return;
    }

    // Default: go to next step
    goToNextStep();
  }

  // Render
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
      {currentStep === "running" ? (
        <AgentDisplay messages={messages} isStreaming={isExecuting} subagents={subagents}>
          {isCompleted && (
            <box border borderColor="green" flexDirection="column" padding={1} gap={1} alignItems="center">
              <text fg="green">✓ Pentest Completed</text>
              <text fg="white">Report generated successfully</text>
              <box flexDirection="row" gap={1}>
                <text fg="gray">Press</text>
                <text fg="green">[ENTER]</text>
                <text fg="gray">to view report or</text>
                <text fg="green">[ESC]</text>
                <text fg="gray">to close</text>
              </box>
              <text fg="gray">{sessionPath}/comprehensive-pentest-report.md</text>
            </box>
          )}
        </AgentDisplay>
      ) : (
        <box
          border
          borderColor="green"
          width={70}
          flexDirection="column"
          padding={1}
          gap={1}
        >
          {/* Header */}
          <box flexDirection="row" justifyContent="space-between">
            <text fg="green">Step {currentStepIndex + 1} of {totalSteps}: {getStepTitle(currentStep)}</text>
            <text fg="gray">{state.pentestType === "quick" ? "Quick" : "Full"} Mode</text>
          </box>
          <text fg="gray">{'─'.repeat(66)}</text>

          {/* Step Content */}
          {renderStepContent()}

          {/* Footer */}
          <text fg="gray">{'─'.repeat(66)}</text>
          <box flexDirection="row" gap={2}>
            {canGoBack && <text fg="gray"><span fg="green">[ESC]</span> Back</text>}
            {canSkip && <text fg="gray"><span fg="green">[S]</span> Skip</text>}
            <text fg="gray"><span fg="green">[ENTER]</span> {currentStep === "confirm" ? "Start" : "Next"}</text>
          </box>
        </box>
      )}
    </box>
  );

  function renderStepContent() {
    switch (currentStep) {
      case "select-type":
        return (
          <box flexDirection="column" gap={1}>
            <text fg="white">Choose the type of penetration test:</text>
            <box flexDirection="column">
              <text fg={state.pentestType === "quick" ? "green" : "gray"}>
                {state.pentestType === "quick" ? "●" : "○"} Quick Pentest
                <span fg="gray"> - Faster scan with essential configuration</span>
              </text>
              <text fg={state.pentestType === "full" ? "green" : "gray"}>
                {state.pentestType === "full" ? "●" : "○"} Full Pentest
                <span fg="gray"> - Comprehensive scan with all options</span>
              </text>
            </box>
            <text fg="gray">Use ↑/↓ to select</text>
          </box>
        );

      case "target":
        return (
          <box flexDirection="column" gap={1}>
            <Input
              label="Target URL or Domain"
              description="e.g., https://example.com or example.com"
              placeholder="https://example.com"
              value={state.target}
              onInput={(v) => setState((prev) => ({ ...prev, target: v }))}
              focused={true}
            />
          </box>
        );

      case "auth":
        return (
          <box flexDirection="column" gap={1}>
            <text fg="white">Configure authentication (optional):</text>
            <Input
              label="Login URL"
              description="URL of the login endpoint"
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
              label="Additional Instructions"
              description="Free-form authentication instructions for the agent"
              placeholder="Use OAuth flow, then extract bearer token..."
              value={state.auth.instructions}
              onInput={(v) => setState((prev) => ({ ...prev, auth: { ...prev.auth, instructions: v } }))}
              focused={focusedField === 3}
            />
          </box>
        );

      case "objective":
        return (
          <box flexDirection="column" gap={1}>
            <text fg="white">Custom objective guidance (optional):</text>
            <Input
              label="Objective Guidance"
              description="Custom instructions for what the pentest should focus on"
              placeholder="Focus on authentication bypass and data exfiltration..."
              value={state.objectiveGuidance}
              onInput={(v) => setState((prev) => ({ ...prev, objectiveGuidance: v }))}
              focused={true}
            />
            <text fg="gray">Leave empty to use default guidance</text>
          </box>
        );

      case "scope":
        return (
          <box flexDirection="column" gap={1}>
            <text fg="white">Configure scope constraints (optional):</text>
            <Input
              label="Add Allowed Host"
              description="Press ENTER to add"
              placeholder="example.com"
              value={hostInput}
              onInput={setHostInput}
              focused={focusedField === 0}
            />
            {state.scope.allowedHosts.length > 0 && (
              <box flexDirection="column" paddingLeft={2}>
                <text fg="gray">Allowed hosts:</text>
                {state.scope.allowedHosts.map((h, i) => (
                  <text key={i} fg="white">• {h}</text>
                ))}
              </box>
            )}
            <Input
              label="Add Allowed Port"
              description="Press ENTER to add"
              placeholder="443"
              value={portInput}
              onInput={setPortInput}
              focused={focusedField === 1}
            />
            {state.scope.allowedPorts.length > 0 && (
              <box flexDirection="column" paddingLeft={2}>
                <text fg="gray">Allowed ports:</text>
                {state.scope.allowedPorts.map((p, i) => (
                  <text key={i} fg="white">• {p}</text>
                ))}
              </box>
            )}
            <box flexDirection="row" gap={1}>
              <text fg={focusedField === 2 ? "green" : "gray"}>Strict Scope:</text>
              <text fg={state.scope.strictScope ? "green" : "gray"}>
                {state.scope.strictScope ? "● Enabled" : "○ Disabled"}
              </text>
              {focusedField === 2 && <text fg="gray">(↑/↓ to toggle)</text>}
            </box>
          </box>
        );

      case "headers":
        return (
          <box flexDirection="column" gap={1}>
            <text fg="white">Configure request headers:</text>
            <box flexDirection="column">
              <text fg={state.headers.mode === "none" ? "green" : "gray"}>
                {state.headers.mode === "none" ? "●" : "○"} None
                <span fg="gray"> - No custom headers</span>
              </text>
              <text fg={state.headers.mode === "default" ? "green" : "gray"}>
                {state.headers.mode === "default" ? "●" : "○"} Default
                <span fg="gray"> - User-Agent: pensar-apex</span>
              </text>
              <text fg={state.headers.mode === "custom" ? "green" : "gray"}>
                {state.headers.mode === "custom" ? "●" : "○"} Custom
                <span fg="gray"> - Define custom headers</span>
              </text>
            </box>
            {focusedField === 0 && <text fg="gray">Use ↑/↓ to select mode</text>}

            {state.headers.mode === "custom" && (
              <box flexDirection="column" gap={1}>
                <text fg="gray">{'─'.repeat(50)}</text>
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
                <text fg="gray">Press ENTER to add header</text>
                {Object.keys(state.headers.customHeaders).length > 0 && (
                  <box flexDirection="column">
                    <text fg="gray">Custom headers:</text>
                    {Object.entries(state.headers.customHeaders).map(([k, v]) => (
                      <text key={k} fg="white">• {k}: {v}</text>
                    ))}
                  </box>
                )}
              </box>
            )}
          </box>
        );

      case "confirm":
        return (
          <box flexDirection="column" gap={1}>
            <text fg="green">Configuration Summary:</text>
            <text fg="white">• Target: <span fg="green">{state.target}</span></text>
            <text fg="white">• Mode: <span fg="green">{state.pentestType === "quick" ? "Quick" : "Full"}</span></text>

            {(state.auth.username || state.auth.instructions) && (
              <text fg="white">• Auth: <span fg="green">Configured</span></text>
            )}
            {state.objectiveGuidance && (
              <text fg="white">• Objective: <span fg="green">Custom</span></text>
            )}
            {(state.scope.allowedHosts.length > 0 || state.scope.allowedPorts.length > 0) && (
              <text fg="white">• Scope: <span fg="green">{state.scope.allowedHosts.length} hosts, {state.scope.allowedPorts.length} ports{state.scope.strictScope ? " (strict)" : ""}</span></text>
            )}
            {state.headers.mode !== "default" && (
              <text fg="white">• Headers: <span fg="green">{state.headers.mode}</span></text>
            )}

            <text fg="gray">{'─'.repeat(50)}</text>
            <text fg="yellow">Press ENTER to start the penetration test</text>
          </box>
        );

      default:
        return null;
    }
  }
}
