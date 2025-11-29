import { useEffect, useState } from "react";
import { useKeyboard } from "@opentui/react";
import { Session } from "../../../core/session";
import { Dialog } from "../dialog";

interface CreateSessionDialogProps {
  onClose: () => void;
  onSuccess: (sessionId: string) => void;
}

type DialogStep = "name" | "targets";

export default function CreateSessionDialog({ onClose, onSuccess }: CreateSessionDialogProps) {
  const [step, setStep] = useState<DialogStep>("name");
  const [name, setName] = useState("");
  const [currentTarget, setCurrentTarget] = useState("");
  const [targets, setTargets] = useState<string[]>([]);
  const [error, setError] = useState("");

  const [newSessionId, setNewSessionId] = useState("");

  const createSession = async () => {
      try {
          const newSession = await Session.create({ name: name.trim() });
          setNewSessionId(newSession.id);
          setStep("targets");
        } catch (err) {
          setError("Failed to create session");
          console.error(err);
        }
  }

  const updateTargets = async () => {
    try {
      if(targets.length > 0) {
        await Session.update(newSessionId, (session) => {
          session.targets = targets;
        });
        onSuccess(newSessionId);
        return;
      }
      setError("Please provide a target endpoint");
      return;
    } catch (err) {
      setError("Failed to create session");
      console.error(err); 
    }
  }

  useKeyboard(async (key) => {
    // Escape - Close dialog or go back
    if (key.name === "escape") {
      if (step === "targets") {
        setStep("name");
        setError("");
      } else {
        onClose();
      }
      return;
    }

    // Step 1: Name input
    if (step === "name") {
      if (key.name === "return") {
        if (!name.trim()) {
          setError("Session name is required");
          return;
        }
        setError("");
        await createSession();
        return;
      }
    }

    // Step 2: Targets input
    if (step === "targets") {
      // Enter - Add target to list
      if (key.name === "return") {
        if (currentTarget.trim()) {
          setTargets((prev) => [...prev, currentTarget.trim()]);
          setCurrentTarget("");
          setError("");
        }
        return;
      }

      // Ctrl+A - Finalize and create session
      if (key.ctrl && key.name === "a") {
        await updateTargets();
        return;
      }

      // Backspace - Remove last target if input is empty
      if (key.name === "backspace" && currentTarget.length === 0 && targets.length > 0) {
        setTargets((prev) => prev.slice(0, -1));
        return;
      }
    }
  });

  return (
    <Dialog size="medium" onClose={step === "targets" ? () => setStep("name") : onClose}>
      <box
        flexDirection="column"
        padding={2}
        gap={2}
        width="100%"
      >
        {/* Header */}
        <box flexDirection="row" justifyContent="space-between" width="100%">
          <text fg="white">
            {step === "name" ? "Create New Session" : "Add Target Domains"}
          </text>
          <text fg="gray">esc to {step === "targets" ? "go back" : "cancel"}</text>
        </box>

        {step === "name" ? (
          <>
            {/* Step 1: Name Input */}
            <box
              width="100%"
              border={["left"]}
              borderColor="green"
              backgroundColor="transparent"
            >
              <input
                paddingLeft={1}
                backgroundColor="transparent"
                placeholder="Session name"
                value={name}
                onInput={setName}
                focused={step === "name"}
              />
            </box>

            {/* Error Message */}
            {error && <text fg="red">{error}</text>}

            {/* Footer */}
            <box flexDirection="row" gap={2}>
              <text fg="gray">
                <span fg="green">[Enter]</span> Continue
              </text>
            </box>
          </>
        ) : (
          <>
            {/* Step 2: Targets Input */}
            <box
              width="100%"
              border={["left"]}
              borderColor="green"
              backgroundColor="transparent"
            >
              <input
                paddingLeft={1}
                backgroundColor="transparent"
                placeholder="Enter domain"
                value={currentTarget}
                onInput={setCurrentTarget}
                focused={step === "targets"}
              />
            </box>

            {/* Targets List */}
            {targets.length > 0 && (
              <box
                flexDirection="column"
                gap={1}
                maxHeight={5}
                overflow="hidden"
                backgroundColor="transparent"
                padding={1}
              >
                <scrollbox
                  style={{
                    rootOptions: {
                      width: "100%",
                      maxHeight: 5,
                      overflow: "hidden",
                    },
                    wrapperOptions: {
                      overflow: "hidden",
                    },
                    contentOptions: {
                      gap: 1,
                      flexDirection: "column",
                    },
                  }}
                >
                  {targets.map((target, index) => (
                    <box key={index} flexDirection="row" gap={1}>
                      <text fg="green">●</text>
                      <text fg="white">{target}</text>
                    </box>
                  ))}
                </scrollbox>
              </box>
            )}

            {targets.length === 0 && (
              <text fg="gray">No targets added yet. Enter a domain and press Enter.</text>
            )}

            {/* Error Message */}
            {error && <text fg="red">{error}</text>}

            {/* Footer */}
            <box flexDirection="column" columnGap={1}>
              <box flexDirection="row" gap={2}>
                <text fg="gray">
                  <span fg="green">[Enter]</span> Add target ·{" "}
                  <span fg="green">[Ctrl+A]</span> Finalize
                </text>
              </box>
              <text fg="gray">
                <span fg="green">[Backspace]</span> Remove last target
              </text>
            </box>
          </>
        )}
      </box>
    </Dialog>
  );
}
