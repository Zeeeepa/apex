import { createContext, useContext, useRef, useCallback, type ReactNode } from "react";
import type { InputRenderable } from "@opentui/core";

interface FocusContextType {
  commandInputRef: React.MutableRefObject<InputRenderable | null>;
  refocusCommandInput: () => void;
}

const FocusContext = createContext<FocusContextType | undefined>(undefined);

export function FocusProvider({ children }: { children: ReactNode }) {
  const commandInputRef = useRef<InputRenderable | null>(null);

  const refocusCommandInput = useCallback(() => {
    setTimeout(() => {
      const input = commandInputRef.current;
      if (!input) return;
      if (input.isDestroyed) return;
      input.focus();
    }, 1);
  }, []);

  return (
    <FocusContext.Provider value={{ commandInputRef, refocusCommandInput }}>
      {children}
    </FocusContext.Provider>
  );
}

export function useFocus() {
  const context = useContext(FocusContext);
  if (!context) {
    throw new Error("useFocus must be used within FocusProvider");
  }
  return context;
}
