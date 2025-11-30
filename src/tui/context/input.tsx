import { createContext, useContext, useState, ReactNode } from "react";

interface InputContextType {
  inputValue: string;
  setInputValue: (value: string) => void;
  isInputEmpty: boolean;
}

const InputContext = createContext<InputContextType | undefined>(undefined);

export function InputProvider({ children }: { children: ReactNode }) {
  const [inputValue, setInputValue] = useState("");

  return (
    <InputContext.Provider
      value={{
        inputValue,
        setInputValue,
        isInputEmpty: inputValue.trim().length === 0
      }}
    >
      {children}
    </InputContext.Provider>
  );
}

export function useInput() {
  const context = useContext(InputContext);
  if (!context) {
    throw new Error("useInput must be used within InputProvider");
  }
  return context;
}
