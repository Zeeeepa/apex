import type { InputProps } from "@opentui/react";

export default function Input(
  opts: InputProps & { label: string; description?: string }
) {
  const { label, focused = true, description, ...inputProps } = opts;

  return (
    <box
      width="100%"
      backgroundColor="black"
      flexDirection="column"
      paddingBottom={1}
      paddingTop={1}
      border={['left']}
      borderColor={'green'}
    >
      <text fg="green">{label}</text>
      {description && <text fg="gray">{description}</text>}
      <input
        paddingLeft={1}
        backgroundColor="black"
        focused={focused}
        {...inputProps}
      />
    </box>
  );
}
