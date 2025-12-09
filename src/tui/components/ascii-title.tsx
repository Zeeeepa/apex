import React from "react";
import { RGBA } from "@opentui/core";

/**
 * Large pixelated ASCII art text for "APEX" in a retro blocky style
 * Similar to the Mistral Vibe CLI aesthetic
 */

// Each letter is defined as a pixel grid (1 = filled, 0 = empty)
// Using a 7-row tall font for good visibility

const LETTER_A = [
  "  ███  ",
  " █   █ ",
  "█     █",
  "███████",
  "█     █",
  "█     █",
  "█     █",
];

const LETTER_P = [
  "██████ ",
  "█     █",
  "█     █",
  "██████ ",
  "█      ",
  "█      ",
  "█      ",
];

const LETTER_E = [
  "███████",
  "█      ",
  "█      ",
  "█████  ",
  "█      ",
  "█      ",
  "███████",
];

const LETTER_X = [
  "█     █",
  " █   █ ",
  "  █ █  ",
  "   █   ",
  "  █ █  ",
  " █   █ ",
  "█     █",
];

const APEX_LETTERS = [LETTER_A, LETTER_P, LETTER_E, LETTER_X];

// Cream/beige color like in the Mistral image
const TEXT_COLOR = { r: 255, g: 248, b: 220 };

interface AsciiTitleProps {
  color?: { r: number; g: number; b: number };
}

export function AsciiTitle({ color = TEXT_COLOR }: AsciiTitleProps) {
  const rgbaColor = RGBA.fromInts(color.r, color.g, color.b, 255);

  // Combine all letters into rows with spacing
  const rows: string[] = [];
  for (let row = 0; row < 7; row++) {
    let line = "";
    for (let letterIdx = 0; letterIdx < APEX_LETTERS.length; letterIdx++) {
      const letter = APEX_LETTERS[letterIdx];
      line += letter[row];
      if (letterIdx < APEX_LETTERS.length - 1) {
        line += "  "; // Space between letters
      }
    }
    rows.push(line);
  }

  return (
    <box flexDirection="column">
      {rows.map((row, idx) => (
        <text key={idx} fg={rgbaColor}>
          {row}
        </text>
      ))}
    </box>
  );
}

/**
 * Subtitle component for "Apex CLI"
 */
export function AsciiSubtitle() {
  const color = RGBA.fromInts(255, 248, 220, 255);

  // Smaller blocky text for "Apex CLI"
  const lines = [
    "█▀█ █▀█ █▀▀ ▀▄▀   █▀▀ █   █",
    "█▀█ █▀▀ ██▄ █ █   █▄▄ █▄▄ █",
  ];

  return (
    <box flexDirection="column">
      {lines.map((line, idx) => (
        <text key={idx} fg={color}>
          {line}
        </text>
      ))}
    </box>
  );
}
