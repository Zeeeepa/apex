/**
 * Defines tools to enable agent to interace with a browser
 * session - this aids in the exploitation of XSS based attacks
 * or other types of exploits that require browser access.
 */


import { Stagehand } from "@browserbasehq/stagehand";
import type { MetaTestingSessionInfo } from "./types";
import type { Logger } from "../logger";
import { tool } from "@ai-sdk/provider-utils";
import z, { type ZodTypeAny } from "zod";

const initStagehand = async () => {
    const stagehand = new Stagehand({
        env: "BROWSERBASE",
    });

    await stagehand.init();
    const page = stagehand.context.pages()[0];

    return {
        stagehand,
        page
    }
}

function parseZodType(typeString: string): ZodTypeAny {
  const trimmed = typeString.trim();

  const primitives: Record<string, () => ZodTypeAny> = {
    'z.string()': () => z.string(),
    'z.number()': () => z.number(),
    'z.boolean()': () => z.boolean(),
    'z.null()': () => z.null(),
    'z.undefined()': () => z.undefined(),
    'z.any()': () => z.any(),
    'z.unknown()': () => z.unknown(),
  };

  if (primitives[trimmed]) {
    return primitives[trimmed]();
  }

  // Handle z.object({...})
  const objectMatch = trimmed.match(/^z\.object\(\{(.+)\}\)$/s);
  if (objectMatch) {
    const innerContent = objectMatch[1];
    const shape: Record<string, ZodTypeAny> = {};
    const pairs = splitByComma(innerContent);

    for (const pair of pairs) {
      const colonIndex = pair.indexOf(':');
      if (colonIndex === -1) continue;

      const key = pair.slice(0, colonIndex).trim();
      const value = pair.slice(colonIndex + 1).trim();
      shape[key] = parseZodType(value);
    }

    return z.object(shape);
  }

  // Handle z.array(...)
  const arrayMatch = trimmed.match(/^z\.array\((.+)\)$/s);
  if (arrayMatch) {
    return z.array(parseZodType(arrayMatch[1]));
  }

  // Handle .optional()
  const optionalMatch = trimmed.match(/^(.+)\.optional\(\)$/s);
  if (optionalMatch) {
    return parseZodType(optionalMatch[1]).optional();
  }

  // Handle .nullable()
  const nullableMatch = trimmed.match(/^(.+)\.nullable\(\)$/s);
  if (nullableMatch) {
    return parseZodType(nullableMatch[1]).nullable();
  }

  throw new Error(`Unknown Zod type: ${trimmed}`);
}

// Split by comma, but respect nested braces/parentheses
function splitByComma(str: string): string[] {
  const results: string[] = [];
  let current = '';
  let depth = 0;

  for (const char of str) {
    if (char === '(' || char === '{' || char === '[') {
      depth++;
      current += char;
    } else if (char === ')' || char === '}' || char === ']') {
      depth--;
      current += char;
    } else if (char === ',' && depth === 0) {
      results.push(current.trim());
      current = '';
    } else {
      current += char;
    }
  }

  if (current.trim()) {
    results.push(current.trim());
  }

  return results;
}


export async function createStagehandTool(
    session: MetaTestingSessionInfo,
    logger: Logger,
    targetUrl: string
) {
    const { stagehand, page } = await initStagehand();

    const use_browser = tool({
        description: `Execute actions through a browser session.

This tool allows you to take actions through a headless browser session and is useful for testing for XSS vulnerabilities or other vulnerabilities that require browser-use.

The base URL that you are targeting is: ${targetUrl}. Always base your actions on this target URL.

This has three types of actions:
1. goto('url') - navigates to a page
2. act('Click the learn more button') - takes an action on the page (actions are provided with natural language)
3. extract('extract the description', z.string()) - extracts structured data from the page

Only call one action at a time.

Call this tool multiple times to chain actions together. For example: goto('url') -> act('Click the login button') -> extract('Extract the user's profile data', z.object({name: z.string(), email: z.string(), id: z.number()})).
`,
        inputSchema: z.object({
            goto: z.object({
                target: z.string().describe("Target url to navigate to")
            }).optional(),
            act: z.object({
                action: z.string().describe("Action to take on the page")
            }).optional(),
            extract: z.object({
                instruction: z.string().describe("Instruction to tell the browser agent what data to extract"),
                zodType: z.string().describe("A zod type such as z.string() or a zod object with properties such as z.object({id: z.string()})")
            })
        }),

        execute: async ({ goto, act, extract }) => {
            if(goto) {
                try {
                    const resp = await page.goto(goto.target);
                    if(resp) {
                        return await resp.body();
                    }
                    return null;
                } catch(error) {
                    logger.error(String(error));
                    throw error;
                }
            }

            if(act) {
                try {
                    const resp = await stagehand.act(act.action);
                    return resp;
                } catch(error) {
                    logger.error(String(error));
                    throw error;
                }
            }

            if(extract) {
                try {
                    const schema = parseZodType(extract.zodType);
                    const resp = await stagehand.extract(extract.instruction, schema);
                    return resp;
                } catch(error) {
                    logger.error(String(error));
                    throw error;
                }

            }

            throw new Error("Must supply an action within [goto, act, extract]");
        }
    })

    return use_browser;
}