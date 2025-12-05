/**
 * POC Generator Agent
 *
 * Specialized sub-agent for generating proof-of-concept scripts
 * for security vulnerabilities with vulnerability-specific guidance.
 */

import { tool, hasToolCall, stepCountIs } from 'ai';
import { streamResponse, type AIModel } from '../../ai';
import { z } from 'zod';
import {
  BASE_POC_GUIDANCE,
  getPocPromptForVulnerability,
  detectVulnerabilityType,
} from './prompts';
import type { AIAuthConfig } from '../../ai/utils';

export interface PocGeneratorInput {
  /**
   * The security finding to create a POC for
   */
  finding: {
    title: string;
    description: string;
    severity: string;
    evidence: string;
    endpoint?: string;
  };

  /**
   * Additional context from the pentest agent
   */
  context?: {
    target: string;
    sessionCookie?: string;
    authToken?: string;
    testingObjective?: string;
    discoveredParameters?: string[];
    authenticationInstructions?: string;
  };

  /**
   * Override automatic vulnerability type detection
   */
  vulnerabilityType?: string;
}

export interface PocGeneratorResult {
  success: boolean;
  pocName: string;
  pocType: 'bash' | 'html';
  pocContent: string;
  description: string;
  vulnerabilityType: string;
  reasoning?: string;
  error?: string;
}

/**
 * Generate a POC for a security vulnerability using specialized prompts
 */
export async function generatePoc(
  input: PocGeneratorInput,
  model: AIModel,
  authConfig?: AIAuthConfig
): Promise<PocGeneratorResult> {
  const { finding, context, vulnerabilityType: overrideType } = input;

  // Detect or use provided vulnerability type
  const vulnType = overrideType || detectVulnerabilityType(finding);

  // Get specialized prompt for this vulnerability type
  const specializedPrompt = getPocPromptForVulnerability(vulnType);

  // Build the system prompt
  const systemPrompt = `${BASE_POC_GUIDANCE}

---

${specializedPrompt}

---

# Your Task

You are creating a POC for the following security finding:

**Title:** ${finding.title}
**Severity:** ${finding.severity}
**Vulnerability Type:** ${vulnType}

Generate a complete, working POC script that:
1. Demonstrates the vulnerability clearly
2. Implements rate limiting with exponential backoff
3. Tests comprehensively (not just 2-3 attempts for fuzzing vulnerabilities)
4. Shows clear success indicators
5. Includes proper error handling
6. Follows the specialized guidance for ${vulnType}

For IDOR/Authorization vulnerabilities: Test at least 50-100 identifiers with stopping criteria.
For SQL Injection: Test multiple injection techniques (auth bypass, union, error-based, boolean-based).
For XSS: Test multiple payload variations and filter bypasses.
For Command Injection: Test multiple injection methods and demonstrate data exfiltration.

Use the create_poc tool to generate the POC.
`;

  // Build the user prompt with all context
  const userPrompt = `
**FINDING DETAILS:**

Title: ${finding.title}
Severity: ${finding.severity}
Description: ${finding.description}

Evidence:
${finding.evidence}

${finding.endpoint ? `Endpoint: ${finding.endpoint}` : ''}

**CONTEXT:**

${context ? `
Target: ${context.target}
${context.authenticationInstructions ? `

**AUTHENTICATION REQUIRED:**
${context.authenticationInstructions}

**CRITICAL**: You MUST include authentication in the POC script. Parse the authentication instructions above and add the necessary authentication headers, cookies, or credentials to every HTTP request in your POC.
` : ''}
${context.sessionCookie ? `Session Cookie: ${context.sessionCookie}` : ''}
${context.authToken ? `Auth Token: ${context.authToken}` : ''}
${context.testingObjective ? `Testing Objective: ${context.testingObjective}` : ''}
${context.discoveredParameters ? `Known Parameters: ${context.discoveredParameters.join(', ')}` : ''}
` : 'No additional context provided'}

---

Based on the finding details and evidence above, create a comprehensive POC that demonstrates this vulnerability.

**CRITICAL REQUIREMENTS:**
- Implement exponential backoff rate limiting
- For fuzzing/IDOR: Test wide ranges (50-100+ values), not just 2-3
- For injection: Test multiple techniques
- Include stopping criteria (stop after no hits in 3-5 consecutive attempts)
- Show clear success indicators
- Exit code 0 on success, 1 on failure

Call the create_poc tool with your generated POC.
`.trim();

  // Create the tool for POC creation
  let pocResult: PocGeneratorResult | null = null;

  const create_poc = tool({
    name: 'create_poc',
    description: 'Generate the POC script content',
    inputSchema: z.object({
      pocName: z
        .string()
        .describe(
          "Name for the POC file (e.g., 'sqli_login', 'idor_orders', 'xss_search')"
        ),
      pocType: z.enum(['bash', 'html']).describe('Type of POC (bash script or HTML file)'),
      pocContent: z.string().describe('Complete content of the POC script'),
      description: z.string().describe('Brief description of what the POC demonstrates'),
      reasoning: z
        .string()
        .optional()
        .describe('Reasoning for the POC approach and design choices'),
      toolCallDescription: z.string().describe('Description of this tool call').optional(),
    }),
    execute: async (poc) => {
      pocResult = {
        success: true,
        pocName: poc.pocName,
        pocType: poc.pocType,
        pocContent: poc.pocContent,
        description: poc.description,
        vulnerabilityType: vulnType,
        reasoning: poc.reasoning,
      };

      return {
        success: true,
        message: 'POC generated successfully',
      };
    },
  });

  // Run the agent
  const streamResult = streamResponse({
    prompt: userPrompt,
    system: systemPrompt,
    model,
    tools: {
      create_poc,
    },
    authConfig,
    stopWhen: hasToolCall('create_poc') || stepCountIs(100),
    silent: true,
  });

  // Wait for completion
  for await (const delta of streamResult.fullStream) {
  }

  if (!pocResult) {
    return {
      success: false,
      pocName: '',
      pocType: 'bash',
      pocContent: '',
      description: '',
      vulnerabilityType: vulnType,
      error: 'POC generator agent did not produce a POC',
    };
  }

  return pocResult;
}
