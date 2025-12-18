/**
 * Vulnerability-specific prompt exports and mapping
 */

import { BASE_TESTING_PROMPT, OUTCOME_GUIDANCE_TEMPLATE } from './base';
import { SQLI_TESTING_PROMPT } from './sqli';
import { IDOR_TESTING_PROMPT } from './idor';
import { XSS_TESTING_PROMPT } from './xss';
import { COMMAND_INJECTION_TESTING_PROMPT } from './command-injection';
import { GENERIC_TESTING_PROMPT } from './generic';
import type { VulnerabilityClass } from '../types';

// Re-export individual prompts
export { BASE_TESTING_PROMPT, OUTCOME_GUIDANCE_TEMPLATE } from './base';
export { SQLI_TESTING_PROMPT } from './sqli';
export { IDOR_TESTING_PROMPT } from './idor';
export { XSS_TESTING_PROMPT } from './xss';
export { COMMAND_INJECTION_TESTING_PROMPT } from './command-injection';
export { GENERIC_TESTING_PROMPT } from './generic';

/**
 * Map vulnerability class to specialized testing prompt
 */
const VULNERABILITY_PROMPT_MAP: Record<VulnerabilityClass, string> = {
  'sqli': SQLI_TESTING_PROMPT,
  'idor': IDOR_TESTING_PROMPT,
  'xss': XSS_TESTING_PROMPT,
  'command-injection': COMMAND_INJECTION_TESTING_PROMPT,
  'generic': GENERIC_TESTING_PROMPT,
};

/**
 * Get the testing methodology prompt for a vulnerability class
 */
export function getVulnerabilityPrompt(vulnClass: VulnerabilityClass): string {
  return VULNERABILITY_PROMPT_MAP[vulnClass] || GENERIC_TESTING_PROMPT;
}

/**
 * Build complete system prompt for VulnerabilityTestAgent
 */
export function buildSystemPrompt(
  vulnClass: VulnerabilityClass,
  outcomeGuidance: string
): string {
  const vulnerabilityPrompt = getVulnerabilityPrompt(vulnClass);
  const outcomeSection = OUTCOME_GUIDANCE_TEMPLATE.replace(
    '{{OUTCOME_GUIDANCE}}',
    outcomeGuidance
  );

  return `${BASE_TESTING_PROMPT}

---

${vulnerabilityPrompt}

---

${outcomeSection}
`;
}

/**
 * Get human-readable name for vulnerability class
 */
export function getVulnerabilityClassName(vulnClass: VulnerabilityClass): string {
  const names: Record<VulnerabilityClass, string> = {
    'sqli': 'SQL/NoSQL Injection',
    'idor': 'IDOR/Authorization',
    'xss': 'Cross-Site Scripting (XSS)',
    'command-injection': 'Command Injection',
    'generic': 'Generic Vulnerabilities',
  };
  return names[vulnClass] || vulnClass;
}

/**
 * Infer vulnerability classes from an objective string
 */
export function inferVulnerabilityClasses(objective: string): VulnerabilityClass[] {
  const lower = objective.toLowerCase();
  const classes: VulnerabilityClass[] = [];

  // SQL/NoSQL Injection
  if (
    lower.includes('sql') ||
    lower.includes('injection') ||
    lower.includes('database') ||
    lower.includes('nosql') ||
    lower.includes('mongodb')
  ) {
    classes.push('sqli');
  }

  // IDOR/Authorization
  if (
    lower.includes('auth') ||
    lower.includes('idor') ||
    lower.includes('access') ||
    lower.includes('authorization') ||
    lower.includes('privilege') ||
    lower.includes('escalation')
  ) {
    classes.push('idor');
  }

  // XSS
  if (
    lower.includes('xss') ||
    lower.includes('script') ||
    lower.includes('cross-site') ||
    lower.includes('cross site')
  ) {
    classes.push('xss');
  }

  // Command Injection
  if (
    lower.includes('command') ||
    lower.includes('rce') ||
    lower.includes('shell') ||
    lower.includes('code execution')
  ) {
    classes.push('command-injection');
  }

  // Generic (SSRF, XXE, SSTI, CSRF, Path Traversal)
  if (
    lower.includes('ssrf') ||
    lower.includes('xxe') ||
    lower.includes('ssti') ||
    lower.includes('csrf') ||
    lower.includes('traversal') ||
    lower.includes('template') ||
    lower.includes('request forgery')
  ) {
    classes.push('generic');
  }

  // If no specific classes detected, return all for comprehensive testing
  if (classes.length === 0) {
    return ['sqli', 'idor', 'xss', 'command-injection', 'generic'];
  }

  return classes;
}
