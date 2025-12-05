/**
 * Exports all POC generation prompts
 */

import { COMMAND_INJECTION_POC_PROMPT } from './command-injection';
import { GENERIC_POC_PROMPT } from './generic';
import { IDOR_POC_PROMPT } from './idor';
import { SQLI_POC_PROMPT } from './sqli';
import { XSS_POC_PROMPT } from './xss';

export { BASE_POC_GUIDANCE } from './base';
export { IDOR_POC_PROMPT } from './idor';
export { SQLI_POC_PROMPT } from './sqli';
export { XSS_POC_PROMPT } from './xss';
export { COMMAND_INJECTION_POC_PROMPT } from './command-injection';
export { GENERIC_POC_PROMPT } from './generic';

/**
 * Vulnerability type mappings for prompt selection
 */
export type VulnerabilityType =
  | 'sql_injection'
  | 'nosql_injection'
  | 'idor'
  | 'authorization'
  | 'xss'
  | 'xss_reflected'
  | 'xss_stored'
  | 'xss_dom'
  | 'command_injection'
  | 'ssrf'
  | 'xxe'
  | 'ssti'
  | 'csrf'
  | 'path_traversal'
  | 'lfi'
  | 'rfi'
  | 'file_upload'
  | 'deserialization'
  | 'business_logic'
  | 'generic';

/**
 * Get the appropriate POC generation prompt based on vulnerability type
 */
export function getPocPromptForVulnerability(
  vulnerabilityType: string
): string {
  const normalizedType = vulnerabilityType.toLowerCase().replace(/[^a-z_]/g, '_');

  // SQL Injection variants
  if (normalizedType.includes('sql') || normalizedType.includes('sqli')) {
    return SQLI_POC_PROMPT;
  }

  // NoSQL Injection
  if (normalizedType.includes('nosql') || normalizedType.includes('mongodb')) {
    return SQLI_POC_PROMPT; // NoSQL shares similar structure
  }

  // IDOR and Authorization
  if (
    normalizedType.includes('idor') ||
    normalizedType.includes('authorization') ||
    normalizedType.includes('access_control') ||
    normalizedType.includes('broken_access')
  ) {
    return IDOR_POC_PROMPT;
  }

  // XSS variants
  if (normalizedType.includes('xss') || normalizedType.includes('cross_site_scripting')) {
    return XSS_POC_PROMPT;
  }

  // Command Injection
  if (
    normalizedType.includes('command') ||
    normalizedType.includes('rce') ||
    normalizedType.includes('code_injection') ||
    normalizedType.includes('os_command')
  ) {
    return COMMAND_INJECTION_POC_PROMPT;
  }

  // Default to generic prompt
  return GENERIC_POC_PROMPT;
}

/**
 * Detect vulnerability type from finding details
 */
export function detectVulnerabilityType(finding: {
  title: string;
  description: string;
  evidence?: string;
}): VulnerabilityType {
  const text = `${finding.title} ${finding.description} ${finding.evidence || ''}`.toLowerCase();

  // SQL Injection
  if (text.match(/sql\s*injection|sqli|union\s+select|' or '1'='1/i)) {
    return 'sql_injection';
  }

  // NoSQL Injection
  if (text.match(/nosql|mongodb|{"\$gt"|{"\$ne"|mongoose/i)) {
    return 'nosql_injection';
  }

  // IDOR
  if (
    text.match(
      /idor|insecure direct object|unauthorized access|access control|broken access|privilege escalation/i
    )
  ) {
    return 'idor';
  }

  // XSS
  if (text.match(/xss|cross[- ]site scripting|<script|reflected|stored|dom-based/i)) {
    if (text.includes('stored')) return 'xss_stored';
    if (text.includes('dom')) return 'xss_dom';
    return 'xss_reflected';
  }

  // Command Injection
  if (text.match(/command injection|rce|remote code|os command|shell injection/i)) {
    return 'command_injection';
  }

  // SSRF
  if (text.match(/ssrf|server[- ]side request forgery|internal network/i)) {
    return 'generic'; // SSRF is in generic prompt
  }

  // XXE
  if (text.match(/xxe|xml external entity|xml injection/i)) {
    return 'generic'; // XXE is in generic prompt
  }

  // SSTI
  if (text.match(/ssti|template injection|jinja|twig|freemarker/i)) {
    return 'generic'; // SSTI is in generic prompt
  }

  // CSRF
  if (text.match(/csrf|cross[- ]site request forgery/i)) {
    return 'csrf';
  }

  // Path Traversal / LFI
  if (text.match(/path traversal|directory traversal|lfi|local file|\.\.\/|file inclusion/i)) {
    return 'path_traversal';
  }

  // Default
  return 'generic';
}
