/**
 * Base POC generation guidance shared across all vulnerability types
 */

export const BASE_POC_GUIDANCE = `
# Universal POC Requirements

## Session Outcome Guidance

{{OUTCOME_GUIDANCE}}

Your POC must work toward achieving the session objective. Keep this goal in mind throughout.

## Core Principles

Every POC you generate must follow these principles:

1. **ALWAYS use bash POCs** - HTML POCs are NOT executed or validated. Only bash POCs prove a vulnerability works.
2. **POC is a codification of your exploit process** - Document exactly what you did to exploit the vulnerability, not a generic template
3. **Authenticate first** - If the endpoint requires authentication, handle it at the start of your POC
4. **Work toward the objective** - Keep the session goal in mind and demonstrate progress toward it
5. **Show actual impact** - Demonstrate real data access, not just HTTP 200 status codes

## CRITICAL: Bash vs HTML POCs

**Always use bash POCs unless absolutely impossible.**

Bash POCs are:
- Automatically executed and tested
- Validated to work before being saved
- Deleted if they fail (allowing iteration)
- The only way to prove a vulnerability actually works

HTML POCs are:
- NOT executed or validated
- Only saved to disk without testing
- Should ONLY be used for DOM-based XSS that requires JavaScript execution in a browser and cannot be verified server-side (extremely rare)

**When to use bash:** IDOR, SQLi, command injection, XSS (reflected/stored), SSRF, XXE, SSTI, path traversal, authentication bypass, rate limiting, information disclosure, CSRF (demonstrate the request works without a token)

## Universal POC Structure

All POCs should follow this structure:

\`\`\`bash
#!/bin/bash
# POC: [Vulnerability Title]
# Severity: [CRITICAL/HIGH/MEDIUM/LOW]
# Description: [What the vulnerability allows]
# Objective: [Session outcome - what we're trying to achieve]

TARGET="[TARGET_URL]"

# ============================================
# STEP 1: AUTHENTICATION (if required)
# ============================================
# Handle authentication FIRST before any exploitation

SESSION="[SESSION_COOKIE]"
AUTH_HEADER="Cookie: \${SESSION}"

# Alternative authentication methods:
# TOKEN="[ACCESS_TOKEN]"
# AUTH_HEADER="Authorization: Bearer \${TOKEN}"

# ============================================
# STEP 2: EXPLOITATION
# ============================================
# Document exactly what you did to exploit the vulnerability

echo "[*] POC: [Vulnerability Title]"
echo "[*] Target: \${TARGET}"
echo ""

# Your exploitation code here...
# Include the SPECIFIC payloads and techniques that worked

# ============================================
# STEP 3: DEMONSTRATE OBJECTIVE ACHIEVED
# ============================================
# Show that the session goal was accomplished

echo ""
echo "[*] Objective result: [what was achieved - flag, data, access, etc.]"
\`\`\`

## Rate Limiting (When Needed)

For POCs that make multiple requests, implement rate limiting:

\`\`\`bash
REQUEST_COUNT=0
BATCH_SIZE=10
DELAY=0.1

make_request() {
  REQUEST_COUNT=\$((REQUEST_COUNT + 1))
  if [ \$((REQUEST_COUNT % BATCH_SIZE)) -eq 0 ]; then
    sleep \$DELAY
    DELAY=\$(echo "\$DELAY * 2" | bc)
    [ \$(echo "\$DELAY > 5" | bc -l) -eq 1 ] && DELAY=5
  fi
  curl -s "\$@"
}
\`\`\`

## POC Principles Summary

1. **Document your actual steps** - The POC reflects what you actually did
2. **Authenticate first** - Always handle auth before exploitation
3. **Show working techniques** - Include the specific payloads that succeeded
4. **Demonstrate impact** - Show actual data access or achieved outcomes
5. **Achieve the objective** - Work toward the session goal

## Success Criteria

Every POC must demonstrate:

1. **Authentication handled** - Session established if needed
2. **Exploitation confirmed** - Clear evidence the vulnerability exists
3. **Impact shown** - Actual data, access, or outcome achieved
4. **Working payload** - The exact technique that works
5. **Objective progress** - Movement toward session goal

## Remember

- **POC = codification of your exploit** - document what you actually did
- **Authenticate first** - always handle auth at the start
- **Content matters more than status codes** - verify actual data access
- **Work toward objective** - keep the session goal in mind (per OUTCOME_GUIDANCE)
`;
