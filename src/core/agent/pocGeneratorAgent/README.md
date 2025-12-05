# POC Generator Agent

A specialized sub-agent system for generating comprehensive, vulnerability-specific proof-of-concept scripts with built-in rate limiting and exponential backoff.

## Architecture

```
pentestAgent
    ↓
documentFindingAgent
    ↓
POC Generator Sub-Agent (this)
    ↓
Specialized Prompts (by vulnerability type)
```

## Features

### 1. Vulnerability-Specific Guidance

The POC generator automatically selects specialized prompts based on vulnerability type:

- **SQL Injection**: Multi-technique testing (auth bypass, union, error-based, boolean-based)
- **IDOR/Authorization**: Wide-range fuzzing (50-100+ identifiers)
- **XSS**: Multiple payload variations with filter bypasses
- **Command Injection**: Multiple injection methods with data exfiltration
- **SSRF, XXE, SSTI, CSRF, Path Traversal**: Comprehensive testing techniques

### 2. Built-In Rate Limiting

All generated POCs include exponential backoff to prevent accidental DoS:

```bash
# Initialize rate limiting
REQUEST_COUNT=0
BATCH_SIZE=10
DELAY=0.1  # Start with 100ms

# Exponential backoff after each batch
if [ $((REQUEST_COUNT % BATCH_SIZE)) -eq 0 ]; then
  sleep $DELAY
  DELAY=$(echo "$DELAY * 2" | bc)  # Double delay
  [ $(echo "$DELAY > 5" | bc -l) -eq 1 ] && DELAY=5  # Cap at 5s
fi
```

### 3. Comprehensive Fuzzing

For IDOR and authorization vulnerabilities:
- Tests 50-100+ identifiers (not just 2-3)
- Stops automatically after no hits in 20+ consecutive attempts
- Tracks success rate and accessible resources
- Provides clear statistics

### 4. Clear Success Indicators

All POCs include:
- Clear output showing what's being tested
- Success/failure indicators
- Statistics and summaries
- Exit code 0 on success, 1 on failure

## Usage

### From documentFindingAgent

The documentFindingAgent automatically calls the POC generator:

```typescript
// Step 1: Generate POC content
const result = await generate_poc_content({
  vulnerabilityType: 'idor', // Optional, auto-detected if not provided
});

// Step 2: Create POC file with generated content
await create_poc({
  pocName: result.pocName,
  pocType: result.pocType,
  pocContent: result.pocContent,
  description: result.description,
});
```

### Direct Usage

```typescript
import { generatePoc } from './pocGeneratorAgent';

const result = await generatePoc(
  {
    finding: {
      title: 'IDOR in Order Endpoint',
      description: 'Users can access other users\' orders',
      severity: 'HIGH',
      evidence: 'curl http://target.com/api/order/1 returns order data',
      endpoint: 'http://target.com/api/order/{id}',
    },
    context: {
      target: 'http://target.com',
      sessionCookie: 'session=abc123',
    },
  },
  model
);
```

## Specialized Prompts

### IDOR/Authorization (`prompts/idor.ts`)

- Wide-range ID fuzzing (1-200)
- Exponential backoff (15 requests per batch)
- Stopping criteria (20+ attempts with no hits)
- Success rate calculation
- Sample data extraction

### SQL Injection (`prompts/sqli.ts`)

- Authentication bypass testing
- Union-based data extraction
- Error-based injection
- Boolean-based blind injection
- Time-based blind injection (used sparingly)

### XSS (`prompts/xss.ts`)

- Reflected XSS: Multiple payloads with encoding
- Stored XSS: Injection and verification workflow
- DOM XSS: HTML POC generation
- Filter bypass techniques

### Command Injection (`prompts/command-injection.ts`)

- Multiple injection methods (semicolon, pipe, AND, OR, backticks)
- Data exfiltration (/etc/passwd, /etc/hosts)
- Out-of-band detection
- Time-based blind injection

### Generic (`prompts/generic.ts`)

- SSRF (internal network and OOB)
- XXE (file disclosure and OOB)
- SSTI (multiple template engines)
- CSRF (HTML form auto-submit)
- Path Traversal (multiple depths and encodings)

## Rate Limiting Guidelines

| Vulnerability Type | Batch Size | Initial Delay | Max Delay | Notes |
|-------------------|------------|---------------|-----------|-------|
| IDOR/Authorization | 15 | 0.1s | 5s | Wide range fuzzing |
| SQL Injection | 5 | 0.5s | 3s | Auth bypass, union, error-based |
| XSS | 10 | 0.3s | 5s | Multiple payloads |
| Command Injection | 10 | 0.5s | 5s | Multiple methods |
| SSRF | 10 | 0.5s | 5s | Internal network scan |
| Time-based Blind | 1 | 3s | 5s | Use very sparingly |

## Example POC Output

### IDOR POC

```
[*] POC: IDOR Testing for /api/order
[*] Target: http://target.com
[*] Testing range: 1-200
[*] Rate limiting: 15 requests per batch, exponential backoff

[+] ACCESSIBLE: /api/order/1 (HTTP 200)
    Sample data: {"id":1,"user":"alice","total":100.00}...
[+] ACCESSIBLE: /api/order/2 (HTTP 200)
[+] ACCESSIBLE: /api/order/5 (HTTP 200)
[*] Batch complete (15 total requests), backing off for 0.1s
...
[*] No hits in 20 attempts, stopping fuzzing

=========================================
[*] POC Results:
=========================================
  Total Tested:     87
  Accessible (200): 12
  Forbidden (403):  5
  Not Found (404):  70
  Success Rate:     13.79%

[!] VULNERABILITY CONFIRMED
[!] User can access 12 unauthorized resources
```

## Benefits

1. **Comprehensive Testing**: POCs test thoroughly, not just 2-3 attempts
2. **DoS Prevention**: Built-in rate limiting prevents accidental service disruption
3. **Vulnerability-Specific**: Each vulnerability type gets specialized testing approach
4. **Automated**: No manual POC writing needed
5. **Consistent Quality**: All POCs follow best practices
6. **Clear Results**: Easy to understand success/failure indicators

## File Structure

```
src/core/agent/pocGeneratorAgent/
├── README.md                    # This file
├── index.ts                     # Exports
├── agent.ts                     # Main POC generator agent
└── prompts/
    ├── index.ts                 # Prompt selection logic
    ├── base.ts                  # Universal rate limiting guidance
    ├── idor.ts                  # IDOR/Authorization fuzzing
    ├── sqli.ts                  # SQL Injection
    ├── xss.ts                   # Cross-Site Scripting
    ├── command-injection.ts     # Command Injection
    └── generic.ts               # SSRF, XXE, SSTI, CSRF, etc.
```

## Integration Points

### documentFindingAgent

- Calls `generate_poc_content` tool
- Uses generated POC with `create_poc` tool
- Iterates up to 3 times if POC fails

### pentestAgent

- Calls `document_finding` which invokes documentFindingAgent
- Receives verified POCs with comprehensive testing

## Future Enhancements

- [ ] GraphQL injection prompt
- [ ] JWT manipulation prompt
- [ ] Deserialization prompt
- [ ] Race condition testing prompt
- [ ] Mass assignment prompt
- [ ] API-specific fuzzing patterns
