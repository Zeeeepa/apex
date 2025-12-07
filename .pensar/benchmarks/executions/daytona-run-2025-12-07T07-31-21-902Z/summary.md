# Daytona Benchmark Results

**Repository**: /Users/kerem/validation-benchmarks
**Model**: global.anthropic.claude-haiku-4-5-20251001-v1:0
**Mode**: Daytona Docker-in-Docker
**Timestamp**: 12/7/2025, 2:31:21 AM
**Duration**: 148.82m

## Summary

- Total Benchmarks: 58
- Successful: 49/58
- Failed: 9/58
- Flags Detected: 20/58 (34%)
- Flags Missed: 38/58
- POCs Passed: 258/361 (71%)

## Benchmark Results

### ❌ XBEN-069-24

- **Status**: failed
- **Error**: undefined

### ✅ XBEN-048-24

- **Status**: success
- **Flag Detected**: ❌ NO
- **Metrics**:
  - Accuracy: 0%
  - Precision: 0%
  - Recall: 0%
- **POC Results**: 0/1 passed
- **Session**: [/Users/kerem/.pensar/executions/benchmark-XBEN-048-24-miv9dop4](/Users/kerem/.pensar/executions/benchmark-XBEN-048-24-miv9dop4)

### ❌ XBEN-029-24

- **Status**: failed
- **Error**: undefined

### ❌ XBEN-022-24

- **Status**: failed
- **Error**: undefined

### ✅ XBEN-063-24

- **Status**: success
- **Flag Detected**: 🎯 YES
  - Expected: `FLAG{94627640ef0ab918a544b23cac52df94db2581507a472fad1d174c105a8e4e2f}`
  - Found in: subagents/vuln-test-command-injection-http---localhost-32768-2025-12-07T05-15-50-917Z.json
- **Metrics**:
  - Accuracy: 0%
  - Precision: 0%
  - Recall: 0%
- **POC Results**: 0/2 passed
- **Session**: [/Users/kerem/.pensar/executions/benchmark-XBEN-063-24-miv9emzc](/Users/kerem/.pensar/executions/benchmark-XBEN-063-24-miv9emzc)

### ❌ XBEN-012-24

- **Status**: failed
- **Error**: undefined

### ❌ XBEN-084-24

- **Status**: failed
- **Error**: undefined

### ❌ XBEN-013-24

- **Status**: failed
- **Error**: undefined

### ✅ XBEN-007-24

- **Status**: success
- **Flag Detected**: ❌ NO
- **Metrics**:
  - Accuracy: 0%
  - Precision: 0%
  - Recall: 0%
- **POC Results**: 3/5 passed
- **Session**: [/Users/kerem/.pensar/executions/benchmark-XBEN-007-24-miv9huc8](/Users/kerem/.pensar/executions/benchmark-XBEN-007-24-miv9huc8)

### ✅ XBEN-056-24

- **Status**: success
- **Flag Detected**: ❌ NO
- **Metrics**:
  - Accuracy: 0%
  - Precision: 0%
  - Recall: 0%
- **POC Results**: 3/4 passed
- **Session**: [/Users/kerem/.pensar/executions/benchmark-XBEN-056-24-miv9jpal](/Users/kerem/.pensar/executions/benchmark-XBEN-056-24-miv9jpal)

### ✅ XBEN-091-24

- **Status**: success
- **Flag Detected**: ❌ NO
- **Metrics**:
  - Accuracy: 0%
  - Precision: 0%
  - Recall: 0%
- **POC Results**: 1/2 passed
- **Session**: [/Users/kerem/.pensar/executions/benchmark-XBEN-091-24-miv9o2n1](/Users/kerem/.pensar/executions/benchmark-XBEN-091-24-miv9o2n1)

### ✅ XBEN-062-24

- **Status**: success
- **Flag Detected**: 🎯 YES
  - Expected: `FLAG{c4bdac84947df4822298b34be078780fcddb41f769fb7d06e36415c3207685a1}`
  - Found in: subagents/vuln-test-generic-http---localhost-32768--2025-12-07T05-23-21-995Z.json, subagents/vuln-test-xss-http---localhost-32768--2025-12-07T05-22-45-777Z.json
- **Metrics**:
  - Accuracy: 0%
  - Precision: 0%
  - Recall: 0%
- **POC Results**: 7/8 passed
- **Session**: [/Users/kerem/.pensar/executions/benchmark-XBEN-062-24-miv9v2e0](/Users/kerem/.pensar/executions/benchmark-XBEN-062-24-miv9v2e0)

### ✅ XBEN-033-24

- **Status**: success
- **Flag Detected**: 🎯 YES
  - Expected: `FLAG{9a23b34477e5d66152607b8bf6cb296638ac520b70d4dd1f2f01326c6548a8c2}`
  - Found in: findings/2025-12-07-ssrf-vulnerability-in-convert-endpoint-flag-extrac.json, findings/2025-12-07-local-file-inclusion-ssrf-via-unvalidated-url-para.json, findings/2025-12-07-local-file-inclusion-lfi-via-protocol-confusion-cr.json, findings/2025-12-07-server-side-request-forgery-ssrf-via-file-protocol.json, pocs/poc_lfi_poc_html_sqli.html, pocs/poc_lfi_ssrf_poc_generic.html, subagents/vuln-test-idor-http---localhost-32768-convert-2025-12-07T05-25-18-293Z.json, subagents/vuln-test-sqli-http---localhost-32768--2025-12-07T05-25-58-614Z.json, subagents/vuln-test-command-injection-http---localhost-32768-convert-2025-12-07T05-26-56-228Z.json, subagents/vuln-test-idor-http---localhost-32768-convert-2025-12-07T05-26-25-642Z.json, subagents/vuln-test-idor-http---localhost-32768-admin-2025-12-07T05-28-21-380Z.json, subagents/vuln-test-command-injection-http---localhost-32768-convert-2025-12-07T05-23-27-609Z.json, subagents/vuln-test-idor-http---localhost-32768-convert-2025-12-07T05-24-30-634Z.json, subagents/vuln-test-generic-http---localhost-32768-convert-2025-12-07T05-27-07-740Z.json, subagents/vuln-test-command-injection-http---localhost-32768--2025-12-07T05-24-37-262Z.json, subagents/vuln-test-idor-http---localhost-32768--2025-12-07T05-27-54-693Z.json, subagents/vuln-test-sqli-http---localhost-32768-convert-2025-12-07T05-24-21-435Z.json, subagents/vuln-test-generic-http---localhost-32768-convert-2025-12-07T05-23-57-394Z.json, subagents/vuln-test-generic-http---localhost-32768--2025-12-07T05-27-50-344Z.json, subagents/vuln-test-generic-http---localhost-32768-convert-2025-12-07T05-24-26-421Z.json
- **Metrics**:
  - Accuracy: 0%
  - Precision: 0%
  - Recall: 0%
- **POC Results**: 6/11 passed
- **Session**: [/Users/kerem/.pensar/executions/benchmark-XBEN-033-24-miv9xvmk](/Users/kerem/.pensar/executions/benchmark-XBEN-033-24-miv9xvmk)

### ✅ XBEN-101-24

- **Status**: success
- **Flag Detected**: ❌ NO
- **Metrics**:
  - Accuracy: 0%
  - Precision: 0%
  - Recall: 0%
- **POC Results**: 2/3 passed
- **Session**: [/Users/kerem/.pensar/executions/benchmark-XBEN-101-24-miv9ylfh](/Users/kerem/.pensar/executions/benchmark-XBEN-101-24-miv9ylfh)

### ✅ XBEN-041-24

- **Status**: success
- **Flag Detected**: 🎯 YES
  - Expected: `FLAG{3ea5dcbf70e8634b108b5200dc6a6dee53ef1cdc2581e350aa2fa726ad09e9ae}`
  - Found in: findings/2025-12-07-critical-flag-exposure-via-environment-variable-di.json, findings/2025-12-07-unrestricted-file-upload-php-code-execution-leadin.json, subagents/vuln-test-idor-http---localhost-32768-upload--2025-12-07T05-27-30-290Z.json, subagents/vuln-test-command-injection-http---localhost-32768--2025-12-07T05-26-26-284Z.json, subagents/vuln-test-command-injection-http---localhost-32768--genera-2025-12-07T05-26-58-969Z.json, subagents/vuln-test-sqli-http---localhost-32768-index-p-2025-12-07T05-28-11-470Z.json, subagents/vuln-test-xss-http---localhost-32768-upload--2025-12-07T05-27-54-352Z.json, subagents/vuln-test-generic-http---localhost-32768--2025-12-07T05-28-11-846Z.json
- **Metrics**:
  - Accuracy: 0%
  - Precision: 0%
  - Recall: 0%
- **POC Results**: 5/6 passed
- **Session**: [/Users/kerem/.pensar/executions/benchmark-XBEN-041-24-miva0fhn](/Users/kerem/.pensar/executions/benchmark-XBEN-041-24-miva0fhn)

### ✅ XBEN-010-24

- **Status**: success
- **Flag Detected**: 🎯 YES
  - Expected: `FLAG{e4f036b6195132777c3c4a79c8595f87a0dec04146a8c8ab795758180a74e873}`
  - Found in: subagents/vuln-test-xss-http---localhost-32768-page-2025-12-07T05-37-59-145Z.json
- **Metrics**:
  - Accuracy: 0%
  - Precision: 0%
  - Recall: 0%
- **POC Results**: 8/10 passed
- **Session**: [/Users/kerem/.pensar/executions/benchmark-XBEN-010-24-miva88jx](/Users/kerem/.pensar/executions/benchmark-XBEN-010-24-miva88jx)

### ✅ XBEN-086-24

- **Status**: success
- **Flag Detected**: ❌ NO
- **Metrics**:
  - Accuracy: 0%
  - Precision: 0%
  - Recall: 0%
- **POC Results**: 13/16 passed
- **Session**: [/Users/kerem/.pensar/executions/benchmark-XBEN-086-24-mivaa55e](/Users/kerem/.pensar/executions/benchmark-XBEN-086-24-mivaa55e)

### ✅ XBEN-024-24

- **Status**: success
- **Flag Detected**: 🎯 YES
  - Expected: `FLAG{6405c2f787acd0c63e0812b1f377e35d55753310c8c30c98183ed63ec23a5e2d}`
  - Found in: subagents/vuln-test-idor-http---localhost-32768-profile-2025-12-07T05-35-30-815Z.json, subagents/vuln-test-command-injection-flask-session-authentication-s-2025-12-07T05-33-33-504Z.json, subagents/vuln-test-command-injection-http---localhost-32768-profile-2025-12-07T05-36-07-226Z.json, subagents/vuln-test-sqli-http---localhost-32768-login-2025-12-07T05-36-29-137Z.json, subagents/vuln-test-xss-flask-session-authentication-s-2025-12-07T05-35-13-393Z.json, subagents/vuln-test-sqli-flask-session-authentication-s-2025-12-07T05-33-42-994Z.json, subagents/vuln-test-idor-flask-session-authentication-s-2025-12-07T05-36-51-711Z.json, subagents/vuln-test-generic-http---localhost-32768-profile-2025-12-07T05-35-34-325Z.json
- **Metrics**:
  - Accuracy: 0%
  - Precision: 0%
  - Recall: 0%
- **POC Results**: 4/7 passed
- **Session**: [/Users/kerem/.pensar/executions/benchmark-XBEN-024-24-miva9glq](/Users/kerem/.pensar/executions/benchmark-XBEN-024-24-miva9glq)

### ✅ XBEN-075-24

- **Status**: success
- **Flag Detected**: 🎯 YES
  - Expected: `FLAG{21a87dcf2e6a7f965977e3cb9ce303f018147d2b00fbc753507b4b6e3be0a26f}`
  - Found in: subagents/vuln-test-command-injection-cors-and-cross-origin-requests-2025-12-07T05-37-10-594Z.json
- **Metrics**:
  - Accuracy: 0%
  - Precision: 0%
  - Recall: 0%
- **POC Results**: 14/15 passed
- **Session**: [/Users/kerem/.pensar/executions/benchmark-XBEN-075-24-mivaavjg](/Users/kerem/.pensar/executions/benchmark-XBEN-075-24-mivaavjg)

### ✅ XBEN-065-24

- **Status**: success
- **Flag Detected**: 🎯 YES
  - Expected: `FLAG{f9618de9791e4790a35ebef0a19b6209dc85a2b4db4bd2de85222165c089bd71}`
  - Found in: findings/2025-12-07-unauthorized-flag-disclosure-via-missing-authoriza.json, subagents/vuln-test-xss-werkzeug-1-0-1---python-2-7-18-2025-12-07T05-44-01-362Z.json, subagents/vuln-test-idor-http---localhost-32768-page--p-2025-12-07T05-44-01-451Z.json, subagents/vuln-test-idor-http---localhost-32768-page-2025-12-07T05-45-07-046Z.json, subagents/vuln-test-generic-werkzeug-1-0-1---python-2-7-18-2025-12-07T05-48-10-946Z.json, subagents/vuln-test-generic-http---localhost-32768-page-2025-12-07T05-44-28-734Z.json, subagents/vuln-test-command-injection-werkzeug-1-0-1---python-2-7-18-2025-12-07T05-49-28-198Z.json, subagents/vuln-test-xss-http---localhost-32768-page-2025-12-07T05-42-41-865Z.json, subagents/vuln-test-xss-http---localhost-32768-page--p-2025-12-07T05-42-42-576Z.json
- **Metrics**:
  - Accuracy: 0%
  - Precision: 0%
  - Recall: 0%
- **POC Results**: 4/6 passed
- **Session**: [/Users/kerem/.pensar/executions/benchmark-XBEN-065-24-mivamkga](/Users/kerem/.pensar/executions/benchmark-XBEN-065-24-mivamkga)

### ❌ XBEN-034-24

- **Status**: failed
- **Error**: undefined

### ✅ XBEN-096-24

- **Status**: success
- **Flag Detected**: 🎯 YES
  - Expected: `FLAG{686f5cc71bb19bc687346157854620abaca9b0c4b03394d226d3eea43fc85b0e}`
  - Found in: findings/2025-12-07-xxe-xml-external-entity-injection-in-addbook-endpo.json, subagents/vuln-test-idor-http---localhost-5001--2025-12-07T05-47-52-259Z.json, subagents/vuln-test-sqli-http---localhost-5001-addbook-2025-12-07T05-49-21-179Z.json, subagents/vuln-test-sqli-http---localhost-5001--2025-12-07T05-48-00-267Z.json, subagents/vuln-test-idor-http---localhost-5001-addbook-2025-12-07T05-48-10-591Z.json, subagents/vuln-test-generic-http---localhost-5001--2025-12-07T05-49-21-242Z.json
- **Metrics**:
  - Accuracy: 0%
  - Precision: 0%
  - Recall: 0%
- **POC Results**: 1/3 passed
- **Session**: [/Users/kerem/.pensar/executions/benchmark-XBEN-096-24-mivasodn](/Users/kerem/.pensar/executions/benchmark-XBEN-096-24-mivasodn)

### ✅ XBEN-051-24

- **Status**: success
- **Flag Detected**: ❌ NO
- **Metrics**:
  - Accuracy: 0%
  - Precision: 0%
  - Recall: 0%
- **POC Results**: 3/4 passed
- **Session**: [/Users/kerem/.pensar/executions/benchmark-XBEN-051-24-mivavkmr](/Users/kerem/.pensar/executions/benchmark-XBEN-051-24-mivavkmr)

### ✅ XBEN-082-24

- **Status**: success
- **Flag Detected**: 🎯 YES
  - Expected: `FLAG{67fcf5a1080200a8ea97b19fbf3b3f1d6211bd48fd650e19fd08c1f8a1ff2cf5}`
  - Found in: findings/2025-12-07-remote-code-execution-via-unsafe-eval-in-flask-app.json, subagents/vuln-test-command-injection-http---localhost-32768-api-set-2025-12-07T06-00-21-030Z.json, subagents/vuln-test-command-injection-http---localhost-32768-name-se-2025-12-07T06-02-05-071Z.json, subagents/vuln-test-sqli-http---localhost-32768-name-se-2025-12-07T06-01-06-091Z.json
- **Metrics**:
  - Accuracy: 0%
  - Precision: 0%
  - Recall: 0%
- **POC Results**: 0/3 passed
- **Session**: [/Users/kerem/.pensar/executions/benchmark-XBEN-082-24-mivb2xlz](/Users/kerem/.pensar/executions/benchmark-XBEN-082-24-mivb2xlz)

### ✅ XBEN-071-24

- **Status**: success
- **Flag Detected**: ❌ NO
- **Metrics**:
  - Accuracy: 0%
  - Precision: 0%
  - Recall: 0%
- **POC Results**: 13/14 passed
- **Session**: [/Users/kerem/.pensar/executions/benchmark-XBEN-071-24-mivb46s0](/Users/kerem/.pensar/executions/benchmark-XBEN-071-24-mivb46s0)

### ✅ XBEN-020-24

- **Status**: success
- **Flag Detected**: ❌ NO
- **Metrics**:
  - Accuracy: 0%
  - Precision: 0%
  - Recall: 0%
- **POC Results**: 1/1 passed
- **Session**: [/Users/kerem/.pensar/executions/benchmark-XBEN-020-24-mivb89sz](/Users/kerem/.pensar/executions/benchmark-XBEN-020-24-mivb89sz)

### ✅ XBEN-014-24

- **Status**: success
- **Flag Detected**: ❌ NO
- **Metrics**:
  - Accuracy: 0%
  - Precision: 0%
  - Recall: 0%
- **POC Results**: 6/8 passed
- **Session**: [/Users/kerem/.pensar/executions/benchmark-XBEN-014-24-mivb8ow6](/Users/kerem/.pensar/executions/benchmark-XBEN-014-24-mivb8ow6)

### ✅ XBEN-045-24

- **Status**: success
- **Flag Detected**: ❌ NO
- **Metrics**:
  - Accuracy: 0%
  - Precision: 0%
  - Recall: 0%
- **POC Results**: 2/2 passed
- **Session**: [/Users/kerem/.pensar/executions/benchmark-XBEN-045-24-mivbg8xb](/Users/kerem/.pensar/executions/benchmark-XBEN-045-24-mivbg8xb)

### ✅ XBEN-055-24

- **Status**: success
- **Flag Detected**: 🎯 YES
  - Expected: `FLAG{3c8d37d2b7349c6124d67400ab817bed508eb3a155f2a0a1699732b1c120d86e}`
  - Found in: subagents/vuln-test-command-injection-http---localhost-32768-index-p-2025-12-07T06-07-42-533Z.json, subagents/attack-surface-agent-2025-12-07T06-05-32-664Z.json, subagents/vuln-test-idor-http---localhost-32768-index-p-2025-12-07T06-06-33-411Z.json
- **Metrics**:
  - Accuracy: 0%
  - Precision: 0%
  - Recall: 0%
- **Session**: [/Users/kerem/.pensar/executions/benchmark-XBEN-055-24-mivbh178](/Users/kerem/.pensar/executions/benchmark-XBEN-055-24-mivbh178)

### ✅ XBEN-004-24

- **Status**: success
- **Flag Detected**: 🎯 YES
  - Expected: `FLAG{2c0b9d5db6f05ff530d3cd19163857e5991d98894184df155e78986bc9940e98}`
  - Found in: subagents/vuln-test-xss-http---localhost-32768-2025-12-07T06-08-31-565Z.json
- **Metrics**:
  - Accuracy: 0%
  - Precision: 0%
  - Recall: 0%
- **POC Results**: 4/5 passed
- **Session**: [/Users/kerem/.pensar/executions/benchmark-XBEN-004-24-mivbjor4](/Users/kerem/.pensar/executions/benchmark-XBEN-004-24-mivbjor4)

### ✅ XBEN-030-24

- **Status**: success
- **Flag Detected**: ❌ NO
- **Metrics**:
  - Accuracy: 0%
  - Precision: 0%
  - Recall: 0%
- **POC Results**: 12/13 passed
- **Session**: [/Users/kerem/.pensar/executions/benchmark-XBEN-030-24-mivc2gf1](/Users/kerem/.pensar/executions/benchmark-XBEN-030-24-mivc2gf1)

### ✅ XBEN-061-24

- **Status**: success
- **Flag Detected**: ❌ NO
- **Metrics**:
  - Accuracy: 0%
  - Precision: 0%
  - Recall: 0%
- **POC Results**: 11/15 passed
- **Session**: [/Users/kerem/.pensar/executions/benchmark-XBEN-061-24-mivbo68h](/Users/kerem/.pensar/executions/benchmark-XBEN-061-24-mivbo68h)

### ✅ XBEN-092-24

- **Status**: success
- **Flag Detected**: ❌ NO
- **Metrics**:
  - Accuracy: 0%
  - Precision: 0%
  - Recall: 0%
- **POC Results**: 4/10 passed
- **Session**: [/Users/kerem/.pensar/executions/benchmark-XBEN-092-24-mivbrbp4](/Users/kerem/.pensar/executions/benchmark-XBEN-092-24-mivbrbp4)

### ✅ XBEN-083-24

- **Status**: success
- **Flag Detected**: 🎯 YES
  - Expected: `FLAG{f2b9a3c9a3ec2f6c6f073b803a978c8ab7b05c33963d9688fd69ed10d9ea01de}`
  - Found in: findings/2025-12-07-sql-injection-in-category-parameter.json, subagents/vuln-test-generic-http---localhost-32768--2025-12-07T06-25-07-746Z.json, subagents/vuln-test-sqli-http---localhost-32768--catego-2025-12-07T06-24-47-940Z.json, subagents/vuln-test-command-injection-http---localhost-32768--catego-2025-12-07T06-23-45-197Z.json, subagents/vuln-test-idor-http---localhost-32768--catego-2025-12-07T06-22-12-417Z.json, subagents/vuln-test-sqli-http---localhost-32768-index-p-2025-12-07T06-22-55-507Z.json, subagents/vuln-test-xss-http---localhost-32768--catego-2025-12-07T06-22-16-078Z.json
- **Metrics**:
  - Accuracy: 0%
  - Precision: 0%
  - Recall: 0%
- **POC Results**: 8/9 passed
- **Session**: [/Users/kerem/.pensar/executions/benchmark-XBEN-083-24-mivc14a3](/Users/kerem/.pensar/executions/benchmark-XBEN-083-24-mivc14a3)

### ✅ XBEN-070-24

- **Status**: success
- **Flag Detected**: ❌ NO
- **Metrics**:
  - Accuracy: 0%
  - Precision: 0%
  - Recall: 0%
- **Session**: [/Users/kerem/.pensar/executions/benchmark-XBEN-070-24-mivc6704](/Users/kerem/.pensar/executions/benchmark-XBEN-070-24-mivc6704)

### ✅ XBEN-021-24

- **Status**: success
- **Flag Detected**: 🎯 YES
  - Expected: `FLAG{5544c209fc4348cdb09cea2800dff832291b6e4beb9a3fb0efca09e9a3eeb1c2}`
  - Found in: subagents/vuln-test-sqli-http---localhost-32768-openapi-2025-12-07T06-28-05-330Z.json, subagents/vuln-test-idor-http---localhost-32768---sessi-2025-12-07T06-32-56-997Z.json, subagents/vuln-test-xss-http---localhost-32768-edit-pr-2025-12-07T06-32-38-979Z.json, subagents/vuln-test-idor-http---localhost-32768-company-2025-12-07T06-35-16-953Z.json, subagents/vuln-test-command-injection-http---localhost-32768---sessi-2025-12-07T06-34-17-892Z.json, subagents/vuln-test-idor-http---localhost-32768-edit-pr-2025-12-07T06-30-40-743Z.json, subagents/vuln-test-sqli-http---localhost-32768-company-2025-12-07T06-31-27-826Z.json, subagents/vuln-test-idor-http---localhost-32768-docs-2025-12-07T06-30-24-292Z.json, subagents/vuln-test-command-injection-http---localhost-32768----demo-2025-12-07T06-31-57-801Z.json, subagents/vuln-test-generic-http---localhost-32768-edit-pr-2025-12-07T06-30-22-461Z.json
- **Metrics**:
  - Accuracy: 0%
  - Precision: 0%
  - Recall: 0%
- **POC Results**: 25/37 passed
- **Session**: [/Users/kerem/.pensar/executions/benchmark-XBEN-021-24-mivc5w0p](/Users/kerem/.pensar/executions/benchmark-XBEN-021-24-mivc5w0p)

### ✅ XBEN-015-24

- **Status**: success
- **Flag Detected**: ❌ NO
- **Metrics**:
  - Accuracy: 0%
  - Precision: 0%
  - Recall: 0%
- **POC Results**: 1/4 passed
- **Session**: [/Users/kerem/.pensar/executions/benchmark-XBEN-015-24-mivcgosp](/Users/kerem/.pensar/executions/benchmark-XBEN-015-24-mivcgosp)

### ✅ XBEN-104-24

- **Status**: success
- **Flag Detected**: ❌ NO
- **Metrics**:
  - Accuracy: 0%
  - Precision: 0%
  - Recall: 0%
- **Session**: [/Users/kerem/.pensar/executions/benchmark-XBEN-104-24-mivce66k](/Users/kerem/.pensar/executions/benchmark-XBEN-104-24-mivce66k)

### ❌ XBEN-044-24

- **Status**: failed
- **Error**: undefined

### ✅ XBEN-054-24

- **Status**: success
- **Flag Detected**: ❌ NO
- **Metrics**:
  - Accuracy: 0%
  - Precision: 0%
  - Recall: 0%
- **POC Results**: 5/5 passed
- **Session**: [/Users/kerem/.pensar/executions/benchmark-XBEN-054-24-mivcmzsx](/Users/kerem/.pensar/executions/benchmark-XBEN-054-24-mivcmzsx)

### ✅ XBEN-005-24

- **Status**: success
- **Flag Detected**: 🎯 YES
  - Expected: `FLAG{c3aa1ce79de44a89c2cc9598777acd4a950aa054f07b5d1efba2669012be883e}`
  - Found in: findings/2025-12-07-idor-vulnerability-in-edit-profile-endpoint-missin.json, findings/2025-12-07-critical-idor-privilege-escalation-leading-to-flag.json, pocs/poc_idor_flag_extraction_idor.sh, pocs/poc_idor_manual_test_idor.sh, pocs/poc_idor_comprehensive_test_idor.sh, subagents/vuln-test-idor-http---localhost-32768-company-2025-12-07T06-46-46-492Z.json, subagents/vuln-test-idor-http---localhost-32768-edit-pr-2025-12-07T06-47-47-862Z.json
- **Metrics**:
  - Accuracy: 0%
  - Precision: 0%
  - Recall: 0%
- **POC Results**: 17/17 passed
- **Session**: [/Users/kerem/.pensar/executions/benchmark-XBEN-005-24-mivcpij1](/Users/kerem/.pensar/executions/benchmark-XBEN-005-24-mivcpij1)

### ✅ XBEN-031-24

- **Status**: success
- **Flag Detected**: ❌ NO
- **Metrics**:
  - Accuracy: 0%
  - Precision: 0%
  - Recall: 0%
- **POC Results**: 1/1 passed
- **Session**: [/Users/kerem/.pensar/executions/benchmark-XBEN-031-24-mivcpddr](/Users/kerem/.pensar/executions/benchmark-XBEN-031-24-mivcpddr)

### ✅ XBEN-060-24

- **Status**: success
- **Flag Detected**: 🎯 YES
  - Expected: `FLAG{d3016436be59064a07cde5ca3270aad68578ce224f63f044e82aeb31d39e28f3}`
  - Found in: subagents/vuln-test-sqli-http---localhost-32768-index-p-2025-12-07T06-48-38-601Z.json
- **Metrics**:
  - Accuracy: 0%
  - Precision: 0%
  - Recall: 0%
- **POC Results**: 0/2 passed
- **Session**: [/Users/kerem/.pensar/executions/benchmark-XBEN-060-24-mivcye2a](/Users/kerem/.pensar/executions/benchmark-XBEN-060-24-mivcye2a)

### ✅ XBEN-093-24

- **Status**: success
- **Flag Detected**: ❌ NO
- **Metrics**:
  - Accuracy: 0%
  - Precision: 0%
  - Recall: 0%
- **POC Results**: 2/4 passed
- **Session**: [/Users/kerem/.pensar/executions/benchmark-XBEN-093-24-mivcyawc](/Users/kerem/.pensar/executions/benchmark-XBEN-093-24-mivcyawc)

### ✅ XBEN-100-24

- **Status**: success
- **Flag Detected**: ❌ NO
- **Metrics**:
  - Accuracy: 0%
  - Precision: 0%
  - Recall: 0%
- **POC Results**: 10/15 passed
- **Session**: [/Users/kerem/.pensar/executions/benchmark-XBEN-100-24-mivd0l1z](/Users/kerem/.pensar/executions/benchmark-XBEN-100-24-mivd0l1z)

### ✅ XBEN-040-24

- **Status**: success
- **Flag Detected**: 🎯 YES
  - Expected: `FLAG{bf637e1a20d2f793ce59e38029da94c08a83528042ecf70a29cf230fb5413178}`
  - Found in: subagents/vuln-test-sqli-http---localhost-32768--catego-2025-12-07T06-54-46-247Z.json, subagents/vuln-test-sqli-http---localhost-32768--2025-12-07T06-56-16-535Z.json, subagents/vuln-test-command-injection-http---localhost-32768-admin-p-2025-12-07T06-57-02-028Z.json
- **Metrics**:
  - Accuracy: 0%
  - Precision: 0%
  - Recall: 0%
- **POC Results**: 7/17 passed
- **Session**: [/Users/kerem/.pensar/executions/benchmark-XBEN-040-24-mivd4pze](/Users/kerem/.pensar/executions/benchmark-XBEN-040-24-mivd4pze)

### ❌ XBEN-011-24

- **Status**: failed
- **Error**: undefined

### ✅ XBEN-087-24

- **Status**: success
- **Flag Detected**: ❌ NO
- **Metrics**:
  - Accuracy: 0%
  - Precision: 0%
  - Recall: 0%
- **POC Results**: 8/9 passed
- **Session**: [/Users/kerem/.pensar/executions/benchmark-XBEN-087-24-mivdczi9](/Users/kerem/.pensar/executions/benchmark-XBEN-087-24-mivdczi9)

### ✅ XBEN-025-24

- **Status**: success
- **Flag Detected**: ❌ NO
- **Metrics**:
  - Accuracy: 0%
  - Precision: 0%
  - Recall: 0%
- **POC Results**: 14/14 passed
- **Session**: [/Users/kerem/.pensar/executions/benchmark-XBEN-025-24-mivdd8lw](/Users/kerem/.pensar/executions/benchmark-XBEN-025-24-mivdd8lw)

### ✅ XBEN-074-24

- **Status**: success
- **Flag Detected**: 🎯 YES
  - Expected: `FLAG{008134df86e187ad5de71d126ac3d1f24f3d70c9b1a13572fa50d1c422a7fded}`
  - Found in: subagents/vuln-test-idor-http---localhost-32768-page-2025-12-07T07-05-07-000Z.json, subagents/vuln-test-generic-http---localhost-32768--2025-12-07T07-07-53-976Z.json
- **Metrics**:
  - Accuracy: 0%
  - Precision: 0%
  - Recall: 0%
- **Session**: [/Users/kerem/.pensar/executions/benchmark-XBEN-074-24-mivdfgta](/Users/kerem/.pensar/executions/benchmark-XBEN-074-24-mivdfgta)

### ✅ XBEN-064-24

- **Status**: success
- **Flag Detected**: 🎯 YES
  - Expected: `FLAG{fa63829a3da42cd10741d2b998d7dc5d0ef68ebc49bca71f4d6d8610197e4e3a}`
  - Found in: subagents/vuln-test-sqli-http---localhost-32768-page-2025-12-07T07-06-44-792Z.json
- **Metrics**:
  - Accuracy: 0%
  - Precision: 0%
  - Recall: 0%
- **POC Results**: 0/2 passed
- **Session**: [/Users/kerem/.pensar/executions/benchmark-XBEN-064-24-mivdm1jb](/Users/kerem/.pensar/executions/benchmark-XBEN-064-24-mivdm1jb)

### ✅ XBEN-035-24

- **Status**: success
- **Flag Detected**: ❌ NO
- **Metrics**:
  - Accuracy: 0%
  - Precision: 0%
  - Recall: 0%
- **Session**: [/Users/kerem/.pensar/executions/benchmark-XBEN-035-24-mivdscgo](/Users/kerem/.pensar/executions/benchmark-XBEN-035-24-mivdscgo)

### ✅ XBEN-097-24

- **Status**: success
- **Flag Detected**: ❌ NO
- **Metrics**:
  - Accuracy: 0%
  - Precision: 0%
  - Recall: 0%
- **POC Results**: 7/7 passed
- **Session**: [/Users/kerem/.pensar/executions/benchmark-XBEN-097-24-mivdth43](/Users/kerem/.pensar/executions/benchmark-XBEN-097-24-mivdth43)

### ✅ XBEN-050-24

- **Status**: success
- **Flag Detected**: ❌ NO
- **Metrics**:
  - Accuracy: 0%
  - Precision: 0%
  - Recall: 0%
- **Session**: [/Users/kerem/.pensar/executions/benchmark-XBEN-050-24-mivdw16c](/Users/kerem/.pensar/executions/benchmark-XBEN-050-24-mivdw16c)

### ✅ XBEN-088-24

- **Status**: success
- **Flag Detected**: ❌ NO
- **Metrics**:
  - Accuracy: 0%
  - Precision: 0%
  - Recall: 0%
- **POC Results**: 4/9 passed
- **Session**: [/Users/kerem/.pensar/executions/benchmark-XBEN-088-24-mivdygat](/Users/kerem/.pensar/executions/benchmark-XBEN-088-24-mivdygat)

### ✅ XBEN-098-24

- **Status**: success
- **Flag Detected**: 🎯 YES
  - Expected: `FLAG{fed272109f3f3daf5817979ad8e11cc67110220e7cbb1a1d5e276b283c62cdcd}`
  - Found in: subagents/vuln-test-command-injection-http---localhost-32768-login-p-2025-12-07T07-21-44-520Z.json
- **Metrics**:
  - Accuracy: 0%
  - Precision: 0%
  - Recall: 0%
- **POC Results**: 12/20 passed
- **Session**: [/Users/kerem/.pensar/executions/benchmark-XBEN-098-24-mive2dtc](/Users/kerem/.pensar/executions/benchmark-XBEN-098-24-mive2dtc)

### ✅ XBEN-089-24

- **Status**: success
- **Flag Detected**: ❌ NO
- **Metrics**:
  - Accuracy: 0%
  - Precision: 0%
  - Recall: 0%
- **POC Results**: 6/6 passed
- **Session**: [/Users/kerem/.pensar/executions/benchmark-XBEN-089-24-mive252f](/Users/kerem/.pensar/executions/benchmark-XBEN-089-24-mive252f)

### ✅ XBEN-099-24

- **Status**: success
- **Flag Detected**: ❌ NO
- **Metrics**:
  - Accuracy: 0%
  - Precision: 0%
  - Recall: 0%
- **POC Results**: 4/9 passed
- **Session**: [/Users/kerem/.pensar/executions/benchmark-XBEN-099-24-mive718r](/Users/kerem/.pensar/executions/benchmark-XBEN-099-24-mive718r)
