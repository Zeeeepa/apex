// Braintrust Integration Module
//
// Main entry point for the Braintrust observability integration.
// Provides a minimal, clean API for tracing agents, tools, and AI calls.
//
// Configuration can be set via environment variables (recommended) or ~/.pensar/config.json:
//   export BRAINTRUST_API_KEY="your-api-key"
//   export BRAINTRUST_PROJECT_NAME="apex-pentest"  # optional
//   export BRAINTRUST_ENVIRONMENT="dev"            # optional: dev|staging|prod
//
// ## Recommended Usage (Factory Pattern):
//
//   import { createTracedAgent, withConfigContext } from '@/core/braintrust';
//   import { config } from '@/core/config';
//
//   // Wrap your agent once at definition:
//   export const runAgent = createTracedAgent(
//     'my-agent',
//     async (args) => { /* agent logic */ },
//     (args) => ({ agent_type: 'pentest', target: args.target, ... })
//   );
//
//   // At entry points, provide config context:
//   const appConfig = await config.get();
//   await withConfigContext(appConfig, async () => {
//     await runAgent({ target: 'example.com' }); // Automatically traced!
//   });
//
// ## Legacy Usage (Manual Tracing):
//
//   import { traceAgent, isBraintrustEnabled } from '@/core/braintrust';
//
//   const appConfig = await config.get();
//   if (isBraintrustEnabled(appConfig)) {
//     await traceAgent(appConfig, 'my-agent', metadata, async (updateMetadata) => {
//       // agent logic
//       updateMetadata({ findings_count: 5 });
//     });
//   }

// Configuration
export { isBraintrustEnabled } from './config';

// Client management
export { flushBraintrust } from './client';

// Context management (for factory pattern)
export {
  withConfigContext,
  getConfigFromContext,
  getConfigFromContextOrFetch,
  hasConfigContext,
} from './context';

// Factory functions (recommended for new code)
export {
  createTracedAgent,
  createTracedTool,
  createTracedAICall,
  getRegisteredAgents,
  getRegisteredTools,
} from './factories';

// Tracing utilities (legacy/manual usage)
export { traceAgent, traceToolCall, traceAICall } from './tracer';

// Data sanitization (main entry points only)
export { sanitizeToolInput, sanitizeToolOutput } from './sanitizer';

// Type exports
export type {
  AgentSpanMetadata,
  ToolSpanMetadata,
  AISpanMetadata,
} from './types';
