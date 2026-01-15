/**
 * Authentication Subagent Tools
 *
 * Tool factory for authentication operations in autonomous mode.
 * Provides tools for detecting auth schemes, authenticating, validating sessions,
 * and exporting auth state for other agents.
 */

import { tool } from "ai";
import type { Session } from "../../session";
import type { Logger } from "../logger";
import { AuthStateManager, extractCookiesFromHeaders, getJWTExpiration } from "./authStateManager";
import {
  DetectAuthSchemeInputSchema,
  AuthenticateInputSchema,
  ValidateSessionInputSchema,
  RefreshSessionInputSchema,
  GetAuthStateInputSchema,
  ExportAuthForAgentInputSchema,
  LoadAuthFlowInputSchema,
  DocumentAuthFlowInputSchema,
  type DetectAuthSchemeResult,
  type AuthenticateResult,
  type ValidateSessionResult,
  type RefreshSessionResult,
  type GetAuthStateResult,
  type ExportAuthForAgentResult,
  type LoadAuthFlowResult,
  type DocumentAuthFlowResult,
  type AuthToken,
  type AuthBarrier,
} from "./types";

// =============================================================================
// Types
// =============================================================================

export interface HttpRequestOpts {
  url: string;
  method: string;
  headers?: Record<string, string>;
  body?: string;
  followRedirects?: boolean;
  timeout?: number;
}

export interface HttpRequestResult {
  success: boolean;
  status: number;
  statusText: string;
  headers: Record<string, string | string[]>;
  body: string;
  error?: string;
  redirected?: boolean;
  url?: string;
}

// BrowserTools is the return type from createBrowserTools
// We use a generic record type to be compatible with the actual tool structure
export type BrowserTools = ReturnType<typeof import("../browserTools/playwrightMcp").createBrowserTools>;

export interface AuthToolsConfig {
  session: Session.SessionInfo;
  authStateManager: AuthStateManager;
  httpRequest?: (opts: HttpRequestOpts) => Promise<HttpRequestResult>;
  browserTools?: BrowserTools;
  logger?: Logger;
  abortSignal?: AbortSignal;
}

// =============================================================================
// Default HTTP Request Implementation
// =============================================================================

async function defaultHttpRequest(opts: HttpRequestOpts): Promise<HttpRequestResult> {
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), opts.timeout || 30000);

    const response = await fetch(opts.url, {
      method: opts.method,
      headers: opts.headers,
      body: opts.body,
      redirect: opts.followRedirects !== false ? "follow" : "manual",
      signal: controller.signal,
    });

    clearTimeout(timeoutId);

    const headers: Record<string, string | string[]> = {};
    response.headers.forEach((value, key) => {
      // Handle multiple Set-Cookie headers
      if (key.toLowerCase() === "set-cookie") {
        const existing = headers[key];
        if (Array.isArray(existing)) {
          existing.push(value);
        } else if (existing) {
          headers[key] = [existing, value];
        } else {
          headers[key] = [value];
        }
      } else {
        headers[key] = value;
      }
    });

    const body = await response.text();

    return {
      success: true,
      status: response.status,
      statusText: response.statusText,
      headers,
      body,
      redirected: response.redirected,
      url: response.url,
    };
  } catch (error) {
    return {
      success: false,
      status: 0,
      statusText: "",
      headers: {},
      body: "",
      error: error instanceof Error ? error.message : String(error),
    };
  }
}

// =============================================================================
// Auth Barrier Detection
// =============================================================================

function detectAuthBarrier(responseBody: string, statusCode: number): AuthBarrier | null {
  const bodyLower = responseBody.toLowerCase();

  // CAPTCHA detection
  if (
    bodyLower.includes("captcha") ||
    bodyLower.includes("recaptcha") ||
    bodyLower.includes("hcaptcha") ||
    bodyLower.includes("g-recaptcha")
  ) {
    return {
      type: "captcha",
      details: "CAPTCHA detected on login form",
    };
  }

  // MFA/2FA detection
  if (
    bodyLower.includes("two-factor") ||
    bodyLower.includes("2fa") ||
    bodyLower.includes("mfa") ||
    bodyLower.includes("verification code") ||
    bodyLower.includes("authenticator")
  ) {
    return {
      type: "mfa",
      details: "Multi-factor authentication required",
    };
  }

  // Rate limiting
  if (statusCode === 429 || bodyLower.includes("rate limit") || bodyLower.includes("too many")) {
    return {
      type: "rate_limit",
      details: "Rate limiting detected",
    };
  }

  return null;
}

// =============================================================================
// Tool Factory
// =============================================================================

export function createAuthenticationTools(config: AuthToolsConfig) {
  const { session, authStateManager, httpRequest, browserTools, logger, abortSignal } = config;

  const makeRequest = httpRequest || defaultHttpRequest;

  // ===========================================================================
  // Tool: load_auth_flow
  // ===========================================================================

  const load_auth_flow = tool({
    description: `Load previously documented authentication flow for context recovery.

CRITICAL: Call this FIRST when starting auth tasks.
If a flow exists, skip discovery and proceed directly to authentication.

Returns:
- Documented auth flow (if exists) with login URL, field names, token locations
- null if no prior documentation

This allows resumed agents to authenticate immediately without re-discovery.`,
    inputSchema: LoadAuthFlowInputSchema,
    execute: async ({ targetHost, toolCallDescription }): Promise<LoadAuthFlowResult> => {
      logger?.info(`load_auth_flow: ${targetHost}`);

      const flow = authStateManager.loadFlow(targetHost);

      if (flow) {
        return {
          success: true,
          flowExists: true,
          flow,
          message: `Loaded documented auth flow for ${targetHost}. Login URL: ${flow.scheme.loginUrl}, Method: ${flow.scheme.method}`,
        };
      }

      return {
        success: true,
        flowExists: false,
        message: `No documented auth flow found for ${targetHost}. Need to discover auth scheme.`,
      };
    },
  });

  // ===========================================================================
  // Tool: detect_auth_scheme
  // ===========================================================================

  const detect_auth_scheme = tool({
    description: `Analyze an endpoint to detect authentication scheme.

Identifies:
- Form-based login (username/password fields)
- HTTP Basic/Digest Auth (WWW-Authenticate header)
- Bearer Token / JWT requirements
- API Key authentication (X-API-Key, etc.)
- OAuth2 flows
- Custom authentication schemes

Also detects auth barriers (CAPTCHA, MFA) that block automated auth.

Returns detected scheme and required fields for authentication.`,
    inputSchema: DetectAuthSchemeInputSchema,
    execute: async ({ endpoint, toolCallDescription }): Promise<DetectAuthSchemeResult> => {
      logger?.info(`detect_auth_scheme: ${endpoint}`);

      // Check if aborted
      if (abortSignal?.aborted) {
        return { success: false, error: "Request aborted" };
      }

      try {
        // First, make a GET request to the endpoint
        const response = await makeRequest({
          url: endpoint,
          method: "GET",
          followRedirects: false,
          timeout: 30000,
        });

        if (!response.success) {
          return { success: false, error: response.error };
        }

        const bodyLower = response.body.toLowerCase();
        const headers = response.headers;

        // Check for auth barrier first
        const barrier = detectAuthBarrier(response.body, response.status);
        if (barrier) {
          return {
            success: true,
            barrier,
          };
        }

        // Check WWW-Authenticate header for Basic/Bearer auth
        const wwwAuth = headers["www-authenticate"] || headers["WWW-Authenticate"];
        if (wwwAuth) {
          const authHeader = Array.isArray(wwwAuth) ? wwwAuth[0] : wwwAuth;
          if (authHeader.toLowerCase().startsWith("basic")) {
            return {
              success: true,
              scheme: {
                method: "basic",
                loginUrl: endpoint,
                fields: ["username", "password"],
              },
            };
          }
          if (authHeader.toLowerCase().startsWith("bearer")) {
            return {
              success: true,
              scheme: {
                method: "bearer",
                loginUrl: endpoint,
              },
            };
          }
        }

        // Check for redirect to login page
        if (response.status === 301 || response.status === 302 || response.status === 303) {
          const location = headers["location"] || headers["Location"];
          if (location) {
            const loginUrl = Array.isArray(location) ? location[0] : location;
            if (
              loginUrl.includes("login") ||
              loginUrl.includes("signin") ||
              loginUrl.includes("auth")
            ) {
              return {
                success: true,
                scheme: {
                  method: "form",
                  loginUrl,
                  browserRequired: true,
                  browserReason: "Redirect to login page detected",
                },
              };
            }
          }
        }

        // Check for form-based login indicators
        const hasLoginForm =
          bodyLower.includes('type="password"') ||
          bodyLower.includes("type='password'") ||
          bodyLower.includes('name="password"') ||
          bodyLower.includes('name="pass"');

        if (hasLoginForm) {
          const fields: string[] = [];

          // Detect username field
          if (bodyLower.includes('name="username"') || bodyLower.includes('name="user"')) {
            fields.push("username");
          } else if (bodyLower.includes('name="email"')) {
            fields.push("email");
          } else {
            fields.push("username");
          }

          // Password field
          fields.push("password");

          // CSRF token
          const csrfRequired =
            bodyLower.includes("csrf") ||
            bodyLower.includes("_token") ||
            bodyLower.includes("authenticity_token");

          // Check if browser is required (SPA indicators)
          const browserRequired =
            bodyLower.includes("__next_data__") ||
            bodyLower.includes("react") ||
            bodyLower.includes("vue") ||
            bodyLower.includes("angular");

          return {
            success: true,
            scheme: {
              method: "form",
              loginUrl: endpoint,
              fields,
              csrfRequired,
              browserRequired,
              browserReason: browserRequired ? "SPA framework detected" : undefined,
            },
          };
        }

        // Check for JSON API login patterns
        if (response.status === 401) {
          const contentType = headers["content-type"] || headers["Content-Type"];
          const isJson =
            contentType && (Array.isArray(contentType) ? contentType[0] : contentType).includes("json");

          if (isJson) {
            return {
              success: true,
              scheme: {
                method: "json",
                loginUrl: endpoint,
              },
            };
          }
        }

        // Default: couldn't determine scheme
        return {
          success: true,
          scheme: undefined,
        };
      } catch (error) {
        return {
          success: false,
          error: error instanceof Error ? error.message : String(error),
        };
      }
    },
  });

  // ===========================================================================
  // Tool: authenticate
  // ===========================================================================

  const authenticate = tool({
    description: `Authenticate with credentials to obtain session tokens.

Supports multiple methods:
- form_post: Traditional HTML form submission (application/x-www-form-urlencoded)
- json_post: JSON API login (application/json)
- basic_auth: HTTP Basic Authentication header
- bearer: Bearer token submission
- api_key: API key header

Returns session cookies/tokens on success.
Authentication state is automatically persisted for sharing with other agents.

NOTE: For SPAs or JavaScript-heavy apps, use browser tools instead (browser_navigate, browser_fill, browser_click, browser_evaluate).`,
    inputSchema: AuthenticateInputSchema,
    execute: async ({
      loginUrl,
      method,
      credentials,
      usernameField,
      passwordField,
      csrfToken,
      toolCallDescription,
    }): Promise<AuthenticateResult> => {
      logger?.info(`authenticate: ${loginUrl} method=${method} hasUsername=${!!credentials.username} hasPassword=${!!credentials.password} hasApiKey=${!!credentials.apiKey}`);

      // Check if aborted
      if (abortSignal?.aborted) {
        return { success: false, message: "Request aborted", error: "Aborted" };
      }

      authStateManager.setStatus("authenticating");

      try {
        let response: HttpRequestResult;
        const headers: Record<string, string> = {};
        let body: string | undefined;

        switch (method) {
          case "form_post": {
            headers["Content-Type"] = "application/x-www-form-urlencoded";
            const params = new URLSearchParams();
            if (credentials.username) {
              params.set(usernameField, credentials.username);
            }
            if (credentials.password) {
              params.set(passwordField, credentials.password);
            }
            if (csrfToken) {
              params.set("_token", csrfToken);
            }
            if (credentials.customFields) {
              for (const [key, value] of Object.entries(credentials.customFields)) {
                params.set(key, value);
              }
            }
            body = params.toString();
            break;
          }

          case "json_post": {
            headers["Content-Type"] = "application/json";
            const jsonBody: Record<string, string> = {};
            if (credentials.username) {
              jsonBody[usernameField] = credentials.username;
            }
            if (credentials.password) {
              jsonBody[passwordField] = credentials.password;
            }
            if (credentials.customFields) {
              Object.assign(jsonBody, credentials.customFields);
            }
            body = JSON.stringify(jsonBody);
            break;
          }

          case "basic_auth": {
            if (credentials.username && credentials.password) {
              const encoded = Buffer.from(
                `${credentials.username}:${credentials.password}`
              ).toString("base64");
              headers["Authorization"] = `Basic ${encoded}`;
            }
            break;
          }

          case "bearer": {
            if (credentials.apiKey) {
              headers["Authorization"] = `Bearer ${credentials.apiKey}`;
            }
            break;
          }

          case "api_key": {
            if (credentials.apiKey) {
              headers["X-API-Key"] = credentials.apiKey;
            }
            break;
          }
        }

        response = await makeRequest({
          url: loginUrl,
          method: method === "basic_auth" || method === "bearer" || method === "api_key" ? "GET" : "POST",
          headers,
          body,
          followRedirects: true,
          timeout: 30000,
        });

        if (!response.success) {
          authStateManager.markFailed(response.error);
          return {
            success: false,
            error: response.error,
            message: `HTTP request failed: ${response.error}`,
          };
        }

        // Check for auth barriers in response
        const barrier = detectAuthBarrier(response.body, response.status);
        if (barrier) {
          authStateManager.markFailed(barrier.details);
          return {
            success: false,
            barrier,
            message: `Authentication blocked: ${barrier.details}`,
          };
        }

        // Check for failed login indicators
        if (
          response.status === 401 ||
          response.status === 403 ||
          response.body.toLowerCase().includes("invalid credentials") ||
          response.body.toLowerCase().includes("incorrect password") ||
          response.body.toLowerCase().includes("login failed")
        ) {
          authStateManager.markFailed("Invalid credentials");
          return {
            success: false,
            message: "Authentication failed: Invalid credentials",
          };
        }

        // Extract tokens from response
        const tokens: AuthToken[] = [];

        // Extract cookies from Set-Cookie headers
        const cookieTokens = extractCookiesFromHeaders(
          response.headers as Record<string, string | string[]>
        );
        tokens.push(...cookieTokens);

        // Check for JWT in response body
        try {
          const bodyJson = JSON.parse(response.body);
          if (bodyJson.token || bodyJson.access_token || bodyJson.accessToken) {
            const jwtValue = bodyJson.token || bodyJson.access_token || bodyJson.accessToken;
            const expiration = getJWTExpiration(jwtValue);
            tokens.push({
              type: "jwt",
              name: "Authorization",
              value: jwtValue,
              expiresAt: expiration || undefined,
            });
          }
          if (bodyJson.refresh_token || bodyJson.refreshToken) {
            tokens.push({
              type: "jwt",
              name: "refresh_token",
              value: bodyJson.refresh_token || bodyJson.refreshToken,
            });
          }
        } catch {
          // Not JSON, skip
        }

        // Check for auth header in response (some APIs return it)
        const authHeader = response.headers["authorization"] || response.headers["Authorization"];
        if (authHeader) {
          const tokenValue = Array.isArray(authHeader) ? authHeader[0] : authHeader;
          if (tokenValue.startsWith("Bearer ")) {
            const jwtValue = tokenValue.substring(7);
            tokens.push({
              type: "bearer",
              name: "Authorization",
              value: jwtValue,
              expiresAt: getJWTExpiration(jwtValue) || undefined,
            });
          }
        }

        if (tokens.length === 0) {
          // Check if login was successful based on redirect or status
          if (response.status === 200 || response.status === 302) {
            // Might be successful but no tokens extracted
            authStateManager.setStatus("active");
            authStateManager.updateState({ authenticatedAt: Date.now() });
            return {
              success: true,
              tokens: [],
              authState: authStateManager.getState(),
              message: "Authentication appears successful but no tokens were extracted. Check cookies or response for session info.",
            };
          }
        }

        // Store all tokens
        for (const token of tokens) {
          authStateManager.addToken(token);
        }

        // Set auth endpoint info
        authStateManager.setAuthEndpoint({
          url: loginUrl,
          method: method === "json_post" ? "POST" : method === "form_post" ? "POST" : "GET",
          contentType: headers["Content-Type"] || "text/html",
          usernameField,
          passwordField,
        });

        return {
          success: true,
          tokens,
          authState: authStateManager.getState(),
          message: `Authentication successful. Obtained ${tokens.length} token(s).`,
        };
      } catch (error) {
        const errorMsg = error instanceof Error ? error.message : String(error);
        authStateManager.markFailed(errorMsg);
        return {
          success: false,
          error: errorMsg,
          message: `Authentication error: ${errorMsg}`,
        };
      }
    },
  });

  // ===========================================================================
  // Tool: document_auth_flow
  // ===========================================================================

  const document_auth_flow = tool({
    description: `Document discovered authentication flow for future reference.

CRITICAL: Call this AFTER successfully authenticating for the first time.
This allows future runs to skip discovery and authenticate immediately.

Documents:
- Login endpoint and method
- Field names (username, password, CSRF)
- Token extraction locations
- Browser flow requirements (if any)
- Rate limiting or other constraints

Persists to auth/auth-flow.json in session directory.`,
    inputSchema: DocumentAuthFlowInputSchema,
    execute: async (input): Promise<DocumentAuthFlowResult> => {
      logger?.info(`document_auth_flow: ${input.targetHost}`);

      try {
        authStateManager.saveFlow({
          targetHost: input.targetHost,
          documentedAt: Date.now(),
          scheme: input.scheme,
          fields: input.fields,
          csrfExtraction: input.csrfExtraction,
          tokenExtraction: input.tokenExtraction,
          browserFlow: input.browserFlow,
          notes: input.notes,
        });

        return {
          success: true,
          flowPath: "auth/auth-flow.json",
          message: `Auth flow documented for ${input.targetHost}. Future runs will skip discovery.`,
        };
      } catch (error) {
        return {
          success: false,
          flowPath: "",
          error: error instanceof Error ? error.message : String(error),
          message: "Failed to document auth flow",
        };
      }
    },
  });

  // ===========================================================================
  // Tool: validate_session
  // ===========================================================================

  const validate_session = tool({
    description: `Test if current authentication session is still valid.

Makes a request to a protected endpoint and checks response:
- 200/2xx: Session valid
- 401/403: Session expired or invalid
- 3xx redirect to login: Session expired

Updates session validity status in auth state.`,
    inputSchema: ValidateSessionInputSchema,
    execute: async ({ testEndpoint, expectedStatus, toolCallDescription }): Promise<ValidateSessionResult> => {
      logger?.info(`validate_session: ${testEndpoint} expectedStatus=${expectedStatus}`);

      if (abortSignal?.aborted) {
        return { success: false, valid: false, message: "Request aborted", error: "Aborted" };
      }

      try {
        const headers = authStateManager.getAuthHeaders();
        const cookies = authStateManager.getCookieString();

        if (cookies) {
          headers["Cookie"] = cookies;
        }

        const response = await makeRequest({
          url: testEndpoint,
          method: "GET",
          headers,
          followRedirects: false,
          timeout: 30000,
        });

        if (!response.success) {
          return {
            success: false,
            valid: false,
            message: `Request failed: ${response.error}`,
            error: response.error,
          };
        }

        // Check for redirect to login
        if (response.status === 301 || response.status === 302 || response.status === 303) {
          const location = response.headers["location"] || response.headers["Location"];
          if (location) {
            const locationStr = Array.isArray(location) ? location[0] : location;
            if (
              locationStr.includes("login") ||
              locationStr.includes("signin") ||
              locationStr.includes("auth")
            ) {
              authStateManager.setStatus("expired");
              return {
                success: true,
                valid: false,
                statusCode: response.status,
                message: "Session expired - redirected to login page",
              };
            }
          }
        }

        // Check status code
        if (response.status === 401 || response.status === 403) {
          authStateManager.setStatus("expired");
          return {
            success: true,
            valid: false,
            statusCode: response.status,
            message: `Session invalid - received ${response.status} ${response.statusText}`,
          };
        }

        if (response.status >= 200 && response.status < 300) {
          authStateManager.markValidated();
          return {
            success: true,
            valid: true,
            statusCode: response.status,
            message: `Session valid - received ${response.status} ${response.statusText}`,
          };
        }

        return {
          success: true,
          valid: response.status === expectedStatus,
          statusCode: response.status,
          message: `Received status ${response.status}, expected ${expectedStatus}`,
        };
      } catch (error) {
        return {
          success: false,
          valid: false,
          message: `Validation error: ${error instanceof Error ? error.message : String(error)}`,
          error: error instanceof Error ? error.message : String(error),
        };
      }
    },
  });

  // ===========================================================================
  // Tool: refresh_session
  // ===========================================================================

  const refresh_session = tool({
    description: `Refresh an expired or expiring session.

Methods:
- Use refresh token endpoint (if available)
- Re-authenticate with original credentials

Automatically updates stored tokens on success.`,
    inputSchema: RefreshSessionInputSchema,
    execute: async ({
      refreshEndpoint,
      useOriginalCredentials,
      toolCallDescription,
    }): Promise<RefreshSessionResult> => {
      logger?.info(`refresh_session: refreshEndpoint=${refreshEndpoint} useOriginalCredentials=${useOriginalCredentials}`);

      if (abortSignal?.aborted) {
        return { success: false, message: "Request aborted", error: "Aborted" };
      }

      try {
        // Try refresh token first
        const tokens = authStateManager.getTokens();
        const refreshToken = tokens.find(
          (t) => t.name === "refresh_token" || t.name === "refreshToken"
        );

        if (refreshEndpoint && refreshToken) {
          const response = await makeRequest({
            url: refreshEndpoint,
            method: "POST",
            headers: {
              "Content-Type": "application/json",
            },
            body: JSON.stringify({ refresh_token: refreshToken.value }),
            timeout: 30000,
          });

          if (response.success && response.status === 200) {
            try {
              const bodyJson = JSON.parse(response.body);
              const newTokens: AuthToken[] = [];

              if (bodyJson.token || bodyJson.access_token || bodyJson.accessToken) {
                const jwtValue = bodyJson.token || bodyJson.access_token || bodyJson.accessToken;
                newTokens.push({
                  type: "jwt",
                  name: "Authorization",
                  value: jwtValue,
                  expiresAt: getJWTExpiration(jwtValue) || undefined,
                });
              }

              if (bodyJson.refresh_token || bodyJson.refreshToken) {
                newTokens.push({
                  type: "jwt",
                  name: "refresh_token",
                  value: bodyJson.refresh_token || bodyJson.refreshToken,
                });
              }

              for (const token of newTokens) {
                authStateManager.addToken(token);
              }

              return {
                success: true,
                newTokens,
                message: `Session refreshed. Obtained ${newTokens.length} new token(s).`,
              };
            } catch {
              // Parse failed
            }
          }
        }

        // Fallback: re-authenticate with original credentials
        if (useOriginalCredentials) {
          const state = authStateManager.getState();
          if (state.authEndpoint) {
            return {
              success: false,
              message: "Refresh token failed. Use authenticate tool to re-authenticate with original credentials.",
              error: "Refresh failed, re-authentication required",
            };
          }
        }

        return {
          success: false,
          message: "Unable to refresh session. No refresh endpoint or original credentials available.",
          error: "No refresh method available",
        };
      } catch (error) {
        return {
          success: false,
          message: `Refresh error: ${error instanceof Error ? error.message : String(error)}`,
          error: error instanceof Error ? error.message : String(error),
        };
      }
    },
  });

  // ===========================================================================
  // Tool: get_auth_state
  // ===========================================================================

  const get_auth_state = tool({
    description: `Get current authentication state.

Returns:
- Current tokens (cookies, JWT, etc.)
- Session validity status
- Expiration times
- Discovered scopes/roles
- Headers to include in requests

Use this to check authentication status before making requests.`,
    inputSchema: GetAuthStateInputSchema,
    execute: async ({ toolCallDescription }): Promise<GetAuthStateResult> => {
      logger?.info("get_auth_state");

      const state = authStateManager.getState();
      const headers = authStateManager.getAuthHeaders();
      const cookies = authStateManager.getCookieString();
      const isValid = !authStateManager.isExpired() && state.status === "active";

      return {
        success: true,
        state,
        headers,
        cookies,
        isValid,
        message: `Auth state: ${state.status}. ${state.tokens.length} active token(s). Valid: ${isValid}`,
      };
    },
  });

  // ===========================================================================
  // Tool: export_auth_for_agent
  // ===========================================================================

  const export_auth_for_agent = tool({
    description: `Export authentication state for use by other agents.

Creates exportable auth info including:
- HTTP headers to include in requests
- Cookies string
- Auth instructions for POC scripts

Formats:
- headers: Returns headers dict
- curl: Returns curl flags (-H, -b)
- poc_script: Returns bash script snippet

This allows other agents (vulnerability testers) to make authenticated requests.`,
    inputSchema: ExportAuthForAgentInputSchema,
    execute: async ({ format, toolCallDescription }): Promise<ExportAuthForAgentResult> => {
      logger?.info(`export_auth_for_agent: format=${format}`);

      const authInfo = authStateManager.exportForAgent();

      switch (format) {
        case "headers":
          return {
            success: true,
            format,
            headers: authStateManager.getAuthHeaders(),
            authenticationInfo: authInfo,
            message: "Auth exported as headers dict",
          };

        case "curl":
          return {
            success: true,
            format,
            curlFlags: authStateManager.exportAsCurlFlags(),
            authenticationInfo: authInfo,
            message: "Auth exported as curl flags",
          };

        case "poc_script":
          return {
            success: true,
            format,
            pocScript: authStateManager.exportAsPocScript(),
            authenticationInfo: authInfo,
            message: "Auth exported as POC script snippet",
          };

        default:
          return {
            success: true,
            format: "headers",
            headers: authStateManager.getAuthHeaders(),
            authenticationInfo: authInfo,
            message: "Auth exported as headers dict (default)",
          };
      }
    },
  });

  // ===========================================================================
  // Return All Tools
  // ===========================================================================

  return {
    load_auth_flow,
    detect_auth_scheme,
    authenticate,
    document_auth_flow,
    validate_session,
    refresh_session,
    get_auth_state,
    export_auth_for_agent,
  };
}

export type AuthenticationTools = ReturnType<typeof createAuthenticationTools>;
