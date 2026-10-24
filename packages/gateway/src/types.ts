/**
 * EvidentAI Gateway Types
 *
 * Type definitions for the LLM Security Gateway including:
 * - OpenAI-compatible API types
 * - Gateway configuration
 * - Pipeline types for input/output processing
 * - Logging and audit types
 */

import type { InjectionCategory, PIIEntityType, PIIMatch, Severity, Confidence } from '@evidentai/detectors';

// =============================================================================
// OpenAI-Compatible API Types
// =============================================================================

export interface ToolCall {
  id: string;
  type: 'function';
  function: {
    name: string;
    arguments: string;
  };
}

/** A content part in the OpenAI array content format. */
export interface ContentPart {
  type: string;
  text?: string;
  [key: string]: unknown;
}

export interface ChatMessage {
  role: 'system' | 'developer' | 'user' | 'assistant' | 'function' | 'tool';
  /** Text, an array of content parts, or null for assistant tool-call-only turns. */
  content: string | ContentPart[] | null;
  name?: string;
  /** Required on `tool` role messages */
  tool_call_id?: string;
  refusal?: string | null;
  function_call?: {
    name: string;
    arguments: string;
  };
  tool_calls?: ToolCall[];
}

export interface ToolDefinition {
  type: 'function';
  function: {
    name: string;
    description?: string;
    parameters?: Record<string, unknown>;
    strict?: boolean;
  };
}

export type ToolChoice =
  | 'none'
  | 'auto'
  | 'required'
  | { type: 'function'; function: { name: string } };

export interface ChatCompletionRequest {
  model: string;
  messages: ChatMessage[];
  temperature?: number;
  top_p?: number;
  n?: number;
  stream?: boolean;
  stream_options?: Record<string, unknown>;
  stop?: string | string[];
  max_tokens?: number;
  max_completion_tokens?: number;
  presence_penalty?: number;
  frequency_penalty?: number;
  logit_bias?: Record<string, number>;
  logprobs?: boolean;
  top_logprobs?: number;
  seed?: number;
  user?: string;
  response_format?: Record<string, unknown>;
  parallel_tool_calls?: boolean;
  service_tier?: string;
  store?: boolean;
  metadata?: Record<string, unknown>;
  functions?: Array<{
    name: string;
    description?: string;
    parameters?: Record<string, unknown>;
  }>;
  function_call?: 'none' | 'auto' | { name: string };
  tools?: ToolDefinition[];
  tool_choice?: ToolChoice;
  /** Any other OpenAI field is forwarded untouched. */
  [key: string]: unknown;
}

export type FinishReason = 'stop' | 'length' | 'function_call' | 'tool_calls' | 'content_filter' | null;

export interface ChatCompletionChoice {
  index: number;
  message: ChatMessage;
  finish_reason: FinishReason;
  logprobs?: unknown;
}

export interface ChatCompletionUsage {
  prompt_tokens: number;
  completion_tokens: number;
  total_tokens: number;
}

export interface ChatCompletionResponse {
  id: string;
  object: 'chat.completion';
  created: number;
  model: string;
  choices: ChatCompletionChoice[];
  usage?: ChatCompletionUsage;
  system_fingerprint?: string;
}

export interface ChatCompletionStreamChunk {
  id: string;
  object: 'chat.completion.chunk';
  created: number;
  model: string;
  choices: Array<{
    index: number;
    delta: Partial<ChatMessage>;
    finish_reason: 'stop' | 'length' | 'function_call' | 'tool_calls' | 'content_filter' | null;
  }>;
  system_fingerprint?: string;
}

// =============================================================================
// LLM Provider Types
// =============================================================================

export type LLMProviderName = 'openai' | 'anthropic' | 'azure';

export interface LLMProviderConfig {
  name: LLMProviderName;
  apiKey: string;
  model?: string;
  baseUrl?: string;
  // Azure-specific
  endpoint?: string;
  deployment?: string;
  apiVersion?: string;
}

// =============================================================================
// Gateway Configuration
// =============================================================================

export interface GatewayConfig {
  /** Port to listen on */
  port: number;
  /** Host to bind to */
  host: string;
  /** Enable CORS */
  cors: boolean;
  /** API key for authenticating gateway requests */
  apiKey?: string;
  /** Enable request logging */
  logging: boolean;
  /** Input pipeline configuration */
  input: InputPipelineConfig;
  /** Output pipeline configuration */
  output: OutputPipelineConfig;
  /** Internal LLM for rephrasing (uses OpenAI by default) */
  internalLLM?: {
    apiKey?: string;
    model?: string;
  };
}

export interface InputPipelineConfig {
  /** Enable injection detection */
  detectInjection: boolean;
  /** Injection detection sensitivity */
  injectionSensitivity: 'low' | 'medium' | 'high';
  /** Action on injection detection */
  injectionAction: 'block' | 'rephrase' | 'log';
  /** Extra regex sources treated as high-confidence injection patterns */
  injectionCustomPatterns?: string[];
  /** Enable input logging */
  logInput: boolean;
}

export interface OutputPipelineConfig {
  /** Enable PII detection */
  detectPII: boolean;
  /** PII types to detect */
  piiTypes: PIIEntityType[];
  /** Action on PII detection */
  piiAction: 'block' | 'redact' | 'log';
  /** Ignore PII matches below this confidence (default `medium`) */
  piiMinConfidence?: Confidence;
  /** Known non-PII values to ignore (support numbers, company addresses) */
  piiAllowValues?: string[];
  /** Regular expressions whose matches are not PII */
  piiAllowPatterns?: string[];
  /**
   * Also scan (and redact inside) tool call arguments. Off by default because
   * redacting JSON arguments can break the calling application.
   */
  piiScanToolArguments?: boolean;
  /** Enable output logging */
  logOutput: boolean;
}

// =============================================================================
// PII Types (shared with the CLI through @evidentai/detectors)
// =============================================================================

export type { PIIEntityType, PIIMatch } from '@evidentai/detectors';

// =============================================================================
// Injection Types
// =============================================================================

export interface InjectionMatch {
  technique: string;
  category: InjectionCategory;
  severity: Severity;
  /** Human readable description of the matched pattern */
  pattern: string;
  matched: string;
  position: number;
  confidence: 'high' | 'medium' | 'low';
  inInput: boolean;
}

// =============================================================================
// Pipeline Results
// =============================================================================

export interface InputSanitizationResult {
  /** Original messages */
  original: ChatMessage[];
  /** Sanitized messages (may be rephrased) */
  sanitized: ChatMessage[];
  /** Whether injection was detected */
  injectionDetected: boolean;
  /** Injection matches found */
  injectionMatches: InjectionMatch[];
  /** Whether the request should be blocked */
  blocked: boolean;
  /** Block reason if blocked */
  blockReason?: string;
  /** Processing time in ms */
  latencyMs: number;
}

export interface OutputProcessingResult {
  /** Original response content */
  original: string;
  /** Processed response content (may have PII redacted) */
  processed: string;
  /** Whether PII was detected */
  piiDetected: boolean;
  /** PII matches found */
  piiMatches: PIIMatch[];
  /** Whether the response should be blocked */
  blocked: boolean;
  /** Block reason if blocked */
  blockReason?: string;
  /** Processing time in ms */
  latencyMs: number;
}

// =============================================================================
// Logging Types
// =============================================================================

export interface GatewayRequest {
  id: string;
  timestamp: string;
  /** Provider used (openai, anthropic, etc.) */
  provider: LLMProviderName;
  /** Model requested */
  model: string;
  /** Original messages */
  messages: ChatMessage[];
  /** Sanitized messages (if different) */
  sanitizedMessages?: ChatMessage[];
  /** Input sanitization result */
  inputResult?: InputSanitizationResult;
  /** User ID if provided */
  userId?: string;
  /** Custom metadata */
  metadata?: Record<string, unknown>;
}

export interface GatewayResponse {
  id: string;
  requestId: string;
  timestamp: string;
  /** Original response */
  original: ChatCompletionResponse;
  /** Processed response (with PII redacted if applicable) */
  processed?: ChatCompletionResponse;
  /** Output processing result */
  outputResult?: OutputProcessingResult;
  /** Response latency in ms */
  latencyMs: number;
  /** Error if any */
  error?: string;
}

export interface Incident {
  id: string;
  timestamp: string;
  requestId: string;
  type: 'injection' | 'pii';
  severity: 'low' | 'medium' | 'high' | 'critical';
  details: InjectionMatch[] | PIIMatch[];
  action: 'blocked' | 'redacted' | 'rephrased' | 'logged';
}

// =============================================================================
// Gateway Error Types
// =============================================================================

export class GatewayError extends Error {
  constructor(
    message: string,
    public statusCode: number,
    public code: string,
    public details?: Record<string, unknown>
  ) {
    super(message);
    this.name = 'GatewayError';
  }
}

export class AuthenticationError extends GatewayError {
  constructor(message = 'Invalid or missing API key') {
    super(message, 401, 'authentication_error');
  }
}

export class ValidationError extends GatewayError {
  constructor(message: string, details?: Record<string, unknown>) {
    super(message, 400, 'validation_error', details);
  }
}

export class InjectionBlockedError extends GatewayError {
  constructor(matches: InjectionMatch[]) {
    super('Request blocked due to detected prompt injection attempt', 403, 'injection_blocked', {
      matches: matches.map((m) => ({
        technique: m.technique,
        confidence: m.confidence,
      })),
    });
  }
}

export class PIIBlockedError extends GatewayError {
  constructor(matches: PIIMatch[]) {
    super('Response blocked due to detected PII', 403, 'pii_blocked', {
      types: [...new Set(matches.map((m) => m.type))],
    });
  }
}

export class ProviderError extends GatewayError {
  constructor(message: string, provider: string, statusCode = 502) {
    super(message, statusCode, 'provider_error', { provider });
  }
}
