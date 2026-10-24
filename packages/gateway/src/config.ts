/**
 * Gateway configuration: defaults and environment parsing.
 *
 * `injectionAction` defaults to `log`. A heuristic detector will sometimes
 * flag a legitimate message, and the only acceptable failure mode for a false
 * positive is a log line plus an `X-Injection-Detected` header. Blocking and
 * rephrasing (which rewrites the user's words with another model) are
 * deliberate opt-ins.
 */

import { z } from 'zod';
import { PII_ENTITY_TYPES, type PIIEntityType } from '@evidentai/detectors';
import type { GatewayConfig } from './types.js';

export const DEFAULT_PII_TYPES: PIIEntityType[] = ['email', 'phone', 'ssn', 'credit_card'];

export const DEFAULT_CONFIG: GatewayConfig = {
  port: 3000,
  host: '0.0.0.0',
  cors: true,
  logging: true,
  input: {
    detectInjection: true,
    injectionSensitivity: 'medium',
    injectionAction: 'log',
    logInput: true,
  },
  output: {
    detectPII: true,
    piiTypes: [...DEFAULT_PII_TYPES],
    piiAction: 'redact',
    piiMinConfidence: 'medium',
    piiScanToolArguments: false,
    logOutput: true,
  },
};

// =============================================================================
// Environment parsing
// =============================================================================

const boolFromEnv = (defaultValue: boolean) =>
  z
    .string()
    .optional()
    .transform((v) => (v === undefined || v === '' ? defaultValue : !/^(false|0|no|off)$/i.test(v)));

const listFromEnv = z
  .string()
  .optional()
  .transform((v) =>
    v === undefined || v.trim() === ''
      ? undefined
      : v
          .split(',')
          .map((s) => s.trim())
          .filter(Boolean)
  );

const EnvSchema = z.object({
  GATEWAY_PORT: z.coerce.number().int().min(0).max(65535).default(3000),
  GATEWAY_HOST: z.string().default('0.0.0.0'),
  GATEWAY_API_KEY: z.string().optional(),
  GATEWAY_LOGGING: boolFromEnv(true),
  GATEWAY_CORS: boolFromEnv(true),
  OPENAI_API_KEY: z.string().optional(),
  GATEWAY_REPHRASE_MODEL: z.string().default('gpt-4o-mini'),

  GATEWAY_DETECT_INJECTION: boolFromEnv(true),
  GATEWAY_INJECTION_SENSITIVITY: z.enum(['low', 'medium', 'high']).default('medium'),
  GATEWAY_INJECTION_ACTION: z.enum(['block', 'rephrase', 'log']).default('log'),
  GATEWAY_INJECTION_CUSTOM_PATTERNS: listFromEnv,
  GATEWAY_LOG_INPUT: boolFromEnv(true),

  GATEWAY_DETECT_PII: boolFromEnv(true),
  GATEWAY_PII_TYPES: listFromEnv.pipe(z.array(z.enum(PII_ENTITY_TYPES as [PIIEntityType, ...PIIEntityType[]])).optional()),
  GATEWAY_PII_ACTION: z.enum(['block', 'redact', 'log']).default('redact'),
  GATEWAY_PII_MIN_CONFIDENCE: z.enum(['low', 'medium', 'high']).default('medium'),
  GATEWAY_PII_ALLOW_VALUES: listFromEnv,
  GATEWAY_PII_ALLOW_PATTERNS: listFromEnv,
  GATEWAY_PII_SCAN_TOOL_ARGUMENTS: boolFromEnv(false),
  GATEWAY_LOG_OUTPUT: boolFromEnv(true),
});

export class ConfigError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ConfigError';
  }
}

/**
 * Build a gateway config from environment variables. Throws ConfigError with
 * a readable message listing every invalid variable.
 */
export function configFromEnv(env: NodeJS.ProcessEnv = process.env): Partial<GatewayConfig> {
  const parsed = EnvSchema.safeParse(env);
  if (!parsed.success) {
    const lines = parsed.error.errors.map((e) => {
      const name = e.path.join('.');
      return `  ${name}: ${e.message} (got ${JSON.stringify(env[name])})`;
    });
    throw new ConfigError(`Invalid gateway environment configuration:\n${lines.join('\n')}`);
  }

  const e = parsed.data;
  const config: Partial<GatewayConfig> = {
    port: e.GATEWAY_PORT,
    host: e.GATEWAY_HOST,
    cors: e.GATEWAY_CORS,
    apiKey: e.GATEWAY_API_KEY,
    logging: e.GATEWAY_LOGGING,
    internalLLM: {
      apiKey: e.OPENAI_API_KEY,
      model: e.GATEWAY_REPHRASE_MODEL,
    },
    input: {
      detectInjection: e.GATEWAY_DETECT_INJECTION,
      injectionSensitivity: e.GATEWAY_INJECTION_SENSITIVITY,
      injectionAction: e.GATEWAY_INJECTION_ACTION,
      injectionCustomPatterns: e.GATEWAY_INJECTION_CUSTOM_PATTERNS,
      logInput: e.GATEWAY_LOG_INPUT,
    },
    output: {
      detectPII: e.GATEWAY_DETECT_PII,
      piiTypes: e.GATEWAY_PII_TYPES ?? [...DEFAULT_PII_TYPES],
      piiAction: e.GATEWAY_PII_ACTION,
      piiMinConfidence: e.GATEWAY_PII_MIN_CONFIDENCE,
      piiAllowValues: e.GATEWAY_PII_ALLOW_VALUES,
      piiAllowPatterns: e.GATEWAY_PII_ALLOW_PATTERNS,
      piiScanToolArguments: e.GATEWAY_PII_SCAN_TOOL_ARGUMENTS,
      logOutput: e.GATEWAY_LOG_OUTPUT,
    },
  };

  return config;
}

/** Merge a partial config over the defaults, one level deep for input/output. */
export function resolveConfig(config: Partial<GatewayConfig> = {}): GatewayConfig {
  return {
    ...DEFAULT_CONFIG,
    ...config,
    input: { ...DEFAULT_CONFIG.input, ...config.input },
    output: { ...DEFAULT_CONFIG.output, ...config.output },
  };
}

/** Non-fatal configuration warnings worth printing at startup. */
export function configWarnings(config: GatewayConfig): string[] {
  const warnings: string[] = [];
  if (
    config.input.detectInjection &&
    config.input.injectionAction === 'rephrase' &&
    !config.internalLLM?.apiKey &&
    !process.env.OPENAI_API_KEY
  ) {
    warnings.push(
      'injectionAction is "rephrase" but no internal LLM key is configured (internalLLM.apiKey / OPENAI_API_KEY). ' +
        'Flagged messages will have matched text stripped instead of being rephrased.'
    );
  }
  if (!config.apiKey) {
    warnings.push('No GATEWAY_API_KEY set: the gateway accepts unauthenticated requests. Fine locally, not for a shared network.');
  }
  return warnings;
}
