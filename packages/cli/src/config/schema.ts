/**
 * Zod Schema for ReleaseGate Configuration
 *
 * This schema validates the YAML configuration file and provides
 * clear, actionable error messages for users.
 *
 * Design principles:
 * - Fail fast with descriptive errors
 * - Sensible defaults where possible
 * - Type inference for TypeScript
 */

import { z } from 'zod';

// =============================================================================
// Constants for valid values (used in error messages)
// =============================================================================

export const VALID_EVALUATORS = ['exact-match', 'contains', 'llm-judge', 'pii', 'prompt-injection', 'custom'] as const;
export const VALID_PROVIDERS = ['openai', 'anthropic', 'azure', 'custom'] as const;
export const VALID_PII_TYPES = ['email', 'phone', 'ssn', 'credit_card', 'ip_address', 'address', 'name', 'date_of_birth'] as const;
export const VALID_OUTPUT_FORMATS = ['json', 'yaml', 'junit', 'markdown'] as const;
export const VALID_DETECTION_METHODS = ['heuristic', 'canary', 'llm'] as const;
export const VALID_SENSITIVITIES = ['low', 'medium', 'high'] as const;

// =============================================================================
// PII Entity Types
// =============================================================================

export const PIIEntityTypeSchema = z.enum(VALID_PII_TYPES, {
  errorMap: () => ({ message: `Invalid PII type. Expected one of: ${VALID_PII_TYPES.join(', ')}` }),
});

// =============================================================================
// Evaluator Configurations
// =============================================================================

export const ExactMatchConfigSchema = z.object({
  case_sensitive: z.boolean().default(true),
  trim_whitespace: z.boolean().default(true),
}).optional();

export const ContainsConfigSchema = z.object({
  case_sensitive: z.boolean().default(false),
  match_all: z.boolean().default(false).describe('true = AND all terms, false = OR any term'),
}).optional();

export const LLMJudgeConfigSchema = z.object({
  model: z.string().optional().describe('Override the judge model (defaults to provider model)'),
  score_range: z.tuple([z.number(), z.number()]).default([1, 5]),
  pass_threshold: z.number().min(0).max(10).default(3),
  chain_of_thought: z.boolean().default(true).describe('Enable chain-of-thought reasoning for better accuracy'),
}).optional();

export const PIIConfigSchema = z.object({
  fail_on: z.array(PIIEntityTypeSchema).min(1, 'Must specify at least one PII type to check'),
  allow: z.array(PIIEntityTypeSchema).optional(),
  redact: z.boolean().default(false).describe('Include a redacted copy of the output in the result details'),
  min_confidence: z.enum(['low', 'medium', 'high']).default('medium')
    .describe('Ignore matches below this confidence (private IPs and bare 10-digit numbers are low)'),
  allow_values: z.array(z.string()).optional()
    .describe('Known non-PII values to ignore, e.g. your support phone number'),
  allow_patterns: z.array(z.string()).optional()
    .describe('Regular expressions; matching values are ignored, e.g. "@yourcompany\\.com$"'),
});

export const PromptInjectionConfigSchema = z.object({
  detection_methods: z.array(z.enum(VALID_DETECTION_METHODS, {
    errorMap: () => ({ message: `Invalid detection method. Expected one of: ${VALID_DETECTION_METHODS.join(', ')}` }),
  })).default(['heuristic']),
  canary_tokens: z.array(z.string()).optional(),
  sensitivity: z.enum(VALID_SENSITIVITIES, {
    errorMap: () => ({ message: `Invalid sensitivity. Expected one of: ${VALID_SENSITIVITIES.join(', ')}` }),
  }).default('medium'),
  check_input: z.boolean().default(false)
    .describe('Scan the test input for attack patterns. Off by default: in a release gate the input IS the attack'),
  check_output: z.boolean().default(true)
    .describe('Scan the model output for compliance with the attack, echoed delimiters and leaked canaries'),
  llm_config: z.object({
    model: z.string().optional(),
    api_key: z.string().optional(),
  }).optional(),
}).optional();

export const CustomEvaluatorConfigSchema = z.object({
  function: z.string().min(1).optional()
    .describe('Inline JavaScript function source, e.g. "({ output }) => ({ passed: output.length < 500 })"'),
  script: z.string().min(1).optional()
    .describe('Path to a .js/.mjs/.cjs file exporting an evaluate function'),
  webhook: z.string().url('Webhook must be a valid URL').optional()
    .describe('HTTP endpoint that receives { input, output, expected, config } and returns { passed, ... }'),
  timeout_ms: z.number().positive().default(30000),
  context: z.record(z.unknown()).optional()
    .describe('Arbitrary data passed to the evaluator as `config`'),
}).refine(
  (cfg) => [cfg.function, cfg.script, cfg.webhook].filter(Boolean).length === 1,
  { message: 'Custom evaluator config must specify exactly one of: function, script, webhook' }
);

// =============================================================================
// Test Case Schemas (Discriminated Union)
// =============================================================================

const TestCaseBaseSchema = z.object({
  name: z.string().min(1, 'Test case name is required'),
  input: z.string().min(1, 'Test case input is required'),
  description: z.string().optional(),
  tags: z.array(z.string()).optional(),
  timeout_ms: z.number().positive().optional(),
});

export const ExactMatchTestCaseSchema = TestCaseBaseSchema.extend({
  evaluator: z.literal('exact-match'),
  expected: z.string().min(1, 'Expected output is required for exact-match'),
  config: ExactMatchConfigSchema,
});

export const ContainsTestCaseSchema = TestCaseBaseSchema.extend({
  evaluator: z.literal('contains'),
  expected: z.array(z.string()).min(1, 'At least one expected term is required'),
  config: ContainsConfigSchema,
});

export const LLMJudgeTestCaseSchema = TestCaseBaseSchema.extend({
  evaluator: z.literal('llm-judge'),
  criteria: z.string().min(10, 'Evaluation criteria must be at least 10 characters'),
  config: LLMJudgeConfigSchema,
});

export const PIITestCaseSchema = TestCaseBaseSchema.extend({
  evaluator: z.literal('pii'),
  config: PIIConfigSchema,
});

export const PromptInjectionTestCaseSchema = TestCaseBaseSchema.extend({
  evaluator: z.literal('prompt-injection'),
  config: PromptInjectionConfigSchema,
});

export const CustomTestCaseSchema = TestCaseBaseSchema.extend({
  evaluator: z.literal('custom'),
  config: CustomEvaluatorConfigSchema,
});

export const TestCaseSchema = z.discriminatedUnion('evaluator', [
  ExactMatchTestCaseSchema,
  ContainsTestCaseSchema,
  LLMJudgeTestCaseSchema,
  PIITestCaseSchema,
  PromptInjectionTestCaseSchema,
  CustomTestCaseSchema,
]);

// =============================================================================
// Suite Schema
// =============================================================================

export const SuiteSchema = z.object({
  name: z.string().min(1, 'Suite name is required'),
  description: z.string().optional(),
  tags: z.array(z.string()).optional(),
  cases: z.array(TestCaseSchema).min(1, 'Suite must have at least one test case'),
});

// =============================================================================
// Provider Schemas (Discriminated Union)
// =============================================================================

const ProviderBaseSchema = z.object({
  temperature: z.number().min(0).max(2).optional(),
  max_tokens: z.number().positive().optional(),
  timeout_ms: z.number().positive().default(60000),
});

export const OpenAIProviderSchema = ProviderBaseSchema.extend({
  name: z.literal('openai'),
  model: z.string().min(1, 'Model is required'),
  api_key: z.string().optional().describe('Falls back to OPENAI_API_KEY env var'),
  base_url: z.string().url().optional(),
});

export const AnthropicProviderSchema = ProviderBaseSchema.extend({
  name: z.literal('anthropic'),
  model: z.string().min(1, 'Model is required'),
  api_key: z.string().optional().describe('Falls back to ANTHROPIC_API_KEY env var'),
});

export const AzureProviderSchema = ProviderBaseSchema.extend({
  name: z.literal('azure'),
  deployment: z.string().min(1, 'Deployment name is required'),
  endpoint: z.string().url('Must be a valid Azure endpoint URL'),
  api_key: z.string().optional().describe('Falls back to AZURE_OPENAI_API_KEY env var'),
  api_version: z.string().default('2024-02-15-preview'),
});

export const CustomProviderSchema = z.object({
  name: z.literal('custom'),
  endpoint: z.string().url('Must be a valid custom provider URL'),
  headers: z.record(z.string()).optional(),
  config: z.record(z.unknown()).optional(),
});

export const ProviderSchema = z.discriminatedUnion('name', [
  OpenAIProviderSchema,
  AnthropicProviderSchema,
  AzureProviderSchema,
  CustomProviderSchema,
]);

// =============================================================================
// Thresholds Schema
// =============================================================================

export const SuiteThresholdSchema = z.object({
  pass_rate: z.number().min(0).max(1).optional(),
  average_score: z.number().min(0).max(1).optional(),
});

export const ThresholdsSchema = z.object({
  pass_rate: z.number()
    .min(0, 'Pass rate must be at least 0')
    .max(1, 'Pass rate must be at most 1 (use 0.95 for 95%)')
    .optional(),
  average_score: z.number()
    .min(0, 'Average score must be at least 0')
    .max(1, 'Average score must be at most 1')
    .optional(),
  per_suite: z.record(z.string(), SuiteThresholdSchema).optional(),
  max_pii_incidents: z.number().int().min(0).optional(),
  max_prompt_injection_attempts: z.number().int().min(0).optional(),
  max_latency_ms: z.number().positive().optional(),
  max_cost_usd: z.number().positive().optional(),
  max_tokens: z.number().int().positive().optional(),
}).optional();

// =============================================================================
// Output Schema
// =============================================================================

export const OutputSchema = z.object({
  format: z.enum(VALID_OUTPUT_FORMATS, {
    errorMap: () => ({ message: `Invalid output format. Expected one of: ${VALID_OUTPUT_FORMATS.join(', ')}` }),
  }).default('json'),
  path: z.string().default('./results.json'),
  verbose: z.boolean().default(false),
}).optional();

// =============================================================================
// Upload Schema
// =============================================================================

export const UploadSchema = z.object({
  enabled: z.boolean().default(true),
  api_url: z.string().url().default('https://api.releasegate.dev'),
  api_key: z.string().optional().describe('Falls back to RELEASEGATE_API_KEY env var'),
}).optional();

// =============================================================================
// Project Schema
// =============================================================================

export const ProjectSchema = z.object({
  id: z.string().optional().describe('Project ID from dashboard'),
  name: z.string().min(1, 'Project name is required'),
  description: z.string().optional(),
});

// =============================================================================
// Root Config Schema
// =============================================================================

export const ConfigSchema = z.object({
  version: z.literal('1').describe('Config version, must be "1"'),
  project: ProjectSchema,
  provider: ProviderSchema,
  suites: z.array(SuiteSchema).min(1, 'At least one suite is required'),
  thresholds: ThresholdsSchema,
  output: OutputSchema,
  upload: UploadSchema,
});

// =============================================================================
// Type Inference
// =============================================================================

// Inferred types from Zod schemas - these are the source of truth
export type PIIEntityType = z.infer<typeof PIIEntityTypeSchema>;
export type Config = z.infer<typeof ConfigSchema>;
export type ConfigInput = z.input<typeof ConfigSchema>;
export type Suite = z.infer<typeof SuiteSchema>;
export type TestCase = z.infer<typeof TestCaseSchema>;
export type ProviderConfig = z.infer<typeof ProviderSchema>;
export type Thresholds = z.infer<typeof ThresholdsSchema>;
export type ProjectConfig = z.infer<typeof ProjectSchema>;

// =============================================================================
// Validation Helpers
// =============================================================================

export interface ValidationError {
  path: string;
  message: string;
}

export interface ValidationResult {
  success: boolean;
  data?: Config;
  errors?: ValidationError[];
}

/**
 * Validate a config object and return structured errors
 */
export function validateConfig(config: unknown): ValidationResult {
  const result = ConfigSchema.safeParse(config);

  if (result.success) {
    return { success: true, data: result.data };
  }

  const errors: ValidationError[] = result.error.errors.map((err) => ({
    path: err.path.join('.'),
    message: err.message,
  }));

  return { success: false, errors };
}

/**
 * Format validation errors for CLI output
 */
export function formatValidationErrors(errors: ValidationError[]): string {
  const lines = ['Configuration validation failed:', ''];

  for (const error of errors) {
    const path = error.path || '(root)';
    lines.push(`  ✗ ${path}: ${error.message}`);
  }

  lines.push('');
  lines.push('See https://docs.releasegate.dev/configuration for help.');

  return lines.join('\n');
}
