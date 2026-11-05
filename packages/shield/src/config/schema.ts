import { z } from 'zod';
import { MLClassifierConfigSchema } from '@evidentai/detectors';

export const ThreatLevelSchema = z.enum(['none', 'low', 'medium', 'high', 'critical']);

export const AnalyzerTypeSchema = z.enum(['heuristic', 'ml', 'llm-judge']);

export const LLMConfigSchema = z.object({
  provider: z.enum(['openai', 'anthropic', 'custom']),
  model: z.string().optional(),
  apiKey: z.string().optional(),
  endpoint: z.string().url().optional(),
});

export const HeuristicConfigSchema = z.object({
  customPatterns: z.array(z.string()).optional(),
  sensitivity: z.enum(['low', 'medium', 'high']).optional().default('medium'),
});

const MLCutpointsSchema = z.object({
  criticalAbove: z.number().min(0).max(1).optional(),
  threshold: z.number().min(0).max(1).optional(),
  mediumAbove: z.number().min(0).max(1).optional(),
  failClosed: z.boolean().optional(),
});

/**
 * The ml config is a classifier backend config (discriminated on `backend`)
 * plus cut points. Zod cannot extend a discriminated union directly, so the
 * two are validated separately and merged.
 */
export const MLConfigSchema = z
  .object({ backend: z.enum(['transformers', 'http', 'jev', 'custom']) })
  .passthrough()
  .superRefine((value, ctx) => {
    const { criticalAbove: _c, threshold: _t, mediumAbove: _m, failClosed: _f, ...classifier } = value as Record<string, unknown>;
    const classifierResult = MLClassifierConfigSchema.safeParse(classifier);
    if (!classifierResult.success) {
      for (const issue of classifierResult.error.issues) ctx.addIssue(issue);
    }
    const cutResult = MLCutpointsSchema.safeParse(value);
    if (!cutResult.success) {
      for (const issue of cutResult.error.issues) ctx.addIssue(issue);
    }
  });

export const DeferralConfigSchema = z
  .object({
    enabled: z.boolean().default(false),
    lower: z.number().min(0).max(1).default(0.3),
    upper: z.number().min(0).max(1).default(0.7),
  })
  .refine((d) => d.lower < d.upper, { message: 'deferral.lower must be less than deferral.upper' });

export const ShieldConfigSchema = z.object({
  enabled: z.boolean().default(true),
  blockThreshold: ThreatLevelSchema.default('high'),
  analyzers: z.array(AnalyzerTypeSchema).default(['heuristic']),
  logAll: z.boolean().default(false),
  // Callbacks are typed at runtime, use passthrough for Zod
  onThreat: z.any().optional(),
  onBlock: z.any().optional(),
  llm: LLMConfigSchema.optional(),
  heuristic: HeuristicConfigSchema.optional(),
  ml: MLConfigSchema.optional(),
  deferral: DeferralConfigSchema.optional(),
  classifierFactory: z.any().optional(),
});

export type ShieldConfigInput = z.input<typeof ShieldConfigSchema>;
export type ShieldConfigParsed = z.output<typeof ShieldConfigSchema>;

export function parseConfig(config: ShieldConfigInput): ShieldConfigParsed {
  return ShieldConfigSchema.parse(config);
}

export function validateConfig(config: unknown): { valid: boolean; errors?: string[] } {
  const result = ShieldConfigSchema.safeParse(config);
  if (result.success) {
    return { valid: true };
  }
  return {
    valid: false,
    errors: result.error.errors.map((e) => `${e.path.join('.')}: ${e.message}`),
  };
}
