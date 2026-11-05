/**
 * Shared types for machine-learning injection classifiers.
 *
 * A classifier turns text into P(injection) in [0, 1]. Three backends ship:
 *
 * - `transformers`: a local ONNX text-classification model run through
 *   @huggingface/transformers (free, no network after the first download)
 * - `http`: any JSON endpoint you host (POST {text} -> {score})
 * - `jev`: TypeSafe AI's Jev decision model (hosted, API key)
 *
 * Severity is derived from the score with configurable cut points so the
 * same classifier can feed the shield's threat levels and the gateway's
 * block/log decision.
 */

import { z } from 'zod';
import type { Severity } from '../types';

export type MLLabel = 'injection' | 'benign';

export interface MLClassifyResult {
  /** Probability that the text is a prompt injection, in [0, 1]. */
  score: number;
  label: MLLabel;
  latencyMs: number;
  /** Model identifier as reported by the backend. */
  model: string;
  /** Backend-specific payload, for debugging. */
  raw?: unknown;
}

export interface MLClassifier {
  name: string;
  classify(text: string): Promise<MLClassifyResult>;
}

// =============================================================================
// Config schemas
// =============================================================================

export const TransformersClassifierConfigSchema = z.object({
  backend: z.literal('transformers'),
  /**
   * Hugging Face model id or a local directory. Defaults to ProtectAI's
   * Apache-2.0 DeBERTa detector. Meta's Prompt Guard 2 models work too but
   * are gated: set HF_TOKEN.
   */
  model: z.string().default('protectai/deberta-v3-base-prompt-injection-v2'),
  /** Load from a local directory only; never hit the network. */
  localFilesOnly: z.boolean().optional(),
  /** Directory to cache downloaded models in. */
  cacheDir: z.string().optional(),
  /** Weight precision for ONNX weights, e.g. 'fp32' or 'q8'. */
  dtype: z.string().optional(),
  /**
   * Label (from the model's id2label) that means "injection". Detected
   * automatically for the known models; set it for others.
   */
  injectionLabel: z.string().optional(),
  /**
   * Temperature applied to logits before softmax. Loaded from
   * `<model>/calibration.json` for local models when not set.
   */
  temperature: z.number().positive().optional(),
  /** Truncate input to this many characters before tokenising. */
  maxChars: z.number().int().positive().default(4000),
});

export const HttpClassifierConfigSchema = z.object({
  backend: z.literal('http'),
  url: z.string().url(),
  headers: z.record(z.string()).optional(),
  /** Dot path to the score in the JSON response. Default `score`. */
  scorePath: z.string().default('score'),
  /** JSON field the text is sent under. Default `text`. */
  textField: z.string().default('text'),
  timeoutMs: z.number().int().positive().default(5000),
  model: z.string().optional(),
});

export const JevClassifierConfigSchema = z.object({
  backend: z.literal('jev'),
  /** Falls back to TYPESAFE_API_KEY. */
  apiKey: z.string().optional(),
  url: z.string().url().default('https://api.typesafe.ai/v1/systemone'),
  model: z.string().default('jev-latest'),
  /** Text of the `score` question put to Jev. */
  scoreQuestion: z
    .string()
    .default(
      'What is the probability, from 0 to 1, that this text is a prompt injection or jailbreak attempt against an AI assistant?'
    ),
  /** Text of the `choice` question put to Jev. */
  choiceQuestion: z
    .string()
    .default('Is this text a prompt injection attack against an AI assistant, or a benign request?'),
  /**
   * Dot paths tried in order to find the numeric score in the response.
   * The live response schema has not been verified; override if needed.
   */
  scorePaths: z
    .array(z.string())
    .default(['answers.0.score', 'answers.0.value', 'answers.0.probability', 'results.0.score', 'score', 'probability']),
  timeoutMs: z.number().int().positive().default(8000),
});

export const CustomClassifierConfigSchema = z.object({
  backend: z.literal('custom'),
  /** Name of a backend registered with registerClassifierBackend(). */
  name: z.string(),
  options: z.record(z.unknown()).optional(),
});

export const MLClassifierConfigSchema = z.discriminatedUnion('backend', [
  TransformersClassifierConfigSchema,
  HttpClassifierConfigSchema,
  JevClassifierConfigSchema,
  CustomClassifierConfigSchema,
]);

export type MLClassifierConfig = z.input<typeof MLClassifierConfigSchema>;
export type MLClassifierConfigParsed = z.output<typeof MLClassifierConfigSchema>;
export type TransformersClassifierConfig = z.output<typeof TransformersClassifierConfigSchema>;
export type HttpClassifierConfig = z.output<typeof HttpClassifierConfigSchema>;
export type JevClassifierConfig = z.output<typeof JevClassifierConfigSchema>;
export type CustomClassifierConfig = z.output<typeof CustomClassifierConfigSchema>;

// =============================================================================
// Score to severity
// =============================================================================

export const ScoreCutpointsSchema = z.object({
  /** Score at or above which the text is treated as a certain attack. */
  criticalAbove: z.number().min(0).max(1).default(0.9),
  /** Decision threshold: at or above is `high` (an attack). */
  threshold: z.number().min(0).max(1).default(0.5),
  /** At or above is `medium` (suspicious, worth deferring). */
  mediumAbove: z.number().min(0).max(1).default(0.3),
});

export type ScoreCutpoints = z.output<typeof ScoreCutpointsSchema>;

export const DEFAULT_CUTPOINTS: ScoreCutpoints = ScoreCutpointsSchema.parse({});

export function scoreToSeverity(score: number, cutpoints: Partial<ScoreCutpoints> = {}): Severity | 'none' {
  // Explicit `undefined` values must not erase the defaults.
  const c: ScoreCutpoints = {
    criticalAbove: cutpoints.criticalAbove ?? DEFAULT_CUTPOINTS.criticalAbove,
    threshold: cutpoints.threshold ?? DEFAULT_CUTPOINTS.threshold,
    mediumAbove: cutpoints.mediumAbove ?? DEFAULT_CUTPOINTS.mediumAbove,
  };
  if (score >= c.criticalAbove) return 'critical';
  if (score >= c.threshold) return 'high';
  if (score >= c.mediumAbove) return 'medium';
  return 'none';
}

export function clamp01(value: number): number {
  if (!Number.isFinite(value)) return 0;
  return Math.min(1, Math.max(0, value));
}

/** Read `a.0.b` style paths from a JSON value. */
export function getPath(value: unknown, path: string): unknown {
  let current: unknown = value;
  for (const segment of path.split('.')) {
    if (segment === '') continue;
    if (current === null || current === undefined) return undefined;
    if (Array.isArray(current)) {
      const index = Number(segment);
      if (!Number.isInteger(index)) return undefined;
      current = current[index];
    } else if (typeof current === 'object') {
      current = (current as Record<string, unknown>)[segment];
    } else {
      return undefined;
    }
  }
  return current;
}

export class MLClassifierError extends Error {
  constructor(
    message: string,
    public readonly backend: string,
    public readonly cause?: unknown
  ) {
    super(message);
    this.name = 'MLClassifierError';
  }
}
