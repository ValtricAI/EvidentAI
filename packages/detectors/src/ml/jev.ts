/**
 * Jev (TypeSafe AI) classifier backend.
 *
 * Jev is a non-generative "decision model": you send a `state` (the text)
 * and typed `questions` (choice / score / noul) and get typed answers back.
 *
 * STATUS: written against the public description of the API
 * (POST https://api.typesafe.ai/v1/systemone, Bearer key from
 * TYPESAFE_API_KEY, body {model, state, questions}). The response schema has
 * NOT been verified against the live service, so the parser searches a list
 * of likely paths for the numeric answer and falls back to the choice answer.
 * Override `scorePaths`, `scoreQuestion` and `choiceQuestion` once you have a
 * key and a real response in hand. The raw response is always returned.
 */

import {
  MLClassifierError,
  clamp01,
  getPath,
  type JevClassifierConfig,
  type MLClassifier,
  type MLClassifyResult,
} from './types';

const CHOICES = ['injection', 'benign'] as const;

export class JevClassifier implements MLClassifier {
  readonly name = 'jev';

  constructor(private readonly config: JevClassifierConfig) {}

  private apiKey(): string {
    const key = this.config.apiKey || process.env.TYPESAFE_API_KEY;
    if (!key) {
      throw new MLClassifierError('Jev backend needs an API key: set TYPESAFE_API_KEY or ml.apiKey', 'jev');
    }
    return key;
  }

  buildRequest(text: string): Record<string, unknown> {
    return {
      model: this.config.model,
      state: text,
      questions: [
        { id: 'score', type: 'score', question: this.config.scoreQuestion, min: 0, max: 1 },
        { id: 'choice', type: 'choice', question: this.config.choiceQuestion, choices: [...CHOICES] },
      ],
    };
  }

  /** Exposed for tests: turn a response body into a score. */
  parseScore(json: unknown): number {
    for (const path of this.config.scorePaths) {
      const value = getPath(json, path);
      const numeric = typeof value === 'number' ? value : typeof value === 'string' ? Number(value) : NaN;
      if (Number.isFinite(numeric)) {
        // Scores may come back as 0..1 or 0..100.
        return clamp01(numeric > 1 ? numeric / 100 : numeric);
      }
    }

    // Fall back to the choice answer anywhere in the response.
    const choice = findChoice(json);
    if (choice === 'injection') return 0.95;
    if (choice === 'benign') return 0.05;

    throw new MLClassifierError(
      `Could not find a score in the Jev response (tried ${this.config.scorePaths.join(', ')}). ` +
        'Set ml.scorePaths to the correct path for your account; the raw response is attached.',
      'jev',
      json
    );
  }

  async classify(text: string): Promise<MLClassifyResult> {
    const start = performance.now();
    const apiKey = this.apiKey();
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.config.timeoutMs);

    try {
      const response = await fetch(this.config.url, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${apiKey}`,
        },
        body: JSON.stringify(this.buildRequest(text)),
        signal: controller.signal,
      });

      if (!response.ok) {
        throw new MLClassifierError(`Jev returned ${response.status}: ${(await response.text()).slice(0, 200)}`, 'jev');
      }

      const json: unknown = await response.json();
      const score = this.parseScore(json);
      const resolvedModel = getPath(json, 'model');

      return {
        score,
        label: score >= 0.5 ? 'injection' : 'benign',
        latencyMs: performance.now() - start,
        model: typeof resolvedModel === 'string' ? resolvedModel : this.config.model,
        raw: json,
      };
    } catch (error) {
      if (error instanceof MLClassifierError) throw error;
      const reason = error instanceof Error && error.name === 'AbortError' ? `timed out after ${this.config.timeoutMs}ms` : String(error);
      throw new MLClassifierError(`Jev request failed: ${reason}`, 'jev', error);
    } finally {
      clearTimeout(timer);
    }
  }
}

function findChoice(value: unknown, depth = 0): (typeof CHOICES)[number] | undefined {
  if (depth > 6 || value === null || value === undefined) return undefined;
  if (typeof value === 'string') {
    const lower = value.trim().toLowerCase();
    return CHOICES.find((c) => c === lower);
  }
  if (Array.isArray(value)) {
    for (const item of value) {
      const hit = findChoice(item, depth + 1);
      if (hit) return hit;
    }
    return undefined;
  }
  if (typeof value === 'object') {
    for (const [key, item] of Object.entries(value as Record<string, unknown>)) {
      if (/question|prompt|state/i.test(key)) continue; // skip echoed inputs
      const hit = findChoice(item, depth + 1);
      if (hit) return hit;
    }
  }
  return undefined;
}
