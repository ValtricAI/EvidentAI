/**
 * Generic HTTP classifier: POST {text} to your own endpoint, read a score.
 */

import {
  MLClassifierError,
  clamp01,
  getPath,
  type HttpClassifierConfig,
  type MLClassifier,
  type MLClassifyResult,
} from './types';

export class HttpClassifier implements MLClassifier {
  readonly name = 'http';

  constructor(private readonly config: HttpClassifierConfig) {}

  async classify(text: string): Promise<MLClassifyResult> {
    const start = performance.now();
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.config.timeoutMs);

    try {
      const response = await fetch(this.config.url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', ...(this.config.headers ?? {}) },
        body: JSON.stringify({ [this.config.textField]: text }),
        signal: controller.signal,
      });

      if (!response.ok) {
        throw new MLClassifierError(
          `Classifier endpoint returned ${response.status}: ${(await response.text()).slice(0, 200)}`,
          'http'
        );
      }

      const json: unknown = await response.json();
      const value = getPath(json, this.config.scorePath);
      const score = typeof value === 'number' ? value : typeof value === 'string' ? Number(value) : NaN;
      if (!Number.isFinite(score)) {
        throw new MLClassifierError(
          `Classifier response has no numeric value at "${this.config.scorePath}"`,
          'http'
        );
      }

      const clamped = clamp01(score);
      return {
        score: clamped,
        label: clamped >= 0.5 ? 'injection' : 'benign',
        latencyMs: performance.now() - start,
        model: this.config.model ?? this.config.url,
        raw: json,
      };
    } catch (error) {
      if (error instanceof MLClassifierError) throw error;
      const reason = error instanceof Error && error.name === 'AbortError' ? `timed out after ${this.config.timeoutMs}ms` : String(error);
      throw new MLClassifierError(`Classifier request failed: ${reason}`, 'http', error);
    } finally {
      clearTimeout(timer);
    }
  }
}
