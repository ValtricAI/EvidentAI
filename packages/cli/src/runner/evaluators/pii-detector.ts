/**
 * PII Detector Evaluator
 *
 * Fails a test when the model output contains personally identifiable
 * information of the configured types.
 *
 * Patterns live in `@evidentai/detectors` and are shared with the gateway.
 * Every match carries a confidence; `min_confidence` (default `medium`) hides
 * weak matches such as private IP ranges and bare 10-digit numbers, and
 * `allow_values` / `allow_patterns` whitelist values that are known not to be
 * personal data (a support line, a company address, a documentation domain).
 */

import {
  detectPII,
  redactPII,
  type Confidence,
  type PIIEntityType,
  type PIIMatch,
} from '@evidentai/detectors';
import type { EvaluatorResult } from '../../config/types';
import type { Evaluator, EvaluatorContext } from './index';

export interface PIIConfig {
  fail_on: PIIEntityType[];
  allow?: PIIEntityType[];
  redact?: boolean;
  min_confidence?: Confidence;
  allow_values?: string[];
  allow_patterns?: string[];
}

export class PIIDetectorEvaluator implements Evaluator {
  name = 'pii' as const;

  async evaluate(ctx: EvaluatorContext): Promise<EvaluatorResult> {
    const config = (ctx.config || {}) as unknown as PIIConfig;

    if (!config.fail_on || config.fail_on.length === 0) {
      return {
        passed: false,
        score: 0,
        reason: 'No PII types specified in fail_on config',
      };
    }

    // Determine which types to detect (fail_on minus allow)
    const allowSet = new Set(config.allow || []);
    const typesToDetect = config.fail_on.filter((t) => !allowSet.has(t));

    const matches = detectPII(ctx.output, typesToDetect, {
      minConfidence: config.min_confidence ?? 'medium',
      allowValues: config.allow_values,
      allowPatterns: config.allow_patterns,
    });

    // Group by type
    const byType: Record<string, PIIMatch[]> = {};
    for (const match of matches) {
      const bucket = byType[match.type] ?? [];
      bucket.push(match);
      byType[match.type] = bucket;
    }

    const passed = matches.length === 0;

    let reason: string;
    if (passed) {
      reason = `No PII detected in output (checked: ${typesToDetect.join(', ')})`;
    } else {
      const summary = Object.entries(byType)
        .map(([type, typeMatches]) => `${type}: ${typeMatches.length}`)
        .join(', ');
      reason = `PII detected: ${summary}`;
    }

    const details: Record<string, unknown> = {
      types_checked: typesToDetect,
      types_allowed: config.allow || [],
      min_confidence: config.min_confidence ?? 'medium',
      matches: matches.map((m) => ({
        type: m.type,
        value: config.redact ? '[REDACTED]' : m.value.substring(0, 4) + '***',
        confidence: m.confidence,
      })),
      total_matches: matches.length,
    };

    if (config.redact && matches.length > 0) {
      details.redacted_output = redactPII(ctx.output, matches);
    }

    return {
      passed,
      score: passed ? 1.0 : 0.0,
      reason,
      details,
    };
  }
}
