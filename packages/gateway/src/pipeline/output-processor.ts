/**
 * Output Processing Pipeline
 *
 * Detects and redacts PII in LLM responses using the shared
 * `@evidentai/detectors` library.
 */

import {
  detectPII as detectPIIShared,
  redactPII as redactPIIShared,
  type Confidence,
  type PIIEntityType,
  type PIIMatch,
} from '@evidentai/detectors';
import type { OutputProcessingResult } from '../types.js';

// =============================================================================
// Configuration
// =============================================================================

export interface OutputProcessorConfig {
  /** PII types to detect */
  piiTypes: PIIEntityType[];
  /** Action to take on detection */
  action: 'block' | 'redact' | 'log';
  /** Ignore matches below this confidence. Default `medium`. */
  minConfidence?: Confidence;
  /** Known non-PII values (support numbers, company addresses) */
  allowValues?: string[];
  /** Regular expressions whose matches are not PII (e.g. "@yourcompany\\.com$") */
  allowPatterns?: string[];
}

// =============================================================================
// Detection and Redaction
// =============================================================================

export function detectPII(
  text: string,
  typesToDetect: PIIEntityType[],
  options: Pick<OutputProcessorConfig, 'minConfidence' | 'allowValues' | 'allowPatterns'> = {}
): PIIMatch[] {
  return detectPIIShared(text, typesToDetect, {
    minConfidence: options.minConfidence ?? 'medium',
    allowValues: options.allowValues,
    allowPatterns: options.allowPatterns,
  });
}

export function redactPII(text: string, matches: PIIMatch[]): string {
  return redactPIIShared(text, matches, {
    placeholder: (m) => `[PII:${m.type.toUpperCase()}]`,
  });
}

// =============================================================================
// Main Processing Function
// =============================================================================

export async function processOutput(
  content: string,
  config: OutputProcessorConfig
): Promise<OutputProcessingResult> {
  const startTime = Date.now();

  const matches = detectPII(content, config.piiTypes, config);
  const piiDetected = matches.length > 0;

  let blocked = false;
  let blockReason: string | undefined;
  let processed = content;

  if (piiDetected) {
    switch (config.action) {
      case 'block': {
        blocked = true;
        const types = [...new Set(matches.map((m) => m.type))];
        blockReason = `Response blocked due to PII: ${types.join(', ')}`;
        break;
      }

      case 'redact': {
        processed = redactPII(content, matches);
        break;
      }

      case 'log':
        // Report only, do not modify
        break;
    }
  }

  return {
    original: content,
    processed,
    piiDetected,
    piiMatches: matches,
    blocked,
    blockReason,
    latencyMs: Date.now() - startTime,
  };
}
