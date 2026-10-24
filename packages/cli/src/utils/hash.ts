/**
 * Config Hashing
 *
 * Creates a deterministic hash of the configuration for change detection.
 * This allows tracking which config version produced each run.
 */

import { createHash } from 'crypto';
import type { Config } from '../config/types';
import { getConfig, getCriteria, getExpected } from '../runner/executor';

/**
 * Create a SHA256 hash of the configuration
 * Returns a string in format "sha256:<hash>"
 */
export function hashConfig(config: Config): string {
  // Create a normalized version of the config for consistent hashing
  const normalized = normalizeConfig(config);
  const json = JSON.stringify(normalized, Object.keys(normalized).sort());

  const hash = createHash('sha256').update(json, 'utf-8').digest('hex');

  return `sha256:${hash.substring(0, 16)}`; // Use first 16 chars for brevity
}

/**
 * Normalize config for consistent hashing
 * Removes runtime-specific values like API keys
 */
function normalizeConfig(config: Config): object {
  return {
    version: config.version,
    project: {
      name: config.project.name,
      // Exclude id as it may change
    },
    provider: {
      name: config.provider.name,
      model: (config.provider as { model?: string }).model,
      // Exclude api_key
    },
    suites: config.suites.map((suite) => ({
      name: suite.name,
      cases: suite.cases.map((c) => ({
        name: c.name,
        input: c.input,
        evaluator: c.evaluator,
        expected: getExpected(c),
        criteria: getCriteria(c),
        config: getConfig(c),
      })),
    })),
    thresholds: config.thresholds,
  };
}

/**
 * Generic hash function for any string
 */
export function hash(input: string): string {
  return createHash('sha256').update(input, 'utf-8').digest('hex');
}

export default hashConfig;
