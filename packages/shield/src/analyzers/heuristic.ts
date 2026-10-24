import { detectInjection, severityRank, type Severity } from '@evidentai/detectors';
import type { Analyzer, ThreatDetection, ShieldConfig, ThreatLevel } from '../types.js';

/**
 * Heuristic Analyzer - Layer 1
 *
 * Fast pattern-based detection for common prompt injection attacks. Runs in
 * well under a millisecond with no external calls.
 *
 * Patterns come from `@evidentai/detectors`, the library shared with the CLI
 * evaluator and the gateway, so tuning happens in one place. Pattern severity
 * maps directly onto the shield threat level.
 *
 * Sensitivity controls which pattern severities are consulted:
 * - `low`: critical and high only
 * - `medium` (default): adds medium severity patterns
 * - `high`: adds low severity patterns (noisy; for audits)
 */
export class HeuristicAnalyzer implements Analyzer {
  name: 'heuristic' = 'heuristic';

  async analyze(input: string, config: ShieldConfig): Promise<ThreatDetection> {
    const startTime = performance.now();
    const sensitivity = config.heuristic?.sensitivity ?? 'medium';

    const matches = detectInjection(input, {
      sensitivity,
      customPatterns: config.heuristic?.customPatterns,
    });

    const indicators: string[] = [];
    const seen = new Set<string>();
    let highestSeverity: ThreatLevel = 'none';
    let highestReason = '';

    for (const match of matches) {
      const indicator = `${match.category}: ${match.description}`;
      if (!seen.has(indicator)) {
        seen.add(indicator);
        indicators.push(indicator);
      }
      if (severityRank(match.severity) > severityRank(highestSeverity)) {
        highestSeverity = match.severity;
        highestReason = match.description;
      }
    }

    const latencyMs = performance.now() - startTime;

    return {
      detected: indicators.length > 0,
      level: highestSeverity,
      confidence: this.calculateConfidence(indicators.length, highestSeverity),
      analyzer: 'heuristic',
      reason: highestReason || 'No threats detected',
      indicators,
      latencyMs,
    };
  }

  private calculateConfidence(indicatorCount: number, severity: ThreatLevel): number {
    if (indicatorCount === 0) return 1.0; // Confident there's no threat

    // More indicators = higher confidence in detection
    const baseConfidence = Math.min(0.5 + indicatorCount * 0.15, 0.95);

    // Higher severity patterns are more reliable
    const severityBoost: Record<Severity | 'none', number> = {
      none: 0,
      low: 0,
      medium: 0.05,
      high: 0.1,
      critical: 0.15,
    };

    return Math.min(baseConfidence + severityBoost[severity], 0.99);
  }
}

export const heuristicAnalyzer = new HeuristicAnalyzer();
