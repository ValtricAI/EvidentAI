/**
 * @evidentai/shield
 *
 * Runtime protection for LLM applications.
 * Detect and block prompt injection attacks in real-time.
 *
 * @example
 * ```ts
 * import { Shield } from '@evidentai/shield';
 *
 * const shield = new Shield({
 *   blockThreshold: 'high',
 *   analyzers: ['heuristic', 'llm-judge'],
 *   llm: { provider: 'openai' }
 * });
 *
 * const result = await shield.analyze({
 *   input: userMessage
 * });
 *
 * if (result.blocked) {
 *   console.log('Blocked:', result.threat.reason);
 * }
 * ```
 */

import { randomUUID } from 'node:crypto';
import type {
  ShieldConfig,
  AnalysisResult,
  ThreatDetection,
  ThreatLevel,
  RequestContext,
} from './types.js';
import { getAnalyzers } from './analyzers/index.js';
import { parseConfig } from './config/schema.js';

export class Shield {
  private config: ShieldConfig;

  constructor(config: Partial<ShieldConfig> = {}) {
    this.config = parseConfig(config) as ShieldConfig;
  }

  /**
   * Analyze input for prompt injection threats.
   */
  async analyze(context: RequestContext): Promise<AnalysisResult> {
    const startTime = performance.now();
    const requestId = randomUUID();

    // If shield is disabled, return safe result
    if (!this.config.enabled) {
      return this.createSafeResult(requestId, context.input, startTime);
    }

    // Run all configured analyzers
    const analyzers = getAnalyzers(this.config.analyzers);
    const analyzerResults: ThreatDetection[] = [];

    for (const analyzer of analyzers) {
      const result = await analyzer.analyze(context.input, this.config);
      analyzerResults.push(result);

      // If critical threat found, stop early
      if (result.detected && result.level === 'critical') {
        break;
      }
    }

    // Aggregate results - use highest threat level
    const threat = this.aggregateResults(analyzerResults);
    const blocked = this.shouldBlock(threat.level);

    const result: AnalysisResult = {
      requestId,
      input: context.input,
      threat,
      analyzerResults,
      blocked,
      totalLatencyMs: performance.now() - startTime,
      timestamp: new Date().toISOString(),
    };

    // Trigger callbacks
    if (threat.detected) {
      await this.config.onThreat?.(result);
    }
    if (blocked) {
      await this.config.onBlock?.(result);
    }

    // Log if configured
    if (this.config.logAll || threat.detected) {
      this.log(result);
    }

    return result;
  }

  /**
   * Check if shield is enabled.
   */
  isEnabled(): boolean {
    return this.config.enabled;
  }

  /**
   * Enable the shield.
   */
  enable(): void {
    this.config.enabled = true;
  }

  /**
   * Disable the shield.
   */
  disable(): void {
    this.config.enabled = false;
  }

  /**
   * Update configuration.
   */
  configure(config: Partial<ShieldConfig>): void {
    this.config = parseConfig({ ...this.config, ...config }) as ShieldConfig;
  }

  /**
   * Get current configuration.
   */
  getConfig(): Readonly<ShieldConfig> {
    return { ...this.config };
  }

  private aggregateResults(results: ThreatDetection[]): ThreatDetection {
    if (results.length === 0) {
      return {
        detected: false,
        level: 'none',
        confidence: 1.0,
        analyzer: 'heuristic',
        reason: 'No analyzers ran',
        indicators: [],
        latencyMs: 0,
      };
    }

    // Find highest severity
    let highest: ThreatDetection = results[0];
    for (const result of results) {
      if (this.threatRank(result.level) > this.threatRank(highest.level)) {
        highest = result;
      }
    }

    // Aggregate indicators from all results
    const allIndicators = results.flatMap((r) => r.indicators);

    return {
      ...highest,
      indicators: [...new Set(allIndicators)], // Dedupe
    };
  }

  private shouldBlock(level: ThreatLevel): boolean {
    return this.threatRank(level) >= this.threatRank(this.config.blockThreshold);
  }

  private threatRank(level: ThreatLevel): number {
    const ranks: Record<ThreatLevel, number> = {
      none: 0,
      low: 1,
      medium: 2,
      high: 3,
      critical: 4,
    };
    return ranks[level];
  }

  private createSafeResult(
    requestId: string,
    input: string,
    startTime: number
  ): AnalysisResult {
    return {
      requestId,
      input,
      threat: {
        detected: false,
        level: 'none',
        confidence: 1.0,
        analyzer: 'heuristic',
        reason: 'Shield disabled',
        indicators: [],
        latencyMs: 0,
      },
      analyzerResults: [],
      blocked: false,
      totalLatencyMs: performance.now() - startTime,
      timestamp: new Date().toISOString(),
    };
  }

  private log(result: AnalysisResult): void {
    const emoji = result.blocked ? '🛡️ BLOCKED' : result.threat.detected ? '⚠️ THREAT' : '✅ SAFE';
    console.log(
      `[Shield] ${emoji} | ${result.threat.level.toUpperCase()} | ${result.totalLatencyMs.toFixed(1)}ms | ${result.requestId}`
    );
    if (result.threat.detected) {
      console.log(`[Shield]   Reason: ${result.threat.reason}`);
      if (result.threat.indicators.length > 0) {
        console.log(`[Shield]   Indicators: ${result.threat.indicators.join(', ')}`);
      }
    }
  }
}

// Re-export types
export type {
  ShieldConfig,
  AnalysisResult,
  ThreatDetection,
  ThreatLevel,
  RequestContext,
  AnalyzerType,
} from './types.js';

// Re-export analyzers
export { heuristicAnalyzer, llmJudgeAnalyzer, getAnalyzer, getAnalyzers } from './analyzers/index.js';

// Re-export config utilities
export { parseConfig, validateConfig } from './config/schema.js';

// Default export
export default Shield;
