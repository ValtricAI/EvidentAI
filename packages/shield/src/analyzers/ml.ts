import {
  createClassifier,
  scoreToSeverity,
  type MLClassifier,
  type MLClassifierConfig,
} from '@evidentai/detectors';
import type { Analyzer, MLAnalyzerConfig, ShieldConfig, ThreatDetection, ThreatLevel } from '../types.js';

/**
 * ML Analyzer - Layer 2
 *
 * Runs a learned classifier (local ONNX model, your own HTTP endpoint, or
 * TypeSafe's Jev) and maps P(injection) onto threat levels:
 *
 *   score >= criticalAbove (0.9) -> critical
 *   score >= threshold     (0.5) -> high
 *   score >= mediumAbove   (0.3) -> medium
 *   otherwise                    -> none
 *
 * The classifier is built once per distinct `ml` config and cached. By
 * default the analyzer fails OPEN: a classifier error yields level `none`
 * with the error recorded, so a model outage never takes your application
 * down with it. Set `ml.failClosed: true` to block on errors instead.
 */
export class MLAnalyzer implements Analyzer {
  name = 'ml' as const;

  /** Built-in backends, keyed by their serialised config. */
  private readonly cache = new Map<string, MLClassifier>();
  /** Factory-built classifiers, keyed by factory identity then config. */
  private readonly factoryCache = new WeakMap<object, Map<string, MLClassifier>>();

  async analyze(input: string, config: ShieldConfig): Promise<ThreatDetection> {
    const startTime = performance.now();
    const mlConfig = config.ml;

    if (!mlConfig) {
      return {
        detected: false,
        level: 'none',
        confidence: 0,
        analyzer: 'ml',
        reason: 'ml analyzer not configured (set config.ml)',
        indicators: [],
        latencyMs: performance.now() - startTime,
        error: 'ml analyzer not configured',
      };
    }

    let classifier: MLClassifier;
    try {
      classifier = this.getClassifier(mlConfig, config.classifierFactory);
      const result = await classifier.classify(input);
      const level = scoreToSeverity(result.score, {
        criticalAbove: mlConfig.criticalAbove,
        threshold: mlConfig.threshold,
        mediumAbove: mlConfig.mediumAbove,
      }) as ThreatLevel;

      const detected = level !== 'none';
      return {
        detected,
        level,
        confidence: detected ? result.score : 1 - result.score,
        analyzer: 'ml',
        reason: detected
          ? `Classifier ${classifier.name} scored ${result.score.toFixed(3)} (${result.model})`
          : 'No threats detected',
        indicators: detected ? [`ml: ${classifier.name} score ${result.score.toFixed(3)}`] : [],
        latencyMs: performance.now() - startTime,
        score: result.score,
      };
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      if (mlConfig.failClosed) {
        return {
          detected: true,
          level: 'critical',
          confidence: 0,
          analyzer: 'ml',
          reason: `Classifier unavailable and ml.failClosed is set: ${message}`,
          indicators: ['ml: classifier error (fail closed)'],
          latencyMs: performance.now() - startTime,
          error: message,
        };
      }
      return {
        detected: false,
        level: 'none',
        confidence: 0,
        analyzer: 'ml',
        reason: `Classifier unavailable, failing open: ${message}`,
        indicators: [],
        latencyMs: performance.now() - startTime,
        error: message,
      };
    }
  }

  /** Drop cached classifiers (tests, hot reconfiguration). */
  reset(): void {
    this.cache.clear();
  }

  private getClassifier(
    mlConfig: MLAnalyzerConfig,
    factory?: (config: MLAnalyzerConfig) => MLClassifier
  ): MLClassifier {
    const { criticalAbove: _c, threshold: _t, mediumAbove: _m, failClosed: _f, ...classifierConfig } = mlConfig;
    const key = JSON.stringify(classifierConfig);

    if (factory) {
      let perFactory = this.factoryCache.get(factory);
      if (!perFactory) {
        perFactory = new Map();
        this.factoryCache.set(factory, perFactory);
      }
      let classifier = perFactory.get(key);
      if (!classifier) {
        classifier = factory(mlConfig);
        perFactory.set(key, classifier);
      }
      return classifier;
    }

    let classifier = this.cache.get(key);
    if (!classifier) {
      classifier = createClassifier(classifierConfig as MLClassifierConfig);
      this.cache.set(key, classifier);
    }
    return classifier;
  }
}

export const mlAnalyzer = new MLAnalyzer();
