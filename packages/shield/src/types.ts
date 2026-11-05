/**
 * Shield Types - Runtime LLM Protection
 */

import type { MLClassifier, MLClassifierConfig } from '@evidentai/detectors';

export type ThreatLevel = 'none' | 'low' | 'medium' | 'high' | 'critical';

export type AnalyzerType = 'heuristic' | 'ml' | 'llm-judge';

export interface ThreatDetection {
  /** Whether a threat was detected */
  detected: boolean;
  /** Severity level of the threat */
  level: ThreatLevel;
  /** Confidence score 0-1 */
  confidence: number;
  /** Which analyzer detected the threat */
  analyzer: AnalyzerType;
  /** Human-readable reason */
  reason: string;
  /** Specific patterns or indicators found */
  indicators: string[];
  /** Time taken to analyze in ms */
  latencyMs: number;
  /** Classifier probability of injection (ml analyzer only) */
  score?: number;
  /** Set when the analyzer failed and the shield fell open or closed */
  error?: string;
}

export interface DeferralRecord {
  /** Why the request was deferred to the LLM judge */
  reason: string;
  /** The ml score that fell inside the deferral band */
  mlScore: number;
  /** The level the judge returned */
  judgeLevel: ThreatLevel;
}

export interface AnalysisResult {
  /** Unique request ID for tracing */
  requestId: string;
  /** The input that was analyzed */
  input: string;
  /** Combined threat assessment */
  threat: ThreatDetection;
  /** Individual analyzer results */
  analyzerResults: ThreatDetection[];
  /** Whether the request should be blocked */
  blocked: boolean;
  /** Total analysis time in ms */
  totalLatencyMs: number;
  /** Timestamp */
  timestamp: string;
  /** Present when the ml score was uncertain and the LLM judge decided */
  deferred?: DeferralRecord;
}

/** Options for the `ml` analyzer: a classifier backend plus score cut points. */
export type MLAnalyzerConfig = MLClassifierConfig & {
  /** Score at or above which the threat is `critical`. Default 0.9 */
  criticalAbove?: number;
  /** Decision threshold: at or above is `high`. Default 0.5 */
  threshold?: number;
  /** At or above is `medium` (suspicious). Default 0.3 */
  mediumAbove?: number;
  /**
   * When the classifier errors: false (default) fails open and reports
   * level `none` with the error; true fails closed and reports `critical`.
   */
  failClosed?: boolean;
};

export interface DeferralConfig {
  /** Escalate uncertain ml scores to the llm-judge. Default false */
  enabled: boolean;
  /** Lower bound of the uncertainty band (inclusive). Default 0.3 */
  lower: number;
  /** Upper bound of the uncertainty band (exclusive). Default 0.7 */
  upper: number;
}

export interface ShieldConfig {
  /** Enable/disable the shield */
  enabled: boolean;
  /** Minimum threat level to block (default: 'high') */
  blockThreshold: ThreatLevel;
  /** Which analyzers to use */
  analyzers: AnalyzerType[];
  /** Log all requests (for debugging) */
  logAll: boolean;
  /** Custom callback when threat detected */
  onThreat?: (result: AnalysisResult) => void | Promise<void>;
  /** Custom callback when request blocked */
  onBlock?: (result: AnalysisResult) => void | Promise<void>;
  /** LLM configuration for llm-judge analyzer */
  llm?: {
    provider: 'openai' | 'anthropic' | 'custom';
    model?: string;
    apiKey?: string;
    endpoint?: string;
  };
  /** Heuristic analyzer options */
  heuristic?: {
    /** Custom patterns to detect (regex strings) */
    customPatterns?: string[];
    /** Sensitivity: 'low' | 'medium' | 'high' */
    sensitivity?: 'low' | 'medium' | 'high';
  };
  /** ml analyzer options */
  ml?: MLAnalyzerConfig;
  /** Escalate uncertain ml scores to the llm-judge */
  deferral?: DeferralConfig;
  /**
   * Build the classifier yourself instead of letting the shield create one
   * from `ml`. Mainly for tests and in-process models.
   */
  classifierFactory?: (config: MLAnalyzerConfig) => MLClassifier;
}

export interface Analyzer {
  name: AnalyzerType;
  analyze(input: string, config: ShieldConfig): Promise<ThreatDetection>;
}

/** Request context passed to middleware */
export interface RequestContext {
  /** The user's input/prompt */
  input: string;
  /** Optional user ID for rate limiting */
  userId?: string;
  /** Optional session ID */
  sessionId?: string;
  /** Any additional metadata */
  metadata?: Record<string, unknown>;
}
