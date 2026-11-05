/**
 * ML classifier step for the input pipeline.
 *
 * Runs after the regex sanitizer, over the text of every `user` message
 * concatenated in order (multi-turn injections are often split across
 * turns). System, developer, assistant and tool messages are application
 * data and are not scored.
 *
 * Fails OPEN by default: if the classifier errors, the request proceeds and
 * the error is returned for logging. Set `failClosed: true` to block instead.
 */

import { createClassifier, type MLClassifier } from '@evidentai/detectors';
import type { ChatMessage, GatewayConfig, GatewayMLConfig } from '../types.js';

export interface MLClassificationResult {
  /** P(injection) or undefined when the classifier failed */
  score?: number;
  /** Whether score >= threshold */
  flagged: boolean;
  /** Whether the request should be blocked (action block, or fail closed on error) */
  blocked: boolean;
  threshold: number;
  model: string;
  latencyMs: number;
  error?: string;
}

const classifierCache = new WeakMap<GatewayConfig, MLClassifier>();

/** Model name for logging; the `custom` backend has none. */
export function modelOf(ml: GatewayMLConfig): string {
  return 'model' in ml && typeof ml.model === 'string' ? ml.model : ml.backend;
}

export function getGatewayClassifier(config: GatewayConfig): MLClassifier | undefined {
  const mlConfig = config.input.mlClassifier;
  if (!mlConfig) return undefined;

  let classifier = classifierCache.get(config);
  if (!classifier) {
    const { action: _a, threshold: _t, failClosed: _f, ...classifierConfig } = mlConfig;
    classifier = config.classifierFactory
      ? config.classifierFactory(mlConfig)
      : createClassifier(classifierConfig as GatewayMLConfig);
    classifierCache.set(config, classifier);
  }
  return classifier;
}

/** Text of all user messages, in order. */
export function userText(messages: ChatMessage[]): string {
  const parts: string[] = [];
  for (const message of messages) {
    if (message.role !== 'user' || message.content === null) continue;
    if (typeof message.content === 'string') {
      parts.push(message.content);
    } else {
      for (const part of message.content) {
        if (typeof part.text === 'string') parts.push(part.text);
      }
    }
  }
  return parts.join('\n');
}

export async function classifyUserMessages(
  messages: ChatMessage[],
  config: GatewayConfig
): Promise<MLClassificationResult | undefined> {
  const mlConfig = config.input.mlClassifier;
  if (!mlConfig) return undefined;

  const start = Date.now();
  const threshold = mlConfig.threshold ?? 0.5;
  const action = mlConfig.action ?? 'log';
  const text = userText(messages);

  if (text.trim() === '') {
    return { flagged: false, blocked: false, threshold, model: modelOf(mlConfig), latencyMs: 0 };
  }

  try {
    const classifier = getGatewayClassifier(config);
    if (!classifier) return undefined;
    const result = await classifier.classify(text);
    const flagged = result.score >= threshold;
    return {
      score: result.score,
      flagged,
      blocked: flagged && action === 'block',
      threshold,
      model: result.model,
      latencyMs: Date.now() - start,
    };
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    return {
      flagged: false,
      blocked: mlConfig.failClosed === true,
      threshold,
      model: modelOf(mlConfig),
      latencyMs: Date.now() - start,
      error: message,
    };
  }
}
