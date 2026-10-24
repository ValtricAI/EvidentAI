/**
 * Input Sanitization Pipeline
 *
 * Detects prompt injection attempts in user messages using the shared
 * `@evidentai/detectors` pattern library and applies the configured action:
 *
 * - `block`: reject the request
 * - `rephrase`: rewrite offending user messages with an internal LLM (falls
 *   back to stripping high-confidence matches when no LLM is configured)
 * - `log`: pass the request through unchanged and only report
 */

import {
  detectInjection,
  type InjectionMatch as LibraryMatch,
  type Sensitivity,
} from '@evidentai/detectors';
import type { ChatMessage, InputSanitizationResult, InjectionMatch } from '../types.js';
import { rephraseWithLLM } from '../sanitizers/injection-rephraser.js';

// =============================================================================
// Configuration
// =============================================================================

export interface InputSanitizerConfig {
  /** Sensitivity level for injection detection */
  sensitivity: Sensitivity;
  /** Action to take on detection */
  action: 'block' | 'rephrase' | 'log';
  /** Internal LLM configuration for rephrasing */
  internalLLM?: {
    apiKey?: string;
    model?: string;
  };
  /** Extra regex sources treated as high-confidence injection patterns */
  customPatterns?: string[];
}

// =============================================================================
// Detection
// =============================================================================

function toGatewayMatch(match: LibraryMatch): InjectionMatch {
  return {
    technique: match.technique,
    category: match.category,
    severity: match.severity,
    pattern: match.description,
    matched: match.matched,
    position: match.position,
    confidence: match.confidence,
    inInput: true,
  };
}

export function detectInjectionInText(
  text: string,
  sensitivity: Sensitivity,
  customPatterns?: string[]
): InjectionMatch[] {
  return detectInjection(text, { sensitivity, customPatterns }).map(toGatewayMatch);
}

// =============================================================================
// Main Sanitization Function
// =============================================================================

export async function sanitizeInput(
  messages: ChatMessage[],
  config: InputSanitizerConfig
): Promise<InputSanitizationResult> {
  const startTime = Date.now();
  const allMatches: InjectionMatch[] = [];
  const matchesByMessage = new Map<number, InjectionMatch[]>();

  // Only user-authored content is untrusted. System and assistant turns are
  // controlled by the application, and `tool` results are application data
  // that the application chose to feed back, so they are not scanned.
  messages.forEach((message, index) => {
    if (message.role !== 'user') return;
    const text = messageText(message);
    if (!text) return;
    const matches = detectInjectionInText(text, config.sensitivity, config.customPatterns);
    if (matches.length > 0) {
      matchesByMessage.set(index, matches);
      allMatches.push(...matches);
    }
  });

  const injectionDetected = allMatches.length > 0;

  let blocked = false;
  let blockReason: string | undefined;
  let sanitizedMessages = messages;

  if (injectionDetected) {
    switch (config.action) {
      case 'block': {
        blocked = true;
        const highConfidence = allMatches.filter((m) => m.confidence === 'high');
        const techniques = [...new Set((highConfidence.length > 0 ? highConfidence : allMatches).map((m) => m.technique))];
        blockReason = highConfidence.length > 0
          ? `Blocked due to high-confidence injection: ${techniques.join(', ')}`
          : `Blocked due to injection patterns: ${techniques.join(', ')}`;
        break;
      }

      case 'rephrase': {
        const apiKey = config.internalLLM?.apiKey || process.env.OPENAI_API_KEY;
        if (apiKey) {
          sanitizedMessages = await rephraseMessages(messages, matchesByMessage, {
            apiKey,
            model: config.internalLLM?.model || 'gpt-4o-mini',
          });
        } else {
          sanitizedMessages = basicCleanup(messages, matchesByMessage);
        }
        break;
      }

      case 'log':
        // Report only, do not modify
        break;
    }
  }

  return {
    original: messages,
    sanitized: sanitizedMessages,
    injectionDetected,
    injectionMatches: allMatches,
    blocked,
    blockReason,
    latencyMs: Date.now() - startTime,
  };
}

// =============================================================================
// Helper Functions
// =============================================================================

/** Text of a message; array content is joined from its text parts. */
function messageText(message: ChatMessage): string {
  if (typeof message.content === 'string') return message.content;
  if (Array.isArray(message.content)) {
    return message.content
      .filter((part) => part.type === 'text' && typeof part.text === 'string')
      .map((part) => part.text as string)
      .join('\n');
  }
  return '';
}

async function rephraseMessages(
  messages: ChatMessage[],
  matchesByMessage: Map<number, InjectionMatch[]>,
  llmConfig: { apiKey: string; model: string }
): Promise<ChatMessage[]> {
  const result: ChatMessage[] = [];

  for (const [index, message] of messages.entries()) {
    if (matchesByMessage.has(index) && messageText(message)) {
      const rephrased = await rephraseWithLLM(messageText(message), llmConfig);
      result.push({ ...message, content: rephrased });
    } else {
      result.push(message);
    }
  }

  return result;
}

/**
 * Strip high-confidence matches out of the offending messages. Positions come
 * from the detector, so removal is exact and does not rely on substring
 * search.
 */
function basicCleanup(
  messages: ChatMessage[],
  matchesByMessage: Map<number, InjectionMatch[]>
): ChatMessage[] {
  return messages.map((message, index) => {
    const matches = matchesByMessage.get(index);
    const original = messageText(message);
    if (!matches || !original) {
      return message;
    }

    const removals = matches
      .filter((m) => m.confidence === 'high')
      .map((m) => ({ start: m.position, end: m.position + m.matched.length }))
      .sort((a, b) => b.start - a.start);

    if (removals.length === 0) {
      return message;
    }

    let content = original;
    let lastStart = Number.POSITIVE_INFINITY;
    for (const removal of removals) {
      if (removal.end > lastStart) continue; // overlapping range already removed
      content = content.slice(0, removal.start) + content.slice(removal.end);
      lastStart = removal.start;
    }

    return {
      ...message,
      content: content.replace(/\s{2,}/g, ' ').trim(),
    };
  });
}
