/**
 * PII detection library.
 *
 * Shared by the CLI `pii` evaluator and the gateway output processor.
 * Patterns are deliberately conservative; every match carries a confidence
 * and callers choose a minimum confidence plus an allowlist for values they
 * know are not personal data (a support line, a company address, a
 * documentation IP range).
 */

import type { Confidence, PIIEntityType, PIIMatch } from './types';

export const PII_ENTITY_TYPES: readonly PIIEntityType[] = [
  'email',
  'phone',
  'ssn',
  'credit_card',
  'ip_address',
  'address',
  'name',
  'date_of_birth',
];

interface PIIPattern {
  pattern: RegExp;
  confidence: Confidence;
  /** Optional post-filter that can veto or re-rate a match. */
  refine?: (value: string) => Confidence | null;
}

const US_STATE_CODES =
  'A[KLRZ]|C[AOT]|D[CE]|FL|GA|HI|I[ADLN]|K[SY]|LA|M[ADEINOST]|N[CDEHJMVY]|O[HKR]|PA|RI|S[CD]|T[NX]|UT|V[AT]|W[AIVY]';

const PII_PATTERNS: Record<PIIEntityType, PIIPattern[]> = {
  email: [
    {
      pattern: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g,
      confidence: 'high',
    },
  ],

  phone: [
    // US formats with country code and separators: 1-800-555-0199
    { pattern: /(?<![\d.])1[-.\s]\d{3}[-.\s]\d{3}[-.\s]\d{4}\b/g, confidence: 'high' },
    // US formats with separators: 555-123-4567, 555.123.4567, 555 123 4567
    { pattern: /\b\d{3}[-.\s]\d{3}[-.\s]\d{4}\b/g, confidence: 'high' },
    // Parentheses format: (555) 123-4567
    { pattern: /(?<![A-Za-z0-9])\(\d{3}\)\s*\d{3}[-.\s]?\d{4}\b/g, confidence: 'high' },
    // +1 format
    { pattern: /(?<![A-Za-z0-9])\+1[-.\s]?\d{3}[-.\s]?\d{3}[-.\s]?\d{4}\b/g, confidence: 'high' },
    // International: +44 20 7946 0958
    {
      pattern: /(?<![A-Za-z0-9])\+\d{1,3}[-.\s]?\d{1,4}[-.\s]?\d{1,4}[-.\s]?\d{1,9}\b/g,
      confidence: 'medium',
    },
    // Bare 10 digits (also matches order numbers and timestamps, so low)
    { pattern: /(?<![\d.])\d{10}(?![\d.])/g, confidence: 'low' },
  ],

  ssn: [
    // With context words (most reliable)
    {
      pattern: /(?:ssn|social\s*security(?:\s*number|\s*#|\s*no\.?)?)[:\s#]*\d{3}[-\s]?\d{2}[-\s]?\d{4}\b/gi,
      confidence: 'high',
    },
    // Standard format with separators. Area number cannot be 000, 666 or 9xx;
    // group cannot be 00; serial cannot be 0000.
    {
      pattern: /\b(?!000|666|9\d\d)\d{3}[-\s](?!00)\d{2}[-\s](?!0000)\d{4}\b/g,
      confidence: 'medium',
    },
    // Without separators, only with context
    { pattern: /(?:ssn|social)[:\s#]*(\d{9})\b/gi, confidence: 'medium' },
  ],

  credit_card: [
    // Visa
    { pattern: /\b4\d{3}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b/g, confidence: 'high' },
    // Mastercard
    { pattern: /\b5[1-5]\d{2}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b/g, confidence: 'high' },
    // Amex
    { pattern: /\b3[47]\d{2}[-\s]?\d{6}[-\s]?\d{5}\b/g, confidence: 'high' },
    // Discover
    { pattern: /\b6(?:011|5\d{2})[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b/g, confidence: 'high' },
    // Generic 16-digit (Luhn-validated below)
    { pattern: /\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b/g, confidence: 'medium' },
  ],

  ip_address: [
    // IPv4. Private, loopback and link-local ranges are not personal data and
    // are re-rated to low confidence.
    {
      pattern: /\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b/g,
      confidence: 'high',
      refine: (value) => (isPrivateIPv4(value) ? 'low' : 'high'),
    },
    // IPv6 (full form)
    { pattern: /\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b/g, confidence: 'high' },
  ],

  address: [
    // US street address: 123 Main Street, Apt 4
    {
      pattern:
        /\b\d{1,6}\s+(?:[A-Z][A-Za-z]*\.?\s+){1,4}(?:Street|St|Avenue|Ave|Boulevard|Blvd|Road|Rd|Drive|Dr|Lane|Ln|Way|Court|Ct|Place|Pl|Terrace|Ter|Circle|Cir|Parkway|Pkwy|Highway|Hwy)\.?(?:,?\s*(?:Apt|Apartment|Suite|Ste|Unit|#)\s*\w+)?/g,
      confidence: 'medium',
    },
    // City, ST 12345 (requires a real state code)
    {
      pattern: new RegExp(
        `\\b[A-Z][a-z]+(?:\\s+[A-Z][a-z]+)*,\\s*(?:${US_STATE_CODES})\\s+\\d{5}(?:-\\d{4})?\\b`,
        'g'
      ),
      confidence: 'high',
    },
  ],

  name: [
    // Names with salutations: Dr. John Smith
    {
      pattern: /\b(?:Mr|Mrs|Ms|Mx|Dr|Prof)\.?\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+)+\b/g,
      confidence: 'medium',
    },
  ],

  date_of_birth: [
    {
      pattern: /(?:born(?:\s+on)?|dob|date\s*of\s*birth|birth\s*date|birthday)[:\s]*\d{1,2}[-/]\d{1,2}[-/]\d{2,4}/gi,
      confidence: 'high',
    },
    {
      pattern:
        /(?:born(?:\s+on)?|dob|date\s*of\s*birth|birth\s*date|birthday)[:\s]*(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\.?\s*\d{1,2},?\s*\d{4}/gi,
      confidence: 'high',
    },
  ],
};

// =============================================================================
// Validators
// =============================================================================

/** Luhn checksum for payment card numbers. */
export function isValidCreditCard(number: string): boolean {
  const digits = number.replace(/\D/g, '');
  if (digits.length < 13 || digits.length > 19) return false;

  let sum = 0;
  let isEven = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let digit = parseInt(digits.charAt(i), 10);
    if (isEven) {
      digit *= 2;
      if (digit > 9) digit -= 9;
    }
    sum += digit;
    isEven = !isEven;
  }
  return sum % 10 === 0;
}

/** True for RFC 1918, loopback, link-local, unspecified and documentation ranges. */
export function isPrivateIPv4(ip: string): boolean {
  const parts = ip.split('.').map((p) => parseInt(p, 10));
  if (parts.length !== 4 || parts.some((p) => Number.isNaN(p))) return false;
  const [a, b] = parts as [number, number, number, number];
  if (a === 10) return true;
  if (a === 127) return true;
  if (a === 0) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  if (a === 169 && b === 254) return true;
  if (a === 192 && b === 0 && parts[2] === 2) return true; // 192.0.2.0/24 TEST-NET-1
  if (a === 198 && b === 51 && parts[2] === 100) return true; // TEST-NET-2
  if (a === 203 && b === 0 && parts[2] === 113) return true; // TEST-NET-3
  if (a >= 224) return true; // multicast and reserved
  return false;
}

const CONFIDENCE_RANK: Record<Confidence, number> = { low: 1, medium: 2, high: 3 };

export function confidenceRank(confidence: Confidence): number {
  return CONFIDENCE_RANK[confidence];
}

// =============================================================================
// Detection
// =============================================================================

export interface DetectPIIOptions {
  /**
   * Drop matches below this confidence. Default `medium`, which excludes
   * private IP ranges and bare 10-digit numbers.
   */
  minConfidence?: Confidence;
  /**
   * Literal values that are known not to be PII (a support phone number, a
   * company address). Compared case-insensitively after whitespace
   * normalisation; a match is allowed if it equals an entry or is contained
   * in one.
   */
  allowValues?: readonly string[];
  /** Regular expressions tested against the matched value. */
  allowPatterns?: readonly (string | RegExp)[];
}

function normalise(value: string): string {
  return value.toLowerCase().replace(/\s+/g, ' ').trim();
}

function compileAllowPatterns(patterns: readonly (string | RegExp)[] | undefined): RegExp[] {
  if (!patterns) return [];
  const compiled: RegExp[] = [];
  for (const p of patterns) {
    try {
      compiled.push(p instanceof RegExp ? p : new RegExp(p, 'i'));
    } catch {
      // ignore invalid patterns
    }
  }
  return compiled;
}

/**
 * Detect PII of the given types in text.
 *
 * Results are sorted by position and de-duplicated by (type, start).
 */
export function detectPII(
  text: string,
  typesToDetect: readonly PIIEntityType[],
  options: DetectPIIOptions = {}
): PIIMatch[] {
  if (!text) return [];

  const minRank = CONFIDENCE_RANK[options.minConfidence ?? 'medium'];
  const allowValues = (options.allowValues ?? []).map(normalise).filter(Boolean);
  const allowPatterns = compileAllowPatterns(options.allowPatterns);

  const isAllowed = (value: string): boolean => {
    const norm = normalise(value);
    if (allowValues.some((allowed) => allowed === norm || allowed.includes(norm) || norm.includes(allowed))) {
      return true;
    }
    return allowPatterns.some((re) => {
      re.lastIndex = 0;
      return re.test(value);
    });
  };

  const matches: PIIMatch[] = [];
  const seen = new Set<string>();

  for (const type of typesToDetect) {
    const patterns = PII_PATTERNS[type] ?? [];

    for (const { pattern, confidence, refine } of patterns) {
      pattern.lastIndex = 0;

      let match: RegExpExecArray | null;
      while ((match = pattern.exec(text)) !== null) {
        const value = match[0];
        if (value.length === 0) {
          pattern.lastIndex++;
          continue;
        }

        if (type === 'credit_card' && !isValidCreditCard(value)) continue;

        let finalConfidence: Confidence | null = confidence;
        if (refine) finalConfidence = refine(value);
        if (!finalConfidence) continue;
        if (CONFIDENCE_RANK[finalConfidence] < minRank) continue;
        if (isAllowed(value)) continue;

        const key = `${type}@${match.index}`;
        if (seen.has(key)) continue;
        seen.add(key);

        matches.push({
          type,
          value,
          start: match.index,
          end: match.index + value.length,
          confidence: finalConfidence,
        });
      }
      pattern.lastIndex = 0;
    }
  }

  return suppressOverlaps(matches);
}

/**
 * When two patterns of the same type overlap (for example "+1 555 123 4567"
 * and the inner "555 123 4567"), keep the longest match and drop the rest.
 */
function suppressOverlaps(matches: PIIMatch[]): PIIMatch[] {
  const sorted = [...matches].sort(
    (a, b) => a.start - b.start || b.end - a.end || confidenceRank(b.confidence) - confidenceRank(a.confidence)
  );
  const kept: PIIMatch[] = [];
  const lastEndByType = new Map<string, number>();

  for (const match of sorted) {
    const lastEnd = lastEndByType.get(match.type) ?? -1;
    if (match.start < lastEnd) continue;
    kept.push(match);
    lastEndByType.set(match.type, match.end);
  }
  return kept;
}

// =============================================================================
// Redaction
// =============================================================================

export interface RedactPIIOptions {
  /** Build the replacement for a match. Default `[EMAIL_REDACTED]` style. */
  placeholder?: (match: PIIMatch) => string;
}

/**
 * Replace every match in text with a placeholder, handling overlaps by
 * processing from the end of the string backwards.
 */
export function redactPII(text: string, matches: readonly PIIMatch[], options: RedactPIIOptions = {}): string {
  const placeholder = options.placeholder ?? ((m: PIIMatch) => `[${m.type.toUpperCase()}_REDACTED]`);
  const sorted = [...matches].sort((a, b) => b.start - a.start);

  let result = text;
  let lastStart = Number.POSITIVE_INFINITY;
  for (const match of sorted) {
    // Skip matches that overlap one we already redacted.
    if (match.end > lastStart) continue;
    result = result.slice(0, match.start) + placeholder(match) + result.slice(match.end);
    lastStart = match.start;
  }
  return result;
}
