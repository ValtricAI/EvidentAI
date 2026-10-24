/**
 * Shared detector types.
 */

/** How strongly a pattern indicates an attack. */
export type Severity = 'critical' | 'high' | 'medium' | 'low';

/** Coarse confidence bucket exposed to consumers that do not use severity. */
export type Confidence = 'high' | 'medium' | 'low';

/**
 * How aggressive detection should be.
 *
 * - `low`: only critical and high severity patterns
 * - `medium`: adds medium severity patterns (default)
 * - `high`: adds low severity patterns (noisy, best for audits)
 */
export type Sensitivity = 'low' | 'medium' | 'high';

export type InjectionCategory =
  | 'instruction_override'
  | 'role_manipulation'
  | 'prompt_extraction'
  | 'delimiter_injection'
  | 'context_manipulation'
  | 'privilege_escalation'
  | 'obfuscation'
  | 'bypass_attempt'
  | 'canary_leak'
  | 'custom';

export interface InjectionPattern {
  /** Stable machine name, e.g. `ignore_instructions`. */
  name: string;
  category: InjectionCategory;
  severity: Severity;
  /** Human readable description used in logs and reasons. */
  description: string;
  pattern: RegExp;
}

export interface InjectionMatch {
  /** Pattern name (`technique` kept for backwards compatibility with the CLI). */
  technique: string;
  category: InjectionCategory;
  severity: Severity;
  confidence: Confidence;
  description: string;
  /** The matched text, truncated to 100 characters. */
  matched: string;
  position: number;
}

export type PIIEntityType =
  | 'email'
  | 'phone'
  | 'ssn'
  | 'credit_card'
  | 'ip_address'
  | 'address'
  | 'name'
  | 'date_of_birth';

export interface PIIMatch {
  type: PIIEntityType;
  value: string;
  start: number;
  end: number;
  confidence: Confidence;
}
