/**
 * PII Detector Evaluator Unit Tests
 *
 * Tests PII detection across all entity types.
 */

import { describe, it, expect } from 'vitest';
import { runEvaluator } from '../../runner/evaluators';

describe('PIIDetectorEvaluator', () => {
  describe('Email Detection', () => {
    it('should detect email addresses', async () => {
      const result = await runEvaluator('pii', {
        input: 'test',
        output: 'Contact me at john.doe@example.com for more info.',
        config: { fail_on: ['email'] },
      });

      expect(result.passed).toBe(false);
      expect(result.details?.total_matches).toBe(1);
    });

    it('should pass when no email present', async () => {
      const result = await runEvaluator('pii', {
        input: 'test',
        output: 'Contact me for more information.',
        config: { fail_on: ['email'] },
      });

      expect(result.passed).toBe(true);
    });

    it('should detect multiple emails', async () => {
      const result = await runEvaluator('pii', {
        input: 'test',
        output: 'Emails: test@test.com and another@domain.org',
        config: { fail_on: ['email'] },
      });

      expect(result.passed).toBe(false);
      expect(result.details?.total_matches).toBe(2);
    });
  });

  describe('Phone Number Detection', () => {
    it('should detect US phone numbers', async () => {
      const result = await runEvaluator('pii', {
        input: 'test',
        output: 'Call me at 555-123-4567.',
        config: { fail_on: ['phone'] },
      });

      expect(result.passed).toBe(false);
    });

    it('should detect phone with parentheses', async () => {
      const result = await runEvaluator('pii', {
        input: 'test',
        output: 'Phone: (555)123-4567',
        config: { fail_on: ['phone'] },
      });

      expect(result.passed).toBe(false);
    });

    it('should detect international numbers', async () => {
      const result = await runEvaluator('pii', {
        input: 'test',
        output: 'Call +1-555-123-4567',
        config: { fail_on: ['phone'] },
      });

      expect(result.passed).toBe(false);
    });
  });

  describe('SSN Detection', () => {
    it('should detect SSN with context', async () => {
      const result = await runEvaluator('pii', {
        input: 'test',
        output: 'SSN: 123-45-6789',
        config: { fail_on: ['ssn'] },
      });

      expect(result.passed).toBe(false);
    });

    it('should detect SSN with separators', async () => {
      const result = await runEvaluator('pii', {
        input: 'test',
        output: 'The number is 123-45-6789.',
        config: { fail_on: ['ssn'] },
      });

      expect(result.passed).toBe(false);
    });

    it('should NOT flag version numbers as SSN', async () => {
      const result = await runEvaluator('pii', {
        input: 'test',
        output: 'Version 1.2.3 released on 2024-01-15',
        config: { fail_on: ['ssn'] },
      });

      expect(result.passed).toBe(true);
    });

    it('should NOT flag invalid SSN area numbers', async () => {
      // 000, 666, and 900-999 are invalid SSN area numbers
      const result = await runEvaluator('pii', {
        input: 'test',
        output: 'Code: 000-12-3456 or 666-12-3456',
        config: { fail_on: ['ssn'] },
      });

      expect(result.passed).toBe(true);
    });

    it('should detect Social Security Number with full text', async () => {
      const result = await runEvaluator('pii', {
        input: 'test',
        output: 'Social Security Number: 123-45-6789',
        config: { fail_on: ['ssn'] },
      });

      expect(result.passed).toBe(false);
    });
  });

  describe('Credit Card Detection', () => {
    it('should detect valid Visa card', async () => {
      const result = await runEvaluator('pii', {
        input: 'test',
        output: 'Card: 4111-1111-1111-1111',
        config: { fail_on: ['credit_card'] },
      });

      expect(result.passed).toBe(false);
    });

    it('should detect valid Mastercard', async () => {
      const result = await runEvaluator('pii', {
        input: 'test',
        output: 'Card: 5500 0000 0000 0004',
        config: { fail_on: ['credit_card'] },
      });

      expect(result.passed).toBe(false);
    });

    it('should NOT flag invalid Luhn numbers', async () => {
      const result = await runEvaluator('pii', {
        input: 'test',
        output: 'Not a card: 1234-5678-9012-3456',
        config: { fail_on: ['credit_card'] },
      });

      expect(result.passed).toBe(true);
    });

    it('should detect Amex format', async () => {
      const result = await runEvaluator('pii', {
        input: 'test',
        output: 'Amex: 3782 822463 10005',
        config: { fail_on: ['credit_card'] },
      });

      expect(result.passed).toBe(false);
    });
  });

  describe('IP Address Detection', () => {
    it('should detect public IPv4 addresses', async () => {
      const result = await runEvaluator('pii', {
        input: 'test',
        output: 'Client IP: 93.184.216.34',
        config: { fail_on: ['ip_address'] },
      });

      expect(result.passed).toBe(false);
    });

    it('should NOT flag private or loopback IPv4 addresses by default', async () => {
      const result = await runEvaluator('pii', {
        input: 'test',
        output: 'Router: 192.168.1.100, VPN: 10.0.0.1, local: 127.0.0.1',
        config: { fail_on: ['ip_address'] },
      });

      expect(result.passed).toBe(true);
    });

    it('should flag private IPv4 addresses when min_confidence is low', async () => {
      const result = await runEvaluator('pii', {
        input: 'test',
        output: 'IP: 10.0.0.1',
        config: { fail_on: ['ip_address'], min_confidence: 'low' },
      });

      expect(result.passed).toBe(false);
    });

    it('should pass on non-IP numbers', async () => {
      const result = await runEvaluator('pii', {
        input: 'test',
        output: 'Score: 192.168.300.500', // Invalid IP - octets > 255
        config: { fail_on: ['ip_address'] },
      });

      expect(result.passed).toBe(true);
    });
  });

  describe('Address Detection', () => {
    it('should detect street addresses', async () => {
      const result = await runEvaluator('pii', {
        input: 'test',
        output: 'Address: 123 Main Street, Apt 4',
        config: { fail_on: ['address'] },
      });

      expect(result.passed).toBe(false);
    });

    it('should detect city/state/zip', async () => {
      const result = await runEvaluator('pii', {
        input: 'test',
        output: 'Located in San Francisco, CA 94102',
        config: { fail_on: ['address'] },
      });

      expect(result.passed).toBe(false);
    });
  });

  describe('Name Detection', () => {
    it('should detect names with salutations', async () => {
      const result = await runEvaluator('pii', {
        input: 'test',
        output: 'Contact Dr. John Smith for assistance.',
        config: { fail_on: ['name'] },
      });

      expect(result.passed).toBe(false);
    });

    it('should not flag names without salutations', async () => {
      // Current implementation requires salutations
      const result = await runEvaluator('pii', {
        input: 'test',
        output: 'Talk to John Smith please.',
        config: { fail_on: ['name'] },
      });

      expect(result.passed).toBe(true);
    });
  });

  describe('Date of Birth Detection', () => {
    it('should detect DOB with context', async () => {
      const result = await runEvaluator('pii', {
        input: 'test',
        output: 'Date of birth: 01/15/1990',
        config: { fail_on: ['date_of_birth'] },
      });

      expect(result.passed).toBe(false);
    });

    it('should detect "born on" dates', async () => {
      const result = await runEvaluator('pii', {
        input: 'test',
        output: 'She was born January 15, 1990',
        config: { fail_on: ['date_of_birth'] },
      });

      expect(result.passed).toBe(false);
    });

    it('should not flag general dates', async () => {
      const result = await runEvaluator('pii', {
        input: 'test',
        output: 'The meeting is on 01/15/2024',
        config: { fail_on: ['date_of_birth'] },
      });

      expect(result.passed).toBe(true);
    });
  });

  describe('Multiple PII Types', () => {
    it('should detect multiple types in one text', async () => {
      const result = await runEvaluator('pii', {
        input: 'test',
        output: 'Email: test@test.com, Phone: 555-123-4567',
        config: { fail_on: ['email', 'phone'] },
      });

      expect(result.passed).toBe(false);
      expect(result.details?.total_matches).toBeGreaterThanOrEqual(2);
    });

    it('should only check specified types', async () => {
      const result = await runEvaluator('pii', {
        input: 'test',
        output: 'Email: test@test.com, Phone: 555-123-4567',
        config: { fail_on: ['email'] },
      });

      expect(result.passed).toBe(false);
      expect(result.details?.total_matches).toBe(1);
    });
  });

  describe('Allow List', () => {
    it('should skip allowed types', async () => {
      const result = await runEvaluator('pii', {
        input: 'test',
        output: 'Email: test@test.com',
        config: { fail_on: ['email', 'phone'], allow: ['email'] },
      });

      expect(result.passed).toBe(true);
    });
  });

  describe('Redaction', () => {
    it('should redact PII when requested', async () => {
      const result = await runEvaluator('pii', {
        input: 'test',
        output: 'Email: test@test.com',
        config: { fail_on: ['email'], redact: true },
      });

      expect(result.details?.redacted_output).toContain('[EMAIL_REDACTED]');
      expect(result.details?.redacted_output).not.toContain('test@test.com');
    });

    it('should show partial values when not redacting', async () => {
      const result = await runEvaluator('pii', {
        input: 'test',
        output: 'Email: test@test.com',
        config: { fail_on: ['email'], redact: false },
      });

      const matches = result.details?.matches as Array<{ value: string }>;
      expect(matches[0]?.value).toContain('***');
      expect(matches[0]?.value).toContain('test');
    });
  });

  describe('Configuration Errors', () => {
    it('should fail when no fail_on specified', async () => {
      const result = await runEvaluator('pii', {
        input: 'test',
        output: 'Some text',
        config: {},
      });

      expect(result.passed).toBe(false);
      expect(result.reason).toContain('fail_on');
    });

    it('should fail when fail_on is empty', async () => {
      const result = await runEvaluator('pii', {
        input: 'test',
        output: 'Some text',
        config: { fail_on: [] },
      });

      expect(result.passed).toBe(false);
    });
  });

  describe('Confidence Levels', () => {
    it('should report confidence in matches', async () => {
      const result = await runEvaluator('pii', {
        input: 'test',
        output: 'Email: test@test.com',
        config: { fail_on: ['email'] },
      });

      const matches = result.details?.matches as Array<{ confidence: string }>;
      expect(matches[0]?.confidence).toBe('high');
    });
  });

  describe('Reason Messages', () => {
    it('should provide helpful pass message', async () => {
      const result = await runEvaluator('pii', {
        input: 'test',
        output: 'No personal info here.',
        config: { fail_on: ['email', 'phone'] },
      });

      expect(result.reason).toContain('No PII detected');
      expect(result.reason).toContain('email');
      expect(result.reason).toContain('phone');
    });

    it('should provide helpful fail message with counts', async () => {
      const result = await runEvaluator('pii', {
        input: 'test',
        output: 'Emails: a@b.com and c@d.com',
        config: { fail_on: ['email'] },
      });

      expect(result.reason).toContain('PII detected');
      expect(result.reason).toContain('email');
      expect(result.reason).toContain('2');
    });
  });
});
