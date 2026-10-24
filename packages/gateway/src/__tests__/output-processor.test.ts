import { describe, it, expect } from 'vitest';
import { processOutput, detectPII, redactPII } from '../pipeline/output-processor.js';

describe('Output Processor', () => {
  describe('PII Detection', () => {
    it('detects email addresses', async () => {
      const result = await processOutput(
        'Contact me at john.doe@example.com for more info.',
        { piiTypes: ['email'], action: 'log' }
      );

      expect(result.piiDetected).toBe(true);
      expect(result.piiMatches.length).toBe(1);
      expect(result.piiMatches[0]?.type).toBe('email');
      expect(result.piiMatches[0]?.value).toBe('john.doe@example.com');
    });

    it('detects phone numbers', async () => {
      const result = await processOutput(
        'Call me at 555-123-4567 or (800) 555-1234.',
        { piiTypes: ['phone'], action: 'log' }
      );

      expect(result.piiDetected).toBe(true);
      expect(result.piiMatches.length).toBe(2);
    });

    it('detects SSNs with context', async () => {
      const result = await processOutput(
        'Your SSN: 123-45-6789 is on file.',
        { piiTypes: ['ssn'], action: 'log' }
      );

      expect(result.piiDetected).toBe(true);
      expect(result.piiMatches[0]?.type).toBe('ssn');
    });

    it('detects credit card numbers with Luhn validation', async () => {
      // Valid Visa test number
      const result = await processOutput(
        'Your card number is 4111-1111-1111-1111.',
        { piiTypes: ['credit_card'], action: 'log' }
      );

      expect(result.piiDetected).toBe(true);
      expect(result.piiMatches[0]?.type).toBe('credit_card');
    });

    it('rejects invalid credit card numbers', async () => {
      // Invalid number (fails Luhn)
      const result = await processOutput(
        'Number: 1234-5678-9012-3456',
        { piiTypes: ['credit_card'], action: 'log' }
      );

      expect(result.piiDetected).toBe(false);
    });

    it('detects public IP addresses', async () => {
      const result = await processOutput(
        'Client IP: 93.184.216.34',
        { piiTypes: ['ip_address'], action: 'log' }
      );

      expect(result.piiDetected).toBe(true);
      expect(result.piiMatches[0]?.value).toBe('93.184.216.34');
    });

    it('ignores private IP addresses unless minConfidence is low', async () => {
      const text = 'Server IP: 192.168.1.100';
      const def = await processOutput(text, { piiTypes: ['ip_address'], action: 'log' });
      expect(def.piiDetected).toBe(false);

      const low = await processOutput(text, { piiTypes: ['ip_address'], action: 'log', minConfidence: 'low' });
      expect(low.piiDetected).toBe(true);
    });

    it('honours allowValues and allowPatterns', async () => {
      const text = 'Call 1-800-555-0199 or email help@company.com';
      const result = await processOutput(text, {
        piiTypes: ['phone', 'email'],
        action: 'redact',
        allowValues: ['1-800-555-0199'],
        allowPatterns: ['@company\\.com$'],
      });
      expect(result.piiDetected).toBe(false);
      expect(result.processed).toBe(text);
    });

    it('detects multiple PII types', async () => {
      const result = await processOutput(
        'Email: test@example.com, Phone: 555-123-4567',
        { piiTypes: ['email', 'phone'], action: 'log' }
      );

      expect(result.piiMatches.length).toBe(2);
      expect(result.piiMatches.map((m) => m.type)).toContain('email');
      expect(result.piiMatches.map((m) => m.type)).toContain('phone');
    });

    it('passes clean text', async () => {
      const result = await processOutput(
        'The weather in San Francisco is sunny today.',
        { piiTypes: ['email', 'phone', 'ssn', 'credit_card'], action: 'log' }
      );

      expect(result.piiDetected).toBe(false);
    });
  });

  describe('PII Redaction', () => {
    it('redacts email with type-specific placeholder', async () => {
      const result = await processOutput(
        'Contact: john@example.com',
        { piiTypes: ['email'], action: 'redact' }
      );

      expect(result.processed).toBe('Contact: [PII:EMAIL]');
    });

    it('redacts phone with type-specific placeholder', async () => {
      const result = await processOutput(
        'Call: 555-123-4567',
        { piiTypes: ['phone'], action: 'redact' }
      );

      expect(result.processed).toBe('Call: [PII:PHONE]');
    });

    it('redacts multiple PII instances', async () => {
      const result = await processOutput(
        'Email: a@b.com and b@c.com',
        { piiTypes: ['email'], action: 'redact' }
      );

      expect(result.processed).toBe('Email: [PII:EMAIL] and [PII:EMAIL]');
    });

    it('redacts mixed PII types', async () => {
      const result = await processOutput(
        'Contact: test@example.com or 555-123-4567',
        { piiTypes: ['email', 'phone'], action: 'redact' }
      );

      expect(result.processed).toContain('[PII:EMAIL]');
      expect(result.processed).toContain('[PII:PHONE]');
    });

    it('preserves original content in result', async () => {
      const original = 'Email: test@example.com';
      const result = await processOutput(
        original,
        { piiTypes: ['email'], action: 'redact' }
      );

      expect(result.original).toBe(original);
      expect(result.processed).not.toBe(original);
    });
  });

  describe('Actions', () => {
    const contentWithPII = 'Email: sensitive@example.com';

    it('blocks when action is block', async () => {
      const result = await processOutput(
        contentWithPII,
        { piiTypes: ['email'], action: 'block' }
      );

      expect(result.blocked).toBe(true);
      expect(result.blockReason).toContain('PII');
    });

    it('does not modify when action is log', async () => {
      const result = await processOutput(
        contentWithPII,
        { piiTypes: ['email'], action: 'log' }
      );

      expect(result.blocked).toBe(false);
      expect(result.processed).toBe(contentWithPII);
    });

    it('redacts when action is redact', async () => {
      const result = await processOutput(
        contentWithPII,
        { piiTypes: ['email'], action: 'redact' }
      );

      expect(result.blocked).toBe(false);
      expect(result.processed).toContain('[PII:EMAIL]');
    });
  });

  describe('detectPII function', () => {
    it('returns matches sorted by position', () => {
      const text = 'First: a@b.com, second: c@d.com';
      const matches = detectPII(text, ['email']);

      expect(matches.length).toBe(2);
      expect(matches[0]!.start).toBeLessThan(matches[1]!.start);
    });
  });

  describe('redactPII function', () => {
    it('handles multiple matches correctly', () => {
      const text = 'A: a@b.com B: c@d.com';
      const matches = detectPII(text, ['email']);
      const redacted = redactPII(text, matches);

      expect(redacted).toBe('A: [PII:EMAIL] B: [PII:EMAIL]');
    });
  });
});
