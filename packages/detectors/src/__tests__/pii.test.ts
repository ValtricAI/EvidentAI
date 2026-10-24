import { describe, it, expect } from 'vitest';
import { detectPII, redactPII, isPrivateIPv4, isValidCreditCard } from '../pii';

const ALL = ['email', 'phone', 'ssn', 'credit_card', 'ip_address', 'address', 'name', 'date_of_birth'] as const;

describe('detectPII', () => {
  it('detects emails', () => {
    const m = detectPII('Contact john.doe@example.com now', ['email']);
    expect(m.map((x) => x.value)).toEqual(['john.doe@example.com']);
  });

  it('detects separated phone numbers at high confidence', () => {
    const m = detectPII('Call 555-123-4567 or (555) 123-4567 or +1 555 123 4567', ['phone']);
    expect(m.length).toBe(3);
    expect(m.every((x) => x.confidence === 'high')).toBe(true);
  });

  it('treats bare 10-digit numbers as low confidence and hides them by default', () => {
    expect(detectPII('Order 5551234567 shipped', ['phone'])).toEqual([]);
    expect(detectPII('Order 5551234567 shipped', ['phone'], { minConfidence: 'low' }).length).toBe(1);
  });

  it('detects SSNs with and without context', () => {
    expect(detectPII('SSN: 123-45-6789', ['ssn'])[0]?.confidence).toBe('high');
    expect(detectPII('The number is 123-45-6789.', ['ssn'])[0]?.confidence).toBe('medium');
    expect(detectPII('Code: 000-12-3456 or 666-12-3456', ['ssn'])).toEqual([]);
    expect(detectPII('Version 1.2.3 released on 2024-01-15', ['ssn'])).toEqual([]);
  });

  it('validates credit cards with Luhn', () => {
    expect(detectPII('Card: 4111-1111-1111-1111', ['credit_card']).length).toBe(1);
    expect(detectPII('Not a card: 1234-5678-9012-3456', ['credit_card'])).toEqual([]);
    expect(isValidCreditCard('4111111111111111')).toBe(true);
    expect(isValidCreditCard('1234567890123456')).toBe(false);
  });

  it('rates private IP addresses low and public ones high', () => {
    expect(isPrivateIPv4('192.168.1.1')).toBe(true);
    expect(isPrivateIPv4('10.0.0.1')).toBe(true);
    expect(isPrivateIPv4('172.16.5.5')).toBe(true);
    expect(isPrivateIPv4('172.32.0.1')).toBe(false);
    expect(isPrivateIPv4('8.8.8.8')).toBe(false);

    expect(detectPII('Router at 192.168.1.1', ['ip_address'])).toEqual([]);
    expect(detectPII('Router at 192.168.1.1', ['ip_address'], { minConfidence: 'low' }).length).toBe(1);
    const pub = detectPII('Client IP 8.8.4.4 logged', ['ip_address']);
    expect(pub.length).toBe(1);
    expect(pub[0]?.confidence).toBe('high');
    expect(detectPII('Score: 192.168.300.500', ['ip_address'], { minConfidence: 'low' })).toEqual([]);
  });

  it('detects addresses but requires a real state code for city/state/zip', () => {
    expect(detectPII('Address: 123 Main Street, Apt 4', ['address']).length).toBe(1);
    expect(detectPII('Located in San Francisco, CA 94102', ['address']).length).toBe(1);
    expect(detectPII('Product AB 12345 is in stock', ['address'])).toEqual([]);
  });

  it('detects names only with salutations', () => {
    expect(detectPII('Contact Dr. John Smith for assistance.', ['name']).length).toBe(1);
    expect(detectPII('Talk to John Smith please.', ['name'])).toEqual([]);
  });

  it('detects dates of birth only with context', () => {
    expect(detectPII('Date of birth: 01/15/1990', ['date_of_birth']).length).toBe(1);
    expect(detectPII('She was born January 15, 1990', ['date_of_birth']).length).toBe(1);
    expect(detectPII('The meeting is on 01/15/2024', ['date_of_birth'])).toEqual([]);
  });

  it('honours allowValues and allowPatterns', () => {
    const text = 'Call support at 1-800-555-0199 or 555-123-4567, or email help@company.com';
    const all = detectPII(text, ['phone', 'email']);
    expect(all.length).toBe(3);

    expect(all.map((m) => m.value)).toEqual(['1-800-555-0199', '555-123-4567', 'help@company.com']);

    const allowed = detectPII(text, ['phone', 'email'], {
      allowValues: ['555-123-4567', '1-800-555-0199'],
      allowPatterns: ['@company\\.com$'],
    });
    expect(allowed).toEqual([]);

    // A toll-free number listed with its country code also covers the bare form.
    expect(
      detectPII('Dial 800-555-0199', ['phone'], { allowValues: ['1-800-555-0199'] })
    ).toEqual([]);
  });

  it('sorts matches by position and dedupes', () => {
    const m = detectPII('b@x.com then 555-123-4567 then a@y.org', ALL);
    expect(m.map((x) => x.type)).toEqual(['email', 'phone', 'email']);
  });
});

describe('redactPII', () => {
  it('uses the default placeholder', () => {
    const text = 'Email: test@test.com';
    expect(redactPII(text, detectPII(text, ['email']))).toBe('Email: [EMAIL_REDACTED]');
  });

  it('accepts a custom placeholder', () => {
    const text = 'Email: a@b.com and c@d.com';
    const out = redactPII(text, detectPII(text, ['email']), {
      placeholder: (m) => `[PII:${m.type.toUpperCase()}]`,
    });
    expect(out).toBe('Email: [PII:EMAIL] and [PII:EMAIL]');
  });

  it('handles overlapping matches without corrupting the string', () => {
    // A Visa number also matches the generic 16-digit pattern at the same start.
    const text = 'Card 4111 1111 1111 1111 end';
    const matches = detectPII(text, ['credit_card', 'phone'], { minConfidence: 'low' });
    const out = redactPII(text, matches);
    expect(out.startsWith('Card [')).toBe(true);
    expect(out.endsWith(' end')).toBe(true);
    expect(out).not.toContain('1111');
  });
});
