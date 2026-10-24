import { describe, it, expect } from 'vitest';
import { configFromEnv, resolveConfig, configWarnings, DEFAULT_CONFIG, ConfigError } from '../config.js';

describe('gateway config', () => {
  it('defaults injection action to log and PII action to redact', () => {
    expect(DEFAULT_CONFIG.input.injectionAction).toBe('log');
    expect(DEFAULT_CONFIG.output.piiAction).toBe('redact');
    expect(DEFAULT_CONFIG.output.piiMinConfidence).toBe('medium');
    expect(DEFAULT_CONFIG.output.piiScanToolArguments).toBe(false);
  });

  it('reads an empty environment as the defaults', () => {
    const config = resolveConfig(configFromEnv({}));
    expect(config.port).toBe(3000);
    expect(config.input.injectionAction).toBe('log');
    expect(config.input.injectionSensitivity).toBe('medium');
    expect(config.output.piiTypes).toEqual(['email', 'phone', 'ssn', 'credit_card']);
    expect(config.output.piiAllowValues).toBeUndefined();
  });

  it('parses lists, booleans and enums', () => {
    const config = resolveConfig(
      configFromEnv({
        GATEWAY_PORT: '8080',
        GATEWAY_INJECTION_ACTION: 'block',
        GATEWAY_INJECTION_CUSTOM_PATTERNS: 'secret handshake, launch codes',
        GATEWAY_DETECT_PII: 'false',
        GATEWAY_PII_TYPES: 'email, ip_address',
        GATEWAY_PII_MIN_CONFIDENCE: 'high',
        GATEWAY_PII_ALLOW_VALUES: '1-800-555-0199,support@example.com',
        GATEWAY_PII_ALLOW_PATTERNS: '@example\\.com$',
        GATEWAY_PII_SCAN_TOOL_ARGUMENTS: 'true',
      })
    );

    expect(config.port).toBe(8080);
    expect(config.input.injectionAction).toBe('block');
    expect(config.input.injectionCustomPatterns).toEqual(['secret handshake', 'launch codes']);
    expect(config.output.detectPII).toBe(false);
    expect(config.output.piiTypes).toEqual(['email', 'ip_address']);
    expect(config.output.piiMinConfidence).toBe('high');
    expect(config.output.piiAllowValues).toEqual(['1-800-555-0199', 'support@example.com']);
    expect(config.output.piiAllowPatterns).toEqual(['@example\\.com$']);
    expect(config.output.piiScanToolArguments).toBe(true);
  });

  it('rejects invalid enum values with a readable message', () => {
    expect(() => configFromEnv({ GATEWAY_PII_ACTION: 'delete' })).toThrow(ConfigError);
    expect(() => configFromEnv({ GATEWAY_PII_ACTION: 'delete' })).toThrow(/GATEWAY_PII_ACTION/);
    expect(() => configFromEnv({ GATEWAY_INJECTION_ACTION: 'nuke' })).toThrow(/GATEWAY_INJECTION_ACTION/);
    expect(() => configFromEnv({ GATEWAY_PII_TYPES: 'email,passport' })).toThrow(/GATEWAY_PII_TYPES/);
    expect(() => configFromEnv({ GATEWAY_PORT: 'abc' })).toThrow(/GATEWAY_PORT/);
  });

  it('warns when rephrase is configured without an internal LLM key', () => {
    const savedKey = process.env.OPENAI_API_KEY;
    delete process.env.OPENAI_API_KEY;
    try {
      const warnings = configWarnings(
        resolveConfig({ apiKey: 'gw', input: { detectInjection: true, injectionSensitivity: 'medium', injectionAction: 'rephrase', logInput: false } })
      );
      expect(warnings.some((w) => w.includes('rephrase'))).toBe(true);

      const quiet = configWarnings(
        resolveConfig({
          apiKey: 'gw',
          internalLLM: { apiKey: 'sk' },
          input: { detectInjection: true, injectionSensitivity: 'medium', injectionAction: 'rephrase', logInput: false },
        })
      );
      expect(quiet).toEqual([]);
    } finally {
      if (savedKey !== undefined) process.env.OPENAI_API_KEY = savedKey;
    }
  });
});
