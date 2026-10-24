#!/usr/bin/env node

/**
 * EvidentAI Gateway CLI
 *
 * Start the LLM security gateway server.
 *
 * Usage:
 *   evidentai-gateway            Start the gateway using environment variables
 *   evidentai-gateway --help     Show this help
 *
 * Environment Variables:
 *   GATEWAY_PORT                      Port to listen on (default: 3000)
 *   GATEWAY_HOST                      Host to bind to (default: 0.0.0.0)
 *   GATEWAY_API_KEY                   Bearer token clients must send (default: none, unauthenticated)
 *   GATEWAY_LOGGING                   Enable logging (default: true)
 *   GATEWAY_DETECT_INJECTION          Enable injection detection (default: true)
 *   GATEWAY_INJECTION_SENSITIVITY     low | medium | high (default: medium)
 *   GATEWAY_INJECTION_ACTION          log | block | rephrase (default: log)
 *   GATEWAY_INJECTION_CUSTOM_PATTERNS Comma-separated extra regex patterns
 *   OPENAI_API_KEY                    Internal LLM key used only for rephrasing
 *   GATEWAY_REPHRASE_MODEL            Model for rephrasing (default: gpt-4o-mini)
 *   GATEWAY_DETECT_PII                Enable PII detection (default: true)
 *   GATEWAY_PII_TYPES                 Comma-separated PII types (default: email,phone,ssn,credit_card)
 *   GATEWAY_PII_ACTION                redact | block | log (default: redact)
 *   GATEWAY_PII_MIN_CONFIDENCE        low | medium | high (default: medium)
 *   GATEWAY_PII_ALLOW_VALUES          Comma-separated values that are not PII
 *   GATEWAY_PII_ALLOW_PATTERNS        Comma-separated regexes whose matches are not PII
 *   GATEWAY_PII_SCAN_TOOL_ARGUMENTS   Also scan tool call arguments (default: false)
 */

const { readFileSync } = require('node:fs');

if (process.argv.includes('--help') || process.argv.includes('-h')) {
  const source = readFileSync(__filename, 'utf8');
  const header = source.match(/\/\*\*([\s\S]*?)\*\//);
  const text = header ? header[1].split('\n').map((l) => l.replace(/^\s*\*\s?/, '')).join('\n').trim() : 'evidentai-gateway';
  console.log(text);
  process.exit(0);
}

process.env.EVIDENTAI_GATEWAY_MAIN = '1';

import('../dist/index.mjs').catch((err) => {
  console.error('Failed to start EvidentAI Gateway:', err.message);
  process.exit(1);
});
