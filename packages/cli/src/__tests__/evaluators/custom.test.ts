import { describe, it, expect, afterAll, afterEach, vi } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import * as http from 'http';
import { runEvaluator } from '../../runner/evaluators';
import { loadConfigFromString } from '../../config/loader';

const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'rg-custom-'));
afterAll(() => {
  fs.rmSync(tmpDir, { recursive: true, force: true });
});

describe('CustomEvaluator', () => {
  describe('inline function', () => {
    it('passes when the function returns passed: true', async () => {
      const result = await runEvaluator('custom', {
        input: 'q',
        output: 'short',
        config: {
          function: '({ output, config }) => ({ passed: output.length < config.max, score: 0.9, reason: "ok" })',
          context: { max: 10 },
        },
      });
      expect(result.passed).toBe(true);
      expect(result.score).toBe(0.9);
      expect(result.reason).toBe('ok');
      expect(result.details?.mode).toBe('inline_function');
    });

    it('fails when the function returns passed: false', async () => {
      const result = await runEvaluator('custom', {
        input: 'q',
        output: 'a very long answer',
        config: { function: 'async ({ output }) => ({ passed: output.length < 5 })' },
      });
      expect(result.passed).toBe(false);
      expect(result.score).toBe(0);
    });

    it('times out async functions that never settle', async () => {
      const result = await runEvaluator('custom', {
        input: 'q',
        output: 'a',
        config: { function: '() => new Promise(() => {})', timeout_ms: 50 },
      });
      expect(result.passed).toBe(false);
      expect(result.reason).toContain('timed out after 50ms');
    });

    it('times out synchronous infinite loops', async () => {
      const result = await runEvaluator('custom', {
        input: 'q',
        output: 'a',
        config: { function: '() => { while (true) {} }', timeout_ms: 50 },
      });
      expect(result.passed).toBe(false);
      expect(result.reason).toContain('timed out');
    });

    it('rejects results without a boolean passed field', async () => {
      const result = await runEvaluator('custom', {
        input: 'q',
        output: 'a',
        config: { function: '() => ({ score: 1 })' },
      });
      expect(result.passed).toBe(false);
      expect(result.reason).toContain('must return { passed: boolean');
    });

    it('rejects source that is not a function', async () => {
      const result = await runEvaluator('custom', {
        input: 'q',
        output: 'a',
        config: { function: '42' },
      });
      expect(result.passed).toBe(false);
      expect(result.reason).toContain('must evaluate to a function');
    });
  });

  describe('script file', () => {
    it('runs an ESM script exporting evaluate', async () => {
      const file = path.join(tmpDir, 'eval.mjs');
      fs.writeFileSync(
        file,
        'export async function evaluate({ output, expected }) { return { passed: output === expected, reason: "esm" }; }'
      );
      const result = await runEvaluator('custom', {
        input: 'q',
        output: 'yes',
        expected: 'yes',
        config: { script: file },
      });
      expect(result.passed).toBe(true);
      expect(result.reason).toBe('esm');
      expect(result.details?.mode).toBe('script_file');
    });

    it('runs a CJS script with module.exports = function (README style)', async () => {
      const file = path.join(tmpDir, 'eval.cjs');
      fs.writeFileSync(
        file,
        'module.exports = async function({ output }) { return { passed: output.length < 500 }; };'
      );
      const result = await runEvaluator('custom', {
        input: 'q',
        output: 'concise',
        config: { script: file },
      });
      expect(result.passed).toBe(true);
    });

    it('reports a missing script', async () => {
      const result = await runEvaluator('custom', {
        input: 'q',
        output: 'a',
        config: { script: path.join(tmpDir, 'missing.js') },
      });
      expect(result.passed).toBe(false);
      expect(result.reason).toContain('not found');
    });

    it('rejects unsupported extensions', async () => {
      const file = path.join(tmpDir, 'eval.ts');
      fs.writeFileSync(file, 'export const evaluate = () => ({ passed: true });');
      const result = await runEvaluator('custom', {
        input: 'q',
        output: 'a',
        config: { script: file },
      });
      expect(result.passed).toBe(false);
      expect(result.reason).toContain('Unsupported script extension');
    });

    it('times out a script that never settles', async () => {
      const file = path.join(tmpDir, 'hang.mjs');
      fs.writeFileSync(file, 'export const evaluate = () => new Promise(() => {});');
      const result = await runEvaluator('custom', {
        input: 'q',
        output: 'a',
        config: { script: file, timeout_ms: 50 },
      });
      expect(result.passed).toBe(false);
      expect(result.reason).toContain('timed out after 50ms');
    });
  });

  describe('webhook', () => {
    let server: http.Server | undefined;
    afterEach(async () => {
      if (server) {
        await new Promise<void>((resolve) => server!.close(() => resolve()));
        server = undefined;
      }
    });

    async function startServer(handler: http.RequestListener): Promise<string> {
      server = http.createServer(handler);
      await new Promise<void>((resolve) => server!.listen(0, '127.0.0.1', () => resolve()));
      const address = server.address();
      if (!address || typeof address === 'string') throw new Error('no address');
      return `http://127.0.0.1:${address.port}/evaluate`;
    }

    it('posts the context and uses the JSON response', async () => {
      let received: unknown;
      const url = await startServer((req, res) => {
        let body = '';
        req.on('data', (c) => (body += c));
        req.on('end', () => {
          received = JSON.parse(body);
          res.setHeader('Content-Type', 'application/json');
          res.end(JSON.stringify({ passed: true, score: 0.75, reason: 'webhook ok', details: { extra: 1 } }));
        });
      });

      const result = await runEvaluator('custom', {
        input: 'q',
        output: 'a',
        expected: ['x'],
        config: { webhook: url, context: { k: 'v' } },
      });

      expect(received).toEqual({ input: 'q', output: 'a', expected: ['x'], config: { k: 'v' } });
      expect(result.passed).toBe(true);
      expect(result.score).toBe(0.75);
      expect(result.reason).toBe('webhook ok');
      expect(result.details?.extra).toBe(1);
      expect(result.details?.mode).toBe('webhook');
    });

    it('fails on non-2xx responses', async () => {
      const url = await startServer((_req, res) => {
        res.statusCode = 500;
        res.end('nope');
      });
      const result = await runEvaluator('custom', {
        input: 'q',
        output: 'a',
        config: { webhook: url },
      });
      expect(result.passed).toBe(false);
      expect(result.reason).toContain('Webhook returned 500');
    });

    it('times out slow webhooks', async () => {
      const url = await startServer(() => {
        /* never respond */
      });
      const result = await runEvaluator('custom', {
        input: 'q',
        output: 'a',
        config: { webhook: url, timeout_ms: 50 },
      });
      expect(result.passed).toBe(false);
      expect(result.reason).toContain('timed out after 50ms');
    });

    it('rejects invalid URLs', async () => {
      const result = await runEvaluator('custom', {
        input: 'q',
        output: 'a',
        config: { webhook: 'not a url' },
      });
      expect(result.passed).toBe(false);
      expect(result.reason).toContain('Invalid webhook URL');
    });

    it('uses mocked fetch when provided', async () => {
      const spy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(
        new Response(JSON.stringify({ passed: false, reason: 'mocked' }), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        })
      );
      try {
        const result = await runEvaluator('custom', {
          input: 'q',
          output: 'a',
          config: { webhook: 'https://example.com/eval' },
        });
        expect(result.passed).toBe(false);
        expect(result.reason).toBe('mocked');
        expect(spy).toHaveBeenCalledTimes(1);
      } finally {
        spy.mockRestore();
      }
    });
  });

  describe('mode selection', () => {
    it('fails when no mode is configured', async () => {
      const result = await runEvaluator('custom', { input: 'q', output: 'a', config: {} });
      expect(result.passed).toBe(false);
      expect(result.reason).toContain('No custom evaluation mode');
    });

    it('fails when several modes are configured', async () => {
      const result = await runEvaluator('custom', {
        input: 'q',
        output: 'a',
        config: { function: '() => ({ passed: true })', webhook: 'https://example.com' },
      });
      expect(result.passed).toBe(false);
      expect(result.reason).toContain('Multiple evaluation modes');
    });
  });

  describe('config schema', () => {
    const base = (configYaml: string) => `
version: "1"
project:
  name: p
provider:
  name: openai
  model: gpt-4o-mini
suites:
  - name: s
    cases:
      - name: c
        input: hi
        evaluator: custom
        config:
${configYaml}
`;

    it('accepts an inline function with timeout_ms and context', () => {
      const config = loadConfigFromString(
        base(`          function: "({ output }) => ({ passed: true })"\n          timeout_ms: 1000\n          context:\n            max: 5`)
      );
      const testCase = config.suites[0]?.cases[0];
      expect(testCase?.evaluator).toBe('custom');
      expect((testCase as { config: { timeout_ms: number } }).config.timeout_ms).toBe(1000);
      expect((testCase as { config: { context: unknown } }).config.context).toEqual({ max: 5 });
    });

    it('accepts a script path and a webhook URL', () => {
      expect(() => loadConfigFromString(base('          script: ./eval.js'))).not.toThrow();
      expect(() => loadConfigFromString(base('          webhook: https://example.com/eval'))).not.toThrow();
    });

    it('defaults timeout_ms to 30000', () => {
      const config = loadConfigFromString(base('          script: ./eval.js'));
      expect((config.suites[0]?.cases[0] as { config: { timeout_ms: number } }).config.timeout_ms).toBe(30000);
    });

    it('rejects zero or several modes', () => {
      expect(() => loadConfigFromString(base('          timeout_ms: 10'))).toThrow(/exactly one of/);
      expect(() =>
        loadConfigFromString(base('          script: ./eval.js\n          webhook: https://example.com/eval'))
      ).toThrow(/exactly one of/);
    });

    it('rejects an invalid webhook URL', () => {
      expect(() => loadConfigFromString(base('          webhook: not-a-url'))).toThrow(/valid URL/);
    });
  });
});
