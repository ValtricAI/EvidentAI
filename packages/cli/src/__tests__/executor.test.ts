import { describe, it, expect } from 'vitest';
import { Executor, runWithConcurrency, withRetry } from '../runner/executor';
import { APIError } from '../runner/providers';
import type { Config } from '../config/types';

function makeConfig(cases: number): Config {
  return {
    version: '1',
    project: { name: 'concurrency-test' },
    provider: { name: 'openai', api_key: 'sk-test', model: 'gpt-4o-mini', timeout_ms: 60000 },
    suites: [
      {
        name: 'suite',
        cases: Array.from({ length: cases }, (_, i) => ({
          name: `t${i}`,
          input: `${i}`,
          evaluator: 'contains' as const,
          expected: [`${i}`],
        })),
      },
    ],
  } as Config;
}

function fakeProvider(opts: { failInputs?: Set<string>; failWithStatus?: number } = {}) {
  let inflight = 0;
  let maxInflight = 0;
  const calls: Record<string, number> = {};
  return {
    stats: () => ({ maxInflight, calls }),
    provider: {
      call: async (input: string) => {
        calls[input] = (calls[input] ?? 0) + 1;
        inflight++;
        maxInflight = Math.max(maxInflight, inflight);
        await new Promise((r) => setTimeout(r, 1 + Math.random() * 10));
        inflight--;
        if (opts.failInputs?.has(input)) {
          throw new APIError('boom', opts.failWithStatus ?? 500, 'fake');
        }
        return `answer ${input}`;
      },
    },
  };
}

describe('runWithConcurrency', () => {
  it.each([1, 3, 10])('never exceeds concurrency %i and preserves order', async (concurrency) => {
    let inflight = 0;
    let maxInflight = 0;
    const tasks = Array.from({ length: 30 }, (_, i) => async () => {
      inflight++;
      maxInflight = Math.max(maxInflight, inflight);
      await new Promise((r) => setTimeout(r, Math.random() * 10));
      inflight--;
      return i;
    });

    const results = await runWithConcurrency(tasks, concurrency);

    expect(maxInflight).toBeLessThanOrEqual(concurrency);
    expect(maxInflight).toBeGreaterThan(0);
    expect(results).toEqual(Array.from({ length: 30 }, (_, i) => i));
  });

  it('propagates the first rejection and stops starting new tasks', async () => {
    let started = 0;
    const tasks = Array.from({ length: 20 }, (_, i) => async () => {
      started++;
      await new Promise((r) => setTimeout(r, 2));
      if (i === 2) throw new Error('task 2 failed');
      return i;
    });

    await expect(runWithConcurrency(tasks, 2)).rejects.toThrow('task 2 failed');
    expect(started).toBeLessThan(20);
  });

  it('handles an empty task list', async () => {
    expect(await runWithConcurrency([], 5)).toEqual([]);
  });
});

describe('withRetry', () => {
  it('reports zero retries when the first attempt succeeds', async () => {
    const r = await withRetry(async () => 'ok', 3, 1);
    expect(r).toEqual({ result: 'ok', retries: 0 });
  });

  it('reports the number of retries performed on eventual success', async () => {
    let attempt = 0;
    const r = await withRetry(
      async () => {
        attempt++;
        if (attempt < 3) throw new APIError('rate limited', 429, 'fake');
        return 'ok';
      },
      5,
      1
    );
    expect(r.retries).toBe(2);
  });

  it('fails fast on non-retryable errors with zero retries', async () => {
    let attempt = 0;
    const err = await withRetry(
      async () => {
        attempt++;
        throw new APIError('bad request', 400, 'fake');
      },
      3,
      1
    ).catch((e) => e);
    expect(err.name).toBe('RetryExhaustedError');
    expect(err.retries).toBe(0);
    expect(attempt).toBe(1);
  });
});

describe('Executor', () => {
  it.each([1, 3, 10])('limits in-flight provider calls to %i and keeps case order', async (concurrency) => {
    const executor = new Executor(makeConfig(30), { concurrency, maxRetries: 0 });
    const fake = fakeProvider();
    (executor as unknown as { provider: unknown }).provider = fake.provider;

    const result = await executor.run();

    expect(fake.stats().maxInflight).toBeLessThanOrEqual(concurrency);
    expect(result.suites[0]?.testCases.map((t) => t.name)).toEqual(
      Array.from({ length: 30 }, (_, i) => `t${i}`)
    );
    expect(result.passed).toBe(30);
  });

  it('reports the retries actually performed on a failed case', async () => {
    const executor = new Executor(makeConfig(3), { concurrency: 2, maxRetries: 2, retryDelayMs: 1 });
    const fake = fakeProvider({ failInputs: new Set(['1']), failWithStatus: 500 });
    (executor as unknown as { provider: unknown }).provider = fake.provider;

    const result = await executor.run();
    const failed = result.suites[0]?.testCases.find((t) => t.name === 't1');

    expect(failed?.result.passed).toBe(false);
    expect(failed?.result.reason).toContain('LLM call failed');
    expect(failed?.retries).toBe(2);
    expect(fake.stats().calls['1']).toBe(3);
    expect(result.suites[0]?.testCases.find((t) => t.name === 't0')?.retries).toBe(0);
  });

  it('does not retry non-retryable provider errors', async () => {
    const executor = new Executor(makeConfig(1), { concurrency: 1, maxRetries: 3, retryDelayMs: 1 });
    const fake = fakeProvider({ failInputs: new Set(['0']), failWithStatus: 401 });
    (executor as unknown as { provider: unknown }).provider = fake.provider;

    const result = await executor.run();
    const failed = result.suites[0]?.testCases[0];

    expect(failed?.result.passed).toBe(false);
    expect(failed?.retries).toBe(0);
    expect(fake.stats().calls['0']).toBe(1);
  });
});
