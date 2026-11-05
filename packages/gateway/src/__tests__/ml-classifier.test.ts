import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { Gateway } from '../index.js';
import { configFromEnv, resolveConfig, configWarnings, ConfigError } from '../config.js';
import { userText } from '../pipeline/ml-classifier.js';
import type { MLClassifier } from '@evidentai/detectors';
import type { GatewayConfig } from '../types.js';

const mockFetch = vi.fn();
global.fetch = mockFetch;

function llmReply(content = 'Sure, here you go.') {
  return new Response(
    JSON.stringify({
      id: 'chatcmpl-1',
      object: 'chat.completion',
      created: 1,
      model: 'gpt-4o-mini',
      choices: [{ index: 0, message: { role: 'assistant', content }, finish_reason: 'stop' }],
      usage: { prompt_tokens: 1, completion_tokens: 1, total_tokens: 2 },
    }),
    { status: 200, headers: { 'content-type': 'application/json' } }
  );
}

function fakeClassifier(scores: Record<string, number>, opts: { fail?: boolean } = {}): MLClassifier & { calls: string[] } {
  const calls: string[] = [];
  return {
    name: 'fake',
    calls,
    async classify(text: string) {
      calls.push(text);
      if (opts.fail) throw new Error('classifier down');
      const score = scores[text] ?? 0.05;
      return { score, label: score >= 0.5 ? 'injection' : 'benign', latencyMs: 0.2, model: 'fake-v1' };
    },
  };
}

function makeGateway(ml: Partial<NonNullable<GatewayConfig['input']['mlClassifier']>>, classifier: MLClassifier): Gateway {
  return new Gateway({
    logging: false,
    input: {
      detectInjection: false, // isolate the ML layer
      injectionSensitivity: 'medium',
      injectionAction: 'log',
      logInput: false,
      mlClassifier: { backend: 'custom', name: 'test', ...ml },
    },
    output: { detectPII: false, piiTypes: [], piiAction: 'log', logOutput: false },
    classifierFactory: () => classifier,
  });
}

async function chat(gateway: Gateway, messages: unknown[]) {
  return gateway.getServer().inject({
    method: 'POST',
    url: '/v1/chat/completions',
    headers: { 'x-llm-api-key': 'sk-test' },
    payload: { model: 'gpt-4o-mini', messages },
  });
}

describe('userText', () => {
  it('joins user messages only, including text content parts', () => {
    const text = userText([
      { role: 'system', content: 'You are helpful' },
      { role: 'user', content: 'first' },
      { role: 'assistant', content: 'reply' },
      { role: 'user', content: [{ type: 'text', text: 'second' }, { type: 'image_url', image_url: {} }] },
      { role: 'tool', content: 'tool output', tool_call_id: 'c1' },
    ]);
    expect(text).toBe('first\nsecond');
  });
});

describe('gateway ML classifier layer', () => {
  beforeEach(() => {
    mockFetch.mockReset();
    mockFetch.mockResolvedValue(llmReply());
  });
  afterEach(() => vi.restoreAllMocks());

  it('is disabled when mlClassifier is not configured', async () => {
    const gateway = new Gateway({ logging: false });
    const res = await chat(gateway, [{ role: 'user', content: 'hello' }]);
    expect(res.statusCode).toBe(200);
    expect(res.headers['x-ml-score']).toBeUndefined();
    await gateway.stop();
  });

  it('logs by default: flagged input passes through with headers', async () => {
    const classifier = fakeClassifier({ 'do the bad thing': 0.82 });
    const gateway = makeGateway({}, classifier);
    const res = await chat(gateway, [{ role: 'user', content: 'do the bad thing' }]);
    expect(res.statusCode).toBe(200);
    expect(res.headers['x-ml-score']).toBe('0.8200');
    expect(res.headers['x-ml-flagged']).toBe('true');
    expect(mockFetch).toHaveBeenCalledTimes(1);
    await gateway.stop();
  });

  it('blocks at the threshold when action is block', async () => {
    const classifier = fakeClassifier({ 'do the bad thing': 0.82, 'nice question': 0.1 });
    const gateway = makeGateway({ action: 'block', threshold: 0.8 }, classifier);

    const blocked = await chat(gateway, [{ role: 'user', content: 'do the bad thing' }]);
    expect(blocked.statusCode).toBe(403);
    const body = JSON.parse(blocked.body);
    expect(body.error.code).toBe('ml_blocked');
    expect(body.error.details.score).toBe(0.82);
    expect(body.error.details.threshold).toBe(0.8);
    expect(mockFetch).not.toHaveBeenCalled();

    const ok = await chat(gateway, [{ role: 'user', content: 'nice question' }]);
    expect(ok.statusCode).toBe(200);
    expect(ok.headers['x-ml-score']).toBe('0.1000');
    expect(ok.headers['x-ml-flagged']).toBeUndefined();
    await gateway.stop();
  });

  it('scores all user turns together and ignores system and tool messages', async () => {
    const classifier = fakeClassifier({});
    const gateway = makeGateway({}, classifier);
    await chat(gateway, [
      { role: 'system', content: 'be nice' },
      { role: 'user', content: 'part one' },
      { role: 'assistant', content: 'ok' },
      { role: 'user', content: 'part two' },
    ]);
    expect(classifier.calls).toEqual(['part one\npart two']);
    await gateway.stop();
  });

  it('fails open when the classifier errors', async () => {
    const gateway = makeGateway({ action: 'block' }, fakeClassifier({}, { fail: true }));
    const res = await chat(gateway, [{ role: 'user', content: 'anything' }]);
    expect(res.statusCode).toBe(200);
    expect(res.headers['x-ml-score']).toBeUndefined();
    expect(mockFetch).toHaveBeenCalledTimes(1);
    await gateway.stop();
  });

  it('fails closed with 503 when configured', async () => {
    const gateway = makeGateway({ action: 'block', failClosed: true }, fakeClassifier({}, { fail: true }));
    const res = await chat(gateway, [{ role: 'user', content: 'anything' }]);
    expect(res.statusCode).toBe(503);
    expect(JSON.parse(res.body).error.code).toBe('ml_unavailable');
    expect(mockFetch).not.toHaveBeenCalled();
    await gateway.stop();
  });

  it('reports the ml layer in /health', async () => {
    const gateway = makeGateway({ action: 'block', threshold: 0.7 }, fakeClassifier({}));
    const res = await gateway.getServer().inject({ method: 'GET', url: '/health' });
    const body = JSON.parse(res.body);
    expect(body.config.ml).toEqual({ enabled: true, backend: 'custom', model: undefined, threshold: 0.7, action: 'block', failClosed: false });
    await gateway.stop();
  });

  it('builds the classifier once per gateway', async () => {
    const factory = vi.fn(() => fakeClassifier({}));
    const gateway = new Gateway({
      logging: false,
      input: { detectInjection: false, injectionSensitivity: 'medium', injectionAction: 'log', logInput: false, mlClassifier: { backend: 'custom', name: 't' } },
      output: { detectPII: false, piiTypes: [], piiAction: 'log', logOutput: false },
      classifierFactory: factory,
    });
    await chat(gateway, [{ role: 'user', content: 'a' }]);
    await chat(gateway, [{ role: 'user', content: 'b' }]);
    expect(factory).toHaveBeenCalledTimes(1);
    await gateway.stop();
  });
});

describe('ML env configuration', () => {
  it('is off unless GATEWAY_ML_BACKEND is set', () => {
    expect(resolveConfig(configFromEnv({})).input.mlClassifier).toBeUndefined();
  });

  it('parses the transformers backend', () => {
    const config = resolveConfig(configFromEnv({ GATEWAY_ML_BACKEND: 'transformers', GATEWAY_ML_MODEL: './models/evident-guard', GATEWAY_ML_THRESHOLD: '0.65', GATEWAY_ML_ACTION: 'block' }));
    expect(config.input.mlClassifier).toEqual({ backend: 'transformers', model: './models/evident-guard', action: 'block', threshold: 0.65, failClosed: false });
    expect(configWarnings(config).some((w) => w.includes('transformers'))).toBe(true);
  });

  it('parses the http backend with JSON headers and requires a url', () => {
    const config = resolveConfig(
      configFromEnv({ GATEWAY_ML_BACKEND: 'http', GATEWAY_ML_URL: 'https://clf.example/score', GATEWAY_ML_HEADERS: '{"X-Token":"t"}', GATEWAY_ML_SCORE_PATH: 'result.p' })
    );
    expect(config.input.mlClassifier).toMatchObject({ backend: 'http', url: 'https://clf.example/score', headers: { 'X-Token': 't' }, scorePath: 'result.p' });

    expect(() => configFromEnv({ GATEWAY_ML_BACKEND: 'http' })).toThrow(ConfigError);
    expect(() => configFromEnv({ GATEWAY_ML_BACKEND: 'http', GATEWAY_ML_URL: 'https://x.example', GATEWAY_ML_HEADERS: 'not json' })).toThrow(ConfigError);
  });

  it('parses the jev backend and warns without a key', () => {
    const config = resolveConfig(configFromEnv({ GATEWAY_ML_BACKEND: 'jev' }));
    expect(config.input.mlClassifier).toMatchObject({ backend: 'jev', action: 'log' });
    expect(configWarnings(config).some((w) => w.includes('TYPESAFE_API_KEY'))).toBe(true);

    const keyed = resolveConfig(configFromEnv({ GATEWAY_ML_BACKEND: 'jev', TYPESAFE_API_KEY: 'k' }));
    expect(keyed.input.mlClassifier).toMatchObject({ backend: 'jev', apiKey: 'k' });
  });

  it('rejects invalid enum values', () => {
    expect(() => configFromEnv({ GATEWAY_ML_BACKEND: 'cnn' })).toThrow(ConfigError);
    expect(() => configFromEnv({ GATEWAY_ML_BACKEND: 'jev', GATEWAY_ML_ACTION: 'rephrase' })).toThrow(ConfigError);
    expect(() => configFromEnv({ GATEWAY_ML_BACKEND: 'jev', GATEWAY_ML_THRESHOLD: '1.5' })).toThrow(ConfigError);
  });
});
