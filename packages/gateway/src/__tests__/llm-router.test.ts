import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { routeToLLM } from '../router/llm-router.js';
import type { ChatCompletionRequest, LLMProviderConfig } from '../types.js';

// Mock fetch globally
const mockFetch = vi.fn();
global.fetch = mockFetch;

describe('LLM Router', () => {
  beforeEach(() => {
    mockFetch.mockReset();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  const baseRequest: ChatCompletionRequest = {
    model: 'gpt-4o-mini',
    messages: [{ role: 'user', content: 'Hello' }],
  };

  describe('OpenAI Routing', () => {
    const openaiConfig: LLMProviderConfig = {
      name: 'openai',
      apiKey: 'test-key',
    };

    it('sends correct headers and body to OpenAI', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () =>
          Promise.resolve({
            id: 'chatcmpl-123',
            object: 'chat.completion',
            created: 1234567890,
            model: 'gpt-4o-mini',
            choices: [
              {
                index: 0,
                message: { role: 'assistant', content: 'Hi!' },
                finish_reason: 'stop',
              },
            ],
            usage: { prompt_tokens: 10, completion_tokens: 5, total_tokens: 15 },
          }),
      });

      await routeToLLM(openaiConfig, baseRequest);

      expect(mockFetch).toHaveBeenCalledWith(
        'https://api.openai.com/v1/chat/completions',
        expect.objectContaining({
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            Authorization: 'Bearer test-key',
          },
        })
      );
    });

    it('returns OpenAI-compatible response', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () =>
          Promise.resolve({
            id: 'chatcmpl-123',
            object: 'chat.completion',
            created: 1234567890,
            model: 'gpt-4o-mini',
            choices: [
              {
                index: 0,
                message: { role: 'assistant', content: 'Hello!' },
                finish_reason: 'stop',
              },
            ],
          }),
      });

      const result = await routeToLLM(openaiConfig, baseRequest);

      expect(result.id).toBe('chatcmpl-123');
      expect(result.object).toBe('chat.completion');
      expect(result.choices[0]?.message.content).toBe('Hello!');
    });

    it('forwards every request field and preserves tool_calls, refusal and finish_reason', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () =>
          Promise.resolve({
            id: 'chatcmpl-123',
            object: 'chat.completion',
            created: 1,
            model: 'gpt-4o-mini',
            choices: [
              {
                index: 0,
                message: {
                  role: 'assistant',
                  content: null,
                  refusal: null,
                  tool_calls: [{ id: 'call_1', type: 'function', function: { name: 'f', arguments: '{}' } }],
                },
                finish_reason: 'tool_calls',
                logprobs: null,
              },
            ],
            usage: { prompt_tokens: 1, completion_tokens: 1, total_tokens: 2 },
            system_fingerprint: 'fp_1',
          }),
      });

      const result = await routeToLLM(openaiConfig, {
        ...baseRequest,
        tools: [{ type: 'function', function: { name: 'f' } }],
        tool_choice: 'auto',
        response_format: { type: 'json_object' },
        seed: 7,
        stream: true, // stripped: streaming is not proxied
        future_field: 'kept',
      });

      const body = JSON.parse(mockFetch.mock.calls[0]?.[1]?.body as string);
      expect(body.tools).toEqual([{ type: 'function', function: { name: 'f' } }]);
      expect(body.tool_choice).toBe('auto');
      expect(body.response_format).toEqual({ type: 'json_object' });
      expect(body.seed).toBe(7);
      expect(body.future_field).toBe('kept');
      expect(body.stream).toBeUndefined();

      expect(result.choices[0]?.finish_reason).toBe('tool_calls');
      expect(result.choices[0]?.message.tool_calls?.[0]?.id).toBe('call_1');
      expect(result.choices[0]?.message.refusal).toBeNull();
      expect(result.system_fingerprint).toBe('fp_1');
    });

    it('throws ProviderError on API error', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 401,
        text: () => Promise.resolve('Unauthorized'),
      });

      await expect(routeToLLM(openaiConfig, baseRequest)).rejects.toThrow(
        'OpenAI API error: 401'
      );
    });
  });

  describe('Anthropic Routing', () => {
    const anthropicConfig: LLMProviderConfig = {
      name: 'anthropic',
      apiKey: 'test-key',
    };

    const anthropicRequest: ChatCompletionRequest = {
      model: 'claude-3-haiku-20240307',
      messages: [{ role: 'user', content: 'Hello' }],
    };

    it('converts OpenAI format to Anthropic format', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () =>
          Promise.resolve({
            id: 'msg_123',
            type: 'message',
            role: 'assistant',
            content: [{ type: 'text', text: 'Hi there!' }],
            model: 'claude-3-haiku-20240307',
            stop_reason: 'end_turn',
            usage: { input_tokens: 10, output_tokens: 5 },
          }),
      });

      await routeToLLM(anthropicConfig, anthropicRequest);

      expect(mockFetch).toHaveBeenCalledWith(
        'https://api.anthropic.com/v1/messages',
        expect.objectContaining({
          method: 'POST',
          headers: expect.objectContaining({
            'x-api-key': 'test-key',
            'anthropic-version': '2023-06-01',
          }),
        })
      );
    });

    it('converts Anthropic response to OpenAI format', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () =>
          Promise.resolve({
            id: 'msg_123',
            type: 'message',
            role: 'assistant',
            content: [{ type: 'text', text: 'Hello from Claude!' }],
            model: 'claude-3-haiku-20240307',
            stop_reason: 'end_turn',
            usage: { input_tokens: 10, output_tokens: 5 },
          }),
      });

      const result = await routeToLLM(anthropicConfig, anthropicRequest);

      expect(result.object).toBe('chat.completion');
      expect(result.choices[0]?.message.role).toBe('assistant');
      expect(result.choices[0]?.message.content).toBe('Hello from Claude!');
      expect(result.choices[0]?.finish_reason).toBe('stop');
      expect(result.usage?.total_tokens).toBe(15);
    });

    const anthropicOk = (content: unknown[], stop_reason = 'end_turn') => ({
      ok: true,
      json: () =>
        Promise.resolve({
          id: 'msg_123',
          type: 'message',
          role: 'assistant',
          content,
          model: 'claude-sonnet-4-20250514',
          stop_reason,
          usage: { input_tokens: 10, output_tokens: 5 },
        }),
    });

    it('translates OpenAI tools and tool_choice into Anthropic tools', async () => {
      mockFetch.mockResolvedValueOnce(anthropicOk([{ type: 'text', text: 'ok' }]));

      await routeToLLM(anthropicConfig, {
        model: 'claude-sonnet-4-20250514',
        messages: [{ role: 'user', content: 'Hi' }],
        tools: [
          { type: 'function', function: { name: 'lookup', description: 'Look up', parameters: { type: 'object', properties: {} } } },
          { type: 'function', function: { name: 'noschema' } },
        ],
        tool_choice: 'required',
        parallel_tool_calls: false,
      });

      const body = JSON.parse(mockFetch.mock.calls[0]?.[1]?.body as string);
      expect(body.tools).toEqual([
        { name: 'lookup', description: 'Look up', input_schema: { type: 'object', properties: {} } },
        { name: 'noschema', input_schema: { type: 'object', properties: {} } },
      ]);
      expect(body.tool_choice).toEqual({ type: 'any', disable_parallel_tool_use: true });
    });

    it('omits tools entirely when tool_choice is none', async () => {
      mockFetch.mockResolvedValueOnce(anthropicOk([{ type: 'text', text: 'ok' }]));

      await routeToLLM(anthropicConfig, {
        model: 'claude-sonnet-4-20250514',
        messages: [{ role: 'user', content: 'Hi' }],
        tools: [{ type: 'function', function: { name: 'lookup' } }],
        tool_choice: 'none',
      });

      const body = JSON.parse(mockFetch.mock.calls[0]?.[1]?.body as string);
      expect(body.tools).toBeUndefined();
      expect(body.tool_choice).toBeUndefined();
    });

    it('maps assistant tool_calls and tool results into tool_use / tool_result blocks', async () => {
      mockFetch.mockResolvedValueOnce(anthropicOk([{ type: 'text', text: 'Sunny.' }]));

      await routeToLLM(anthropicConfig, {
        model: 'claude-sonnet-4-20250514',
        messages: [
          { role: 'system', content: 'Be brief.' },
          { role: 'user', content: 'Weather?' },
          {
            role: 'assistant',
            content: null,
            tool_calls: [{ id: 'toolu_1', type: 'function', function: { name: 'get_weather', arguments: '{"city":"Paris"}' } }],
          },
          { role: 'tool', tool_call_id: 'toolu_1', content: '{"temp": 21}' },
        ],
        tools: [{ type: 'function', function: { name: 'get_weather' } }],
      });

      const body = JSON.parse(mockFetch.mock.calls[0]?.[1]?.body as string);
      expect(body.system).toBe('Be brief.');
      expect(body.messages).toEqual([
        { role: 'user', content: 'Weather?' },
        { role: 'assistant', content: [{ type: 'tool_use', id: 'toolu_1', name: 'get_weather', input: { city: 'Paris' } }] },
        { role: 'user', content: [{ type: 'tool_result', tool_use_id: 'toolu_1', content: '{"temp": 21}' }] },
      ]);
    });

    it('maps tool_use response blocks to OpenAI tool_calls', async () => {
      mockFetch.mockResolvedValueOnce(
        anthropicOk([{ type: 'tool_use', id: 'toolu_9', name: 'get_weather', input: { city: 'Oslo' } }], 'tool_use')
      );

      const result = await routeToLLM(anthropicConfig, {
        model: 'claude-sonnet-4-20250514',
        messages: [{ role: 'user', content: 'Weather in Oslo?' }],
        tools: [{ type: 'function', function: { name: 'get_weather' } }],
      });

      expect(result.choices[0]?.finish_reason).toBe('tool_calls');
      expect(result.choices[0]?.message.content).toBeNull();
      expect(result.choices[0]?.message.tool_calls).toEqual([
        { id: 'toolu_9', type: 'function', function: { name: 'get_weather', arguments: '{"city":"Oslo"}' } },
      ]);
    });

    it('rejects shapes it cannot translate instead of dropping them', async () => {
      await expect(
        routeToLLM(anthropicConfig, {
          model: 'claude-sonnet-4-20250514',
          messages: [{ role: 'user', content: 'Hi' }],
          functions: [{ name: 'legacy' }],
        })
      ).rejects.toThrow('not supported for Anthropic');

      await expect(
        routeToLLM(anthropicConfig, {
          model: 'claude-sonnet-4-20250514',
          messages: [{ role: 'tool', content: 'x' }],
        })
      ).rejects.toThrow('tool_call_id');

      await expect(
        routeToLLM(anthropicConfig, {
          model: 'claude-sonnet-4-20250514',
          messages: [{ role: 'user', content: 'Hi' }],
          n: 2,
        })
      ).rejects.toThrow('n > 1');

      expect(mockFetch).not.toHaveBeenCalled();
    });

    it('handles system messages for Anthropic', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () =>
          Promise.resolve({
            id: 'msg_123',
            type: 'message',
            role: 'assistant',
            content: [{ type: 'text', text: 'Response' }],
            model: 'claude-3-haiku-20240307',
            stop_reason: 'end_turn',
            usage: { input_tokens: 10, output_tokens: 5 },
          }),
      });

      const requestWithSystem: ChatCompletionRequest = {
        model: 'claude-3-haiku-20240307',
        messages: [
          { role: 'system', content: 'You are helpful.' },
          { role: 'user', content: 'Hi' },
        ],
      };

      await routeToLLM(anthropicConfig, requestWithSystem);

      const calledBody = JSON.parse(
        mockFetch.mock.calls[0]?.[1]?.body as string
      );
      expect(calledBody.system).toBe('You are helpful.');
    });
  });

  describe('Azure Routing', () => {
    const azureConfig: LLMProviderConfig = {
      name: 'azure',
      apiKey: 'test-key',
      endpoint: 'https://myinstance.openai.azure.com',
      deployment: 'gpt-4o',
    };

    it('sends correct Azure endpoint and headers', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () =>
          Promise.resolve({
            id: 'chatcmpl-123',
            object: 'chat.completion',
            created: 1234567890,
            model: 'gpt-4o',
            choices: [
              {
                index: 0,
                message: { role: 'assistant', content: 'Azure response' },
                finish_reason: 'stop',
              },
            ],
          }),
      });

      await routeToLLM(azureConfig, baseRequest);

      expect(mockFetch).toHaveBeenCalledWith(
        expect.stringContaining('myinstance.openai.azure.com'),
        expect.objectContaining({
          headers: expect.objectContaining({
            'api-key': 'test-key',
          }),
        })
      );
    });

    it('throws error if endpoint is missing', async () => {
      const badConfig: LLMProviderConfig = {
        name: 'azure',
        apiKey: 'test-key',
        deployment: 'gpt-4o',
      };

      await expect(routeToLLM(badConfig, baseRequest)).rejects.toThrow(
        'Azure endpoint is required'
      );
    });

    it('throws error if deployment is missing', async () => {
      const badConfig: LLMProviderConfig = {
        name: 'azure',
        apiKey: 'test-key',
        endpoint: 'https://test.openai.azure.com',
      };

      await expect(routeToLLM(badConfig, baseRequest)).rejects.toThrow(
        'Azure deployment is required'
      );
    });
  });

  describe('Provider Detection', () => {
    it('throws error for unsupported provider', async () => {
      const badConfig = {
        name: 'unsupported' as unknown as 'openai',
        apiKey: 'test-key',
      };

      await expect(routeToLLM(badConfig, baseRequest)).rejects.toThrow(
        'Unsupported provider'
      );
    });
  });
});
