/**
 * LLM Router
 *
 * Routes requests to the appropriate LLM provider (OpenAI, Anthropic, Azure)
 * and converts between API formats.
 *
 * OpenAI and Azure speak the OpenAI wire format, so the request is forwarded
 * as-is (minus gateway-only fields) and the response is passed through with
 * tool calls, refusals and finish reasons intact.
 *
 * Anthropic requests are translated: system messages become the `system`
 * field, OpenAI tools become Anthropic tools, assistant tool calls become
 * `tool_use` blocks, tool results become `tool_result` blocks, and the
 * response is converted back. Shapes that cannot be translated raise a
 * ValidationError rather than being dropped.
 */

import { nanoid } from 'nanoid';
import type {
  LLMProviderConfig,
  ChatCompletionRequest,
  ChatCompletionResponse,
  ChatCompletionChoice,
  ChatMessage,
  ContentPart,
  FinishReason,
  ToolCall,
  ToolChoice,
  ToolDefinition,
} from '../types.js';
import { ProviderError, ValidationError } from '../types.js';

// =============================================================================
// Provider Configuration
// =============================================================================

const PROVIDER_DEFAULTS = {
  openai: {
    baseUrl: 'https://api.openai.com/v1',
    defaultModel: 'gpt-4o-mini',
  },
  anthropic: {
    baseUrl: 'https://api.anthropic.com/v1',
    defaultModel: 'claude-3-5-haiku-20241022',
    version: '2023-06-01',
    maxTokens: 4096,
  },
  azure: {
    apiVersion: '2024-10-21',
    defaultModel: 'gpt-4o',
  },
};

const TIMEOUT_MS = 60000;

/** Fields the gateway consumes itself and must not forward. */
const GATEWAY_ONLY_FIELDS = new Set<string>([]);

// =============================================================================
// Wire Types
// =============================================================================

interface OpenAIWireResponse {
  id: string;
  object: string;
  created: number;
  model: string;
  choices: Array<{
    index: number;
    message: ChatMessage;
    finish_reason: string | null;
    logprobs?: unknown;
  }>;
  usage?: {
    prompt_tokens: number;
    completion_tokens: number;
    total_tokens: number;
    [key: string]: unknown;
  };
  system_fingerprint?: string;
}

type AnthropicContentBlock =
  | { type: 'text'; text: string }
  | { type: 'tool_use'; id: string; name: string; input: Record<string, unknown> }
  | { type: 'tool_result'; tool_use_id: string; content: string; is_error?: boolean };

interface AnthropicMessage {
  role: 'user' | 'assistant';
  content: string | AnthropicContentBlock[];
}

interface AnthropicResponse {
  id: string;
  type: string;
  role: string;
  content: Array<{ type: string; text?: string; id?: string; name?: string; input?: Record<string, unknown> }>;
  model: string;
  stop_reason: string | null;
  usage: {
    input_tokens: number;
    output_tokens: number;
  };
}

// =============================================================================
// Main Router Function
// =============================================================================

export async function routeToLLM(
  config: LLMProviderConfig,
  request: ChatCompletionRequest
): Promise<ChatCompletionResponse> {
  switch (config.name) {
    case 'openai':
      return routeToOpenAI(config, request);
    case 'anthropic':
      return routeToAnthropic(config, request);
    case 'azure':
      return routeToAzure(config, request);
    default:
      throw new ProviderError(`Unsupported provider: ${String(config.name)}`, String(config.name));
  }
}

// =============================================================================
// Shared helpers
// =============================================================================

async function postJSON<T>(
  url: string,
  headers: Record<string, string>,
  body: unknown,
  provider: string,
  label: string
): Promise<T> {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), TIMEOUT_MS);

  try {
    const response = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...headers },
      body: JSON.stringify(body),
      signal: controller.signal,
    });

    if (!response.ok) {
      const error = await response.text();
      throw new ProviderError(`${label} API error: ${response.status} - ${error}`, provider, response.status);
    }

    return (await response.json()) as T;
  } catch (error) {
    if (error instanceof Error && error.name === 'AbortError') {
      throw new ProviderError(`${label} request timed out`, provider, 408);
    }
    throw error;
  } finally {
    clearTimeout(timeoutId);
  }
}

/** Copy every request field except gateway-only ones and `stream`. */
function forwardableBody(request: ChatCompletionRequest): Record<string, unknown> {
  const body: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(request)) {
    if (GATEWAY_ONLY_FIELDS.has(key) || value === undefined) continue;
    if (key === 'stream' || key === 'stream_options') continue; // streaming is not supported yet
    body[key] = value;
  }
  return body;
}

const FINISH_REASONS: ReadonlySet<string> = new Set(['stop', 'length', 'function_call', 'tool_calls', 'content_filter']);

function normalizeFinishReason(reason: string | null | undefined): FinishReason {
  if (reason && FINISH_REASONS.has(reason)) {
    return reason as Exclude<FinishReason, null>;
  }
  return reason ? 'stop' : null;
}

function passThroughChoices(data: OpenAIWireResponse): ChatCompletionChoice[] {
  return data.choices.map((choice) => ({
    index: choice.index,
    // Keep tool_calls, function_call, refusal and any other message fields.
    message: { ...choice.message },
    finish_reason: normalizeFinishReason(choice.finish_reason),
    ...(choice.logprobs !== undefined ? { logprobs: choice.logprobs } : {}),
  }));
}

// =============================================================================
// OpenAI Router
// =============================================================================

async function routeToOpenAI(
  config: LLMProviderConfig,
  request: ChatCompletionRequest
): Promise<ChatCompletionResponse> {
  const baseUrl = config.baseUrl || PROVIDER_DEFAULTS.openai.baseUrl;
  const url = `${baseUrl}/chat/completions`;

  const data = await postJSON<OpenAIWireResponse>(
    url,
    { Authorization: `Bearer ${config.apiKey}` },
    { ...forwardableBody(request), model: request.model || PROVIDER_DEFAULTS.openai.defaultModel },
    'openai',
    'OpenAI'
  );

  return {
    id: data.id,
    object: 'chat.completion',
    created: data.created,
    model: data.model,
    choices: passThroughChoices(data),
    usage: data.usage,
    ...(data.system_fingerprint ? { system_fingerprint: data.system_fingerprint } : {}),
  };
}

// =============================================================================
// Azure OpenAI Router
// =============================================================================

async function routeToAzure(
  config: LLMProviderConfig,
  request: ChatCompletionRequest
): Promise<ChatCompletionResponse> {
  if (!config.endpoint) {
    throw new ProviderError('Azure endpoint is required (X-Azure-Endpoint header)', 'azure');
  }
  if (!config.deployment) {
    throw new ProviderError('Azure deployment is required (X-Azure-Deployment header)', 'azure');
  }

  const apiVersion = config.apiVersion || PROVIDER_DEFAULTS.azure.apiVersion;
  const url = `${config.endpoint}/openai/deployments/${config.deployment}/chat/completions?api-version=${apiVersion}`;

  // Azure selects the model by deployment; the body's model field is ignored
  // but harmless, so forward the request unchanged.
  const data = await postJSON<OpenAIWireResponse>(
    url,
    { 'api-key': config.apiKey },
    forwardableBody(request),
    'azure',
    'Azure OpenAI'
  );

  return {
    id: data.id,
    object: 'chat.completion',
    created: data.created,
    model: data.model,
    choices: passThroughChoices(data),
    usage: data.usage,
    ...(data.system_fingerprint ? { system_fingerprint: data.system_fingerprint } : {}),
  };
}

// =============================================================================
// Anthropic Router
// =============================================================================

async function routeToAnthropic(
  config: LLMProviderConfig,
  request: ChatCompletionRequest
): Promise<ChatCompletionResponse> {
  const baseUrl = config.baseUrl || PROVIDER_DEFAULTS.anthropic.baseUrl;
  const url = `${baseUrl}/messages`;

  if (request.n !== undefined && request.n > 1) {
    throw new ValidationError('Anthropic does not support n > 1; send one request per completion');
  }
  if (request.functions || request.function_call) {
    throw new ValidationError(
      'Legacy `functions` / `function_call` are not supported for Anthropic; use `tools` and `tool_choice`'
    );
  }

  const { systemMessage, messages } = convertToAnthropicMessages(request.messages);
  const { tools, toolChoice } = convertToAnthropicTools(request.tools, request.tool_choice, request.parallel_tool_calls);

  const body: Record<string, unknown> = {
    model: request.model || PROVIDER_DEFAULTS.anthropic.defaultModel,
    max_tokens: request.max_completion_tokens || request.max_tokens || PROVIDER_DEFAULTS.anthropic.maxTokens,
    messages,
    system: systemMessage,
    temperature: request.temperature,
    top_p: request.top_p,
    stop_sequences: Array.isArray(request.stop) ? request.stop : request.stop ? [request.stop] : undefined,
    metadata: request.user ? { user_id: request.user } : undefined,
  };
  if (tools) body.tools = tools;
  if (toolChoice) body.tool_choice = toolChoice;

  const data = await postJSON<AnthropicResponse>(
    url,
    {
      'x-api-key': config.apiKey,
      'anthropic-version': PROVIDER_DEFAULTS.anthropic.version,
    },
    body,
    'anthropic',
    'Anthropic'
  );

  return convertFromAnthropicResponse(data);
}

// =============================================================================
// Anthropic conversion helpers
// =============================================================================

function contentToText(content: string | ContentPart[] | null): string {
  if (content === null) return '';
  if (typeof content === 'string') return content;
  return content
    .map((part) => {
      if (part.type === 'text' && typeof part.text === 'string') return part.text;
      throw new ValidationError(
        `Content part type "${part.type}" cannot be translated for Anthropic; only text parts are supported`
      );
    })
    .join('');
}

function parseToolArguments(args: string, toolName: string): Record<string, unknown> {
  if (!args.trim()) return {};
  try {
    const parsed: unknown = JSON.parse(args);
    if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
      return parsed as Record<string, unknown>;
    }
  } catch {
    // fall through
  }
  throw new ValidationError(`tool_calls arguments for "${toolName}" must be a JSON object string to translate for Anthropic`);
}

export function convertToAnthropicMessages(messages: ChatMessage[]): {
  systemMessage: string | undefined;
  messages: AnthropicMessage[];
} {
  let systemMessage: string | undefined;
  const converted: AnthropicMessage[] = [];

  const push = (role: 'user' | 'assistant', blocks: AnthropicContentBlock[]) => {
    const last = converted[converted.length - 1];
    if (last && last.role === role) {
      // Anthropic requires alternating roles: merge consecutive same-role turns.
      const existing = typeof last.content === 'string' ? [{ type: 'text', text: last.content } as AnthropicContentBlock] : last.content;
      last.content = [...existing, ...blocks];
    } else {
      converted.push({ role, content: blocks });
    }
  };

  for (const msg of messages) {
    switch (msg.role) {
      case 'system':
      case 'developer': {
        const text = contentToText(msg.content);
        systemMessage = systemMessage ? `${systemMessage}\n\n${text}` : text;
        break;
      }
      case 'user': {
        push('user', [{ type: 'text', text: contentToText(msg.content) }]);
        break;
      }
      case 'assistant': {
        const blocks: AnthropicContentBlock[] = [];
        const text = contentToText(msg.content);
        if (text) blocks.push({ type: 'text', text });
        for (const call of msg.tool_calls ?? []) {
          blocks.push({
            type: 'tool_use',
            id: call.id,
            name: call.function.name,
            input: parseToolArguments(call.function.arguments, call.function.name),
          });
        }
        if (msg.function_call) {
          throw new ValidationError('Legacy assistant `function_call` messages cannot be translated for Anthropic; use tool_calls');
        }
        if (blocks.length === 0) blocks.push({ type: 'text', text: '' });
        push('assistant', blocks);
        break;
      }
      case 'tool': {
        if (!msg.tool_call_id) {
          throw new ValidationError('`tool` role messages require tool_call_id to translate for Anthropic');
        }
        push('user', [{ type: 'tool_result', tool_use_id: msg.tool_call_id, content: contentToText(msg.content) }]);
        break;
      }
      case 'function':
        throw new ValidationError('Legacy `function` role messages cannot be translated for Anthropic; use the `tool` role');
    }
  }

  // Anthropic requires the conversation to start with a user turn.
  if (converted.length > 0 && converted[0]?.role === 'assistant') {
    converted.unshift({ role: 'user', content: [{ type: 'text', text: 'Continue' }] });
  }

  // Collapse single text blocks back to plain strings for readability.
  for (const m of converted) {
    if (Array.isArray(m.content) && m.content.length === 1 && m.content[0]?.type === 'text') {
      m.content = m.content[0].text;
    }
  }

  return { systemMessage, messages: converted };
}

export function convertToAnthropicTools(
  tools: ToolDefinition[] | undefined,
  toolChoice: ToolChoice | undefined,
  parallelToolCalls: boolean | undefined
): {
  tools?: Array<{ name: string; description?: string; input_schema: Record<string, unknown> }>;
  toolChoice?: Record<string, unknown>;
} {
  if (!tools || tools.length === 0) {
    if (toolChoice && toolChoice !== 'none') {
      throw new ValidationError('tool_choice was given without any tools');
    }
    return {};
  }

  if (toolChoice === 'none') {
    // The model must not call tools: the simplest faithful translation is to send none.
    return {};
  }

  const converted = tools.map((tool) => {
    if (tool.type !== 'function') {
      throw new ValidationError(`Tool type "${String(tool.type)}" cannot be translated for Anthropic`);
    }
    return {
      name: tool.function.name,
      ...(tool.function.description ? { description: tool.function.description } : {}),
      input_schema: tool.function.parameters ?? { type: 'object', properties: {} },
    };
  });

  const disableParallel = parallelToolCalls === false ? { disable_parallel_tool_use: true } : {};
  let choice: Record<string, unknown> | undefined;
  if (toolChoice === undefined || toolChoice === 'auto') {
    choice = toolChoice === undefined && parallelToolCalls !== false ? undefined : { type: 'auto', ...disableParallel };
  } else if (toolChoice === 'required') {
    choice = { type: 'any', ...disableParallel };
  } else if (typeof toolChoice === 'object' && toolChoice.type === 'function') {
    choice = { type: 'tool', name: toolChoice.function.name, ...disableParallel };
  } else {
    throw new ValidationError(`Unsupported tool_choice value: ${JSON.stringify(toolChoice)}`);
  }

  return { tools: converted, toolChoice: choice };
}

export function convertFromAnthropicResponse(data: AnthropicResponse): ChatCompletionResponse {
  const textParts: string[] = [];
  const toolCalls: ToolCall[] = [];

  for (const block of data.content) {
    if (block.type === 'text' && typeof block.text === 'string') {
      textParts.push(block.text);
    } else if (block.type === 'tool_use' && block.id && block.name) {
      toolCalls.push({
        id: block.id,
        type: 'function',
        function: { name: block.name, arguments: JSON.stringify(block.input ?? {}) },
      });
    }
  }

  const message: ChatMessage = {
    role: 'assistant',
    content: textParts.length > 0 ? textParts.join('') : toolCalls.length > 0 ? null : '',
  };
  if (toolCalls.length > 0) message.tool_calls = toolCalls;

  return {
    id: `chatcmpl-${nanoid()}`,
    object: 'chat.completion',
    created: Math.floor(Date.now() / 1000),
    model: data.model,
    choices: [
      {
        index: 0,
        message,
        finish_reason: mapAnthropicStopReason(data.stop_reason, toolCalls.length > 0),
      },
    ],
    usage: {
      prompt_tokens: data.usage.input_tokens,
      completion_tokens: data.usage.output_tokens,
      total_tokens: data.usage.input_tokens + data.usage.output_tokens,
    },
  };
}

function mapAnthropicStopReason(reason: string | null, hasToolCalls: boolean): FinishReason {
  if (hasToolCalls || reason === 'tool_use') return 'tool_calls';
  if (!reason) return null;

  switch (reason) {
    case 'end_turn':
    case 'stop_sequence':
      return 'stop';
    case 'max_tokens':
      return 'length';
    case 'refusal':
      return 'content_filter';
    default:
      return 'stop';
  }
}
