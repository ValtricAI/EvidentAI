/**
 * Chat Completions Route Handler
 *
 * Implements the OpenAI-compatible /v1/chat/completions endpoint with:
 * - Input sanitization (injection detection on user messages)
 * - LLM routing (OpenAI, Anthropic, Azure) with tool calling preserved
 * - Output processing (PII detection and redaction on every choice)
 *
 * Validation is deliberately permissive: known fields are checked for shape
 * and unknown fields pass through, so new OpenAI parameters keep working
 * without a gateway release.
 */

import type { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';
import { z } from 'zod';
import { nanoid } from 'nanoid';
import type {
  GatewayConfig,
  ChatCompletionRequest,
  ChatCompletionResponse,
  ChatCompletionChoice,
  LLMProviderName,
  LLMProviderConfig,
  OutputProcessingResult,
} from '../types.js';
import { ValidationError, InjectionBlockedError, PIIBlockedError, ProviderError, GatewayError } from '../types.js';
import { sanitizeInput } from '../pipeline/input-sanitizer.js';
import { processOutput } from '../pipeline/output-processor.js';
import { routeToLLM } from '../router/llm-router.js';

// =============================================================================
// Request Validation Schema
// =============================================================================

const ToolCallSchema = z.object({
  id: z.string(),
  type: z.literal('function'),
  function: z.object({
    name: z.string(),
    arguments: z.string(),
  }),
});

const ContentPartSchema = z
  .object({
    type: z.string(),
    text: z.string().optional(),
  })
  .passthrough();

const ChatMessageSchema = z
  .object({
    role: z.enum(['system', 'developer', 'user', 'assistant', 'function', 'tool']),
    content: z.union([z.string(), z.array(ContentPartSchema), z.null()]).optional().default(null),
    name: z.string().optional(),
    tool_call_id: z.string().optional(),
    refusal: z.string().nullable().optional(),
    function_call: z
      .object({
        name: z.string(),
        arguments: z.string(),
      })
      .optional(),
    tool_calls: z.array(ToolCallSchema).optional(),
  })
  .passthrough()
  .superRefine((msg, ctx) => {
    if (msg.role === 'tool' && !msg.tool_call_id) {
      ctx.addIssue({ code: z.ZodIssueCode.custom, message: 'tool messages require tool_call_id', path: ['tool_call_id'] });
    }
    if (msg.content === null && msg.role !== 'assistant') {
      ctx.addIssue({ code: z.ZodIssueCode.custom, message: 'content may only be null on assistant tool-call messages', path: ['content'] });
    }
    if (msg.role === 'assistant' && msg.content === null && !msg.tool_calls?.length && !msg.function_call) {
      ctx.addIssue({ code: z.ZodIssueCode.custom, message: 'assistant messages need content or tool_calls', path: ['content'] });
    }
  });

const ToolDefinitionSchema = z
  .object({
    type: z.literal('function'),
    function: z
      .object({
        name: z.string().min(1),
        description: z.string().optional(),
        parameters: z.record(z.unknown()).optional(),
        strict: z.boolean().optional(),
      })
      .passthrough(),
  })
  .passthrough();

const ToolChoiceSchema = z.union([
  z.enum(['none', 'auto', 'required']),
  z.object({ type: z.literal('function'), function: z.object({ name: z.string() }) }),
]);

const FunctionDefinitionSchema = z
  .object({
    name: z.string().min(1),
    description: z.string().optional(),
    parameters: z.record(z.unknown()).optional(),
  })
  .passthrough();

const FunctionCallSchema = z.union([z.enum(['none', 'auto']), z.object({ name: z.string() })]);

const ResponseFormatSchema = z
  .object({
    type: z.enum(['text', 'json_object', 'json_schema']),
    json_schema: z.record(z.unknown()).optional(),
  })
  .passthrough();

const ChatCompletionRequestSchema = z
  .object({
    model: z.string().min(1),
    messages: z.array(ChatMessageSchema).min(1),
    temperature: z.number().min(0).max(2).optional(),
    top_p: z.number().min(0).max(1).optional(),
    n: z.number().int().min(1).max(128).optional(),
    stream: z.boolean().optional(),
    stream_options: z.record(z.unknown()).optional(),
    stop: z.union([z.string(), z.array(z.string()).max(4)]).nullable().optional(),
    max_tokens: z.number().int().positive().nullable().optional(),
    max_completion_tokens: z.number().int().positive().nullable().optional(),
    presence_penalty: z.number().min(-2).max(2).nullable().optional(),
    frequency_penalty: z.number().min(-2).max(2).nullable().optional(),
    logit_bias: z.record(z.number()).nullable().optional(),
    logprobs: z.boolean().nullable().optional(),
    top_logprobs: z.number().int().min(0).max(20).nullable().optional(),
    seed: z.number().int().nullable().optional(),
    user: z.string().optional(),
    response_format: ResponseFormatSchema.optional(),
    parallel_tool_calls: z.boolean().optional(),
    service_tier: z.string().nullable().optional(),
    store: z.boolean().nullable().optional(),
    metadata: z.record(z.unknown()).nullable().optional(),
    tools: z.array(ToolDefinitionSchema).optional(),
    tool_choice: ToolChoiceSchema.optional(),
    functions: z.array(FunctionDefinitionSchema).optional(),
    function_call: FunctionCallSchema.optional(),
  })
  .passthrough();

// =============================================================================
// Route Handler
// =============================================================================

export function registerChatCompletionsRoute(server: FastifyInstance, config: GatewayConfig): void {
  server.post('/v1/chat/completions', async (request: FastifyRequest, reply: FastifyReply) => {
    const startTime = Date.now();
    const requestId = (request as FastifyRequest & { requestId?: string }).requestId || nanoid();

    // =======================================================================
    // 1. Parse and validate request
    // =======================================================================
    const parseResult = ChatCompletionRequestSchema.safeParse(request.body);
    if (!parseResult.success) {
      throw new ValidationError('Invalid request body', {
        errors: parseResult.error.errors.map((e) => ({
          path: e.path.join('.'),
          message: e.message,
        })),
      });
    }

    // Zod strips nothing here (passthrough), so the parsed value carries every
    // field the client sent.
    const body = parseResult.data as unknown as ChatCompletionRequest;

    if (body.stream) {
      throw new ValidationError('Streaming is not yet supported. Set stream: false');
    }

    // =======================================================================
    // 2. Extract LLM provider configuration from headers
    // =======================================================================
    const providerConfig = extractProviderConfig(request, body.model);

    if (config.input.logInput) {
      request.log.info(
        {
          requestId,
          provider: providerConfig.name,
          model: body.model,
          messageCount: body.messages.length,
          toolCount: body.tools?.length ?? 0,
        },
        'Incoming chat completion request'
      );
    }

    // =======================================================================
    // 3. Input sanitization pipeline (user messages only; tool results and
    //    system prompts are application data)
    // =======================================================================
    let messagesToSend = body.messages;
    let inputResult = null;

    if (config.input.detectInjection) {
      inputResult = await sanitizeInput(body.messages, {
        sensitivity: config.input.injectionSensitivity,
        action: config.input.injectionAction,
        internalLLM: config.internalLLM,
        customPatterns: config.input.injectionCustomPatterns,
      });

      if (inputResult.injectionDetected) {
        request.log.warn(
          {
            requestId,
            action: config.input.injectionAction,
            matches: inputResult.injectionMatches.length,
            techniques: [...new Set(inputResult.injectionMatches.map((m) => m.technique))],
          },
          'Prompt injection detected'
        );

        if (inputResult.blocked) {
          throw new InjectionBlockedError(inputResult.injectionMatches);
        }

        messagesToSend = inputResult.sanitized;
      }
    }

    // =======================================================================
    // 4. Route to LLM provider
    // =======================================================================
    let llmResponse: ChatCompletionResponse;
    try {
      llmResponse = await routeToLLM(providerConfig, {
        ...body,
        messages: messagesToSend,
      });
    } catch (error) {
      if (error instanceof GatewayError) {
        throw error; // ProviderError / ValidationError already carry status and details
      }
      if (error instanceof Error) {
        throw new ProviderError(error.message, providerConfig.name);
      }
      throw error;
    }

    // =======================================================================
    // 5. Output processing pipeline (every choice)
    // =======================================================================
    let finalResponse = llmResponse;
    const outputResults: OutputProcessingResult[] = [];
    let anyRedacted = false;

    if (config.output.detectPII && llmResponse.choices.length > 0) {
      const processedChoices: ChatCompletionChoice[] = [];

      for (const choice of llmResponse.choices) {
        let processedChoice = choice;

        const content = choice.message?.content;
        if (typeof content === 'string' && content.length > 0) {
          const result = await processOutput(content, outputConfig(config));
          outputResults.push(result);
          if (result.blocked) {
            logPII(request, requestId, choice.index, result);
            throw new PIIBlockedError(result.piiMatches);
          }
          if (result.piiDetected) {
            logPII(request, requestId, choice.index, result);
            if (result.processed !== content) {
              anyRedacted = true;
              processedChoice = {
                ...processedChoice,
                message: { ...processedChoice.message, content: result.processed },
              };
            }
          }
        }

        if (config.output.piiScanToolArguments && choice.message?.tool_calls?.length) {
          const toolCalls = [];
          for (const call of choice.message.tool_calls) {
            const result = await processOutput(call.function.arguments, outputConfig(config));
            outputResults.push(result);
            if (result.blocked) {
              logPII(request, requestId, choice.index, result);
              throw new PIIBlockedError(result.piiMatches);
            }
            if (result.piiDetected) logPII(request, requestId, choice.index, result);
            if (result.processed !== call.function.arguments) anyRedacted = true;
            toolCalls.push({ ...call, function: { ...call.function, arguments: result.processed } });
          }
          processedChoice = {
            ...processedChoice,
            message: { ...processedChoice.message, tool_calls: toolCalls },
          };
        }

        processedChoices.push(processedChoice);
      }

      if (anyRedacted) {
        finalResponse = { ...llmResponse, choices: processedChoices };
      }
    }

    const piiDetected = outputResults.some((r) => r.piiDetected);

    // =======================================================================
    // 6. Log and return response
    // =======================================================================
    const latencyMs = Date.now() - startTime;

    if (config.output.logOutput) {
      request.log.info(
        {
          requestId,
          latencyMs,
          injectionDetected: inputResult?.injectionDetected ?? false,
          piiDetected,
          tokens: finalResponse.usage?.total_tokens,
        },
        'Request completed'
      );
    }

    reply.header('X-Request-ID', requestId);
    reply.header('X-Gateway-Latency-Ms', latencyMs.toString());
    if (inputResult?.injectionDetected) {
      reply.header('X-Injection-Detected', 'true');
      reply.header('X-Injection-Action', config.input.injectionAction);
    }
    if (piiDetected) {
      reply.header('X-PII-Detected', 'true');
      reply.header('X-PII-Redacted', anyRedacted.toString());
    }

    return finalResponse;
  });
}

// =============================================================================
// Helper Functions
// =============================================================================

function outputConfig(config: GatewayConfig) {
  return {
    piiTypes: config.output.piiTypes,
    action: config.output.piiAction,
    minConfidence: config.output.piiMinConfidence,
    allowValues: config.output.piiAllowValues,
    allowPatterns: config.output.piiAllowPatterns,
  };
}

function logPII(request: FastifyRequest, requestId: string, choiceIndex: number, result: OutputProcessingResult): void {
  request.log.warn(
    {
      requestId,
      choice: choiceIndex,
      matches: result.piiMatches.length,
      types: [...new Set(result.piiMatches.map((m) => m.type))],
      blocked: result.blocked,
    },
    'PII detected in response'
  );
}

function headerValue(value: string | string[] | undefined): string | undefined {
  if (Array.isArray(value)) return value[0];
  return value;
}

function extractProviderConfig(request: FastifyRequest, model: string): LLMProviderConfig {
  const headers = request.headers;

  const provider = inferProvider(headerValue(headers['x-llm-provider']), model);

  const apiKey = headerValue(headers['x-llm-api-key']);
  if (!apiKey) {
    throw new ValidationError('Missing X-LLM-API-Key header');
  }

  const providerConfig: LLMProviderConfig = {
    name: provider,
    apiKey,
    model,
  };

  const baseUrl = headerValue(headers['x-llm-base-url']);
  if (baseUrl) providerConfig.baseUrl = baseUrl;

  if (provider === 'azure') {
    providerConfig.endpoint = headerValue(headers['x-azure-endpoint']);
    providerConfig.deployment = headerValue(headers['x-azure-deployment']);
    providerConfig.apiVersion = headerValue(headers['x-azure-api-version']);
  }

  return providerConfig;
}

function inferProvider(providerHeader: string | undefined, model: string): LLMProviderName {
  if (providerHeader) {
    const normalized = providerHeader.toLowerCase();
    if (normalized === 'openai' || normalized === 'anthropic' || normalized === 'azure') {
      return normalized;
    }
    throw new ValidationError(`Unknown X-LLM-Provider "${providerHeader}". Use openai, anthropic or azure`);
  }

  if (model.startsWith('claude')) {
    return 'anthropic';
  }
  return 'openai';
}
