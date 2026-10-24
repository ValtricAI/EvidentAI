/**
 * EvidentAI Gateway
 *
 * OpenAI-compatible LLM proxy that adds:
 * - Prompt injection detection on user messages (log, block or rephrase)
 * - PII detection and redaction on responses
 * - Routing to OpenAI, Anthropic or Azure OpenAI with tool calling preserved
 * - Request/response logging
 *
 * @example
 * ```ts
 * import { createGateway } from '@evidentai/gateway';
 *
 * const gateway = await createGateway({
 *   port: 3000,
 *   input: { detectInjection: true, injectionAction: 'block' },
 *   output: { detectPII: true, piiAction: 'redact' },
 * });
 *
 * await gateway.start();
 * ```
 */

import Fastify, { type FastifyInstance, type FastifyRequest, type FastifyReply } from 'fastify';
import cors from '@fastify/cors';
import { nanoid } from 'nanoid';
import type { GatewayConfig } from './types.js';
import { AuthenticationError, GatewayError } from './types.js';
import { registerChatCompletionsRoute } from './routes/chat-completions.js';
import { ConfigError, configFromEnv, configWarnings, resolveConfig } from './config.js';

// =============================================================================
// Informational model list for /v1/models
// =============================================================================

/**
 * The gateway does not know which models a provider key can reach; this list
 * exists so OpenAI SDK clients that call /v1/models at startup get a sensible
 * answer. Any model name is accepted by /v1/chat/completions.
 */
const KNOWN_MODELS: Array<{ id: string; owned_by: 'openai' | 'anthropic' }> = [
  { id: 'gpt-4o', owned_by: 'openai' },
  { id: 'gpt-4o-mini', owned_by: 'openai' },
  { id: 'gpt-4.1', owned_by: 'openai' },
  { id: 'gpt-4.1-mini', owned_by: 'openai' },
  { id: 'o3', owned_by: 'openai' },
  { id: 'o4-mini', owned_by: 'openai' },
  { id: 'claude-opus-4-20250514', owned_by: 'anthropic' },
  { id: 'claude-sonnet-4-20250514', owned_by: 'anthropic' },
  { id: 'claude-3-5-haiku-20241022', owned_by: 'anthropic' },
];

// =============================================================================
// Gateway Class
// =============================================================================

export class Gateway {
  private server: FastifyInstance;
  private config: GatewayConfig;

  constructor(config: Partial<GatewayConfig> = {}) {
    this.config = resolveConfig(config);

    this.server = Fastify({
      logger: this.config.logging
        ? {
            level: 'info',
            transport: {
              target: 'pino-pretty',
              options: {
                colorize: true,
                translateTime: 'HH:MM:ss',
                ignore: 'pid,hostname',
              },
            },
          }
        : false,
      genReqId: () => nanoid(),
    });

    this.setupMiddleware();
    this.setupRoutes();
    this.setupErrorHandler();
  }

  private setupMiddleware(): void {
    if (this.config.cors) {
      this.server.register(cors, {
        origin: true,
        methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
        allowedHeaders: [
          'Content-Type',
          'Authorization',
          'X-LLM-Provider',
          'X-LLM-API-Key',
          'X-LLM-Base-URL',
          'X-LLM-Model',
          'X-Azure-Endpoint',
          'X-Azure-Deployment',
          'X-Azure-API-Version',
          'X-Request-ID',
        ],
      });
    }

    // Gateway API key authentication (if configured)
    if (this.config.apiKey) {
      const expected = this.config.apiKey;
      this.server.addHook('preHandler', async (request: FastifyRequest, _reply: FastifyReply) => {
        if (request.url === '/health' || request.url === '/v1/models') {
          return;
        }

        const authHeader = request.headers.authorization;
        if (!authHeader?.startsWith('Bearer ')) {
          throw new AuthenticationError('Missing Authorization header');
        }

        const token = authHeader.slice(7);
        if (!constantTimeEqual(token, expected)) {
          throw new AuthenticationError('Invalid API key');
        }
      });
    }

    this.server.decorateRequest('requestId', '');
    this.server.addHook('preHandler', async (request: FastifyRequest) => {
      const incoming = request.headers['x-request-id'];
      (request as FastifyRequest & { requestId: string }).requestId =
        (Array.isArray(incoming) ? incoming[0] : incoming) || request.id;
    });
  }

  private setupRoutes(): void {
    this.server.get('/health', async () => ({
      status: 'ok',
      timestamp: new Date().toISOString(),
      config: {
        injection: {
          enabled: this.config.input.detectInjection,
          sensitivity: this.config.input.injectionSensitivity,
          action: this.config.input.injectionAction,
        },
        pii: {
          enabled: this.config.output.detectPII,
          types: this.config.output.piiTypes,
          action: this.config.output.piiAction,
          minConfidence: this.config.output.piiMinConfidence ?? 'medium',
        },
      },
    }));

    this.server.get('/v1/models', async () => ({
      object: 'list',
      data: KNOWN_MODELS.map((m) => ({ id: m.id, object: 'model', created: 0, owned_by: m.owned_by })),
    }));

    registerChatCompletionsRoute(this.server, this.config);
  }

  private setupErrorHandler(): void {
    this.server.setErrorHandler(
      async (error: Error, request: FastifyRequest, reply: FastifyReply) => {
        if (error instanceof GatewayError) {
          return reply.status(error.statusCode).send({
            error: {
              message: error.message,
              type: error.code,
              code: error.code,
              details: error.details,
            },
          });
        }

        if ('validation' in error) {
          return reply.status(400).send({
            error: {
              message: error.message,
              type: 'validation_error',
              code: 'invalid_request',
            },
          });
        }

        request.log.error(error, 'Unexpected error');

        return reply.status(500).send({
          error: {
            message: process.env.NODE_ENV === 'development' ? error.message : 'Internal server error',
            type: 'internal_error',
            code: 'internal_error',
          },
        });
      }
    );
  }

  async start(): Promise<void> {
    for (const warning of configWarnings(this.config)) {
      console.warn(`[Gateway] Warning: ${warning}`);
    }
    try {
      await this.server.listen({
        port: this.config.port,
        host: this.config.host,
      });
      const address = this.server.addresses()[0];
      const shown = address ? `http://${address.address}:${address.port}` : `http://${this.config.host}:${this.config.port}`;
      console.log(`[Gateway] Running on ${shown}`);
      console.log(`[Gateway] POST /v1/chat/completions - OpenAI-compatible chat API`);
      console.log(`[Gateway] GET /health - Health check endpoint`);
      console.log(
        `[Gateway] Injection: ${this.config.input.detectInjection ? `${this.config.input.injectionSensitivity} sensitivity, action=${this.config.input.injectionAction}` : 'disabled'}` +
          ` | PII: ${this.config.output.detectPII ? `${this.config.output.piiTypes.join(',')}, action=${this.config.output.piiAction}` : 'disabled'}`
      );
    } catch (err) {
      this.server.log.error(err);
      throw err;
    }
  }

  async stop(): Promise<void> {
    await this.server.close();
  }

  getServer(): FastifyInstance {
    return this.server;
  }

  getConfig(): Readonly<GatewayConfig> {
    return this.config;
  }
}

function constantTimeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
}

// =============================================================================
// Factory Function
// =============================================================================

export async function createGateway(config: Partial<GatewayConfig> = {}): Promise<Gateway> {
  return new Gateway(config);
}

// =============================================================================
// CLI Entry Point
// =============================================================================

async function main(): Promise<void> {
  let config: Partial<GatewayConfig>;
  try {
    config = configFromEnv();
  } catch (err) {
    if (err instanceof ConfigError) {
      console.error(`[Gateway] ${err.message}`);
      process.exit(2);
    }
    throw err;
  }

  const gateway = await createGateway(config);
  await gateway.start();

  const shutdown = async () => {
    console.log('\n[Gateway] Shutting down...');
    await gateway.stop();
    process.exit(0);
  };

  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);
}

// Run if executed directly (node dist/index.mjs, or via bin/gateway.js which
// sets EVIDENTAI_GATEWAY_MAIN).
if (process.env.EVIDENTAI_GATEWAY_MAIN === '1' || import.meta.url === `file://${process.argv[1]}`) {
  main().catch((err) => {
    console.error('Failed to start gateway:', err);
    process.exit(1);
  });
}

// =============================================================================
// Exports
// =============================================================================

export { Gateway as default };
export { DEFAULT_CONFIG, configFromEnv, resolveConfig, configWarnings, ConfigError } from './config.js';
export type {
  GatewayConfig,
  InputPipelineConfig,
  OutputPipelineConfig,
  ChatCompletionRequest,
  ChatCompletionResponse,
  ChatCompletionChoice,
  ChatMessage,
  ToolCall,
  ToolDefinition,
  ToolChoice,
  FinishReason,
  LLMProviderConfig,
  PIIEntityType,
  PIIMatch,
  InjectionMatch,
  InputSanitizationResult,
  OutputProcessingResult,
  GatewayRequest,
  GatewayResponse,
  Incident,
} from './types.js';

export {
  GatewayError,
  AuthenticationError,
  ValidationError,
  InjectionBlockedError,
  PIIBlockedError,
  ProviderError,
} from './types.js';
