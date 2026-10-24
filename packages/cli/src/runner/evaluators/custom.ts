/**
 * Custom Evaluator
 *
 * Allows users to define their own evaluation logic. Exactly one mode must be
 * configured:
 * 1. `function`: inline JavaScript function source, run in a node `vm` context
 * 2. `script`: path to a .js/.mjs/.cjs file exporting an `evaluate` function
 * 3. `webhook`: HTTP endpoint that receives the evaluation context as JSON
 *
 * Every mode is bounded by `timeout_ms` (default 30s).
 *
 * SECURITY NOTE: node's `vm` module is NOT a security sandbox. Inline functions
 * and script files run with the same privileges as the CLI process. Only use
 * evaluator code from your own repository, never from untrusted input.
 */

import type { EvaluatorResult } from '../../config/types';
import type { Evaluator, EvaluatorContext } from './index';
import * as vm from 'vm';
import * as path from 'path';
import * as fs from 'fs';
import { pathToFileURL } from 'url';

export interface CustomConfig {
  /** Inline function as string */
  function?: string;
  /** Path to external script */
  script?: string;
  /** Webhook URL */
  webhook?: string;
  /** Timeout in ms (matches the rest of the config schema) */
  timeout_ms?: number;
  /** Additional context to pass to the evaluator as `config` */
  context?: Record<string, unknown>;
}

interface CustomEvalContext {
  input: string;
  output: string;
  expected?: string | string[];
  config: Record<string, unknown>;
}

interface CustomEvalResult {
  passed: boolean;
  score?: number;
  reason?: string;
  details?: Record<string, unknown>;
}

const DEFAULT_TIMEOUT_MS = 30000;

// =============================================================================
// Helpers
// =============================================================================

/**
 * Race a promise against a timeout. The timer is always cleared so it never
 * keeps the event loop alive.
 */
async function withTimeout<T>(promise: Promise<T>, timeoutMs: number, message: string): Promise<T> {
  let timer: NodeJS.Timeout | undefined;
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(new Error(message)), timeoutMs);
  });
  try {
    return await Promise.race([promise, timeout]);
  } finally {
    if (timer) clearTimeout(timer);
  }
}

function normaliseResult(result: unknown, source: string): CustomEvalResult {
  if (!result || typeof result !== 'object' || typeof (result as CustomEvalResult).passed !== 'boolean') {
    throw new Error(`${source} must return { passed: boolean, ... }`);
  }
  const r = result as CustomEvalResult;
  return {
    passed: r.passed,
    score: typeof r.score === 'number' ? r.score : r.passed ? 1.0 : 0.0,
    reason: typeof r.reason === 'string' ? r.reason : r.passed ? 'Custom evaluation passed' : 'Custom evaluation failed',
    details: r.details,
  };
}

// =============================================================================
// Execution Modes
// =============================================================================

/**
 * Execute an inline JavaScript function in a vm context.
 *
 * The vm `timeout` option only bounds synchronous execution, so the returned
 * promise is additionally raced against the same timeout.
 */
async function executeInlineFunction(
  functionCode: string,
  evalContext: CustomEvalContext,
  timeoutMs: number
): Promise<CustomEvalResult> {
  const sandbox: vm.Context = {
    input: evalContext.input,
    output: evalContext.output,
    expected: evalContext.expected,
    config: evalContext.config,
    console: {
      log: () => {},
      warn: () => {},
      error: () => {},
    },
    JSON,
    Math,
    String,
    Number,
    Boolean,
    Array,
    Object,
    Date,
    RegExp,
    Promise,
    setTimeout,
    clearTimeout,
  };

  vm.createContext(sandbox);

  // Evaluate the user code to a function value, then call it. The script
  // expression evaluates to a promise we can await outside the vm.
  const wrappedCode = `
    (async () => {
      const evaluateFunction = (${functionCode});
      if (typeof evaluateFunction !== 'function') {
        throw new Error('Custom function source must evaluate to a function');
      }
      return await evaluateFunction({ input, output, expected, config });
    })()
  `;

  let resultPromise: Promise<unknown>;
  try {
    const script = new vm.Script(wrappedCode, { filename: 'custom-evaluator.vm' });
    resultPromise = script.runInContext(sandbox, { timeout: timeoutMs, displayErrors: true }) as Promise<unknown>;
  } catch (error) {
    if (error instanceof Error && error.message.includes('Script execution timed out')) {
      throw new Error(`Custom function timed out after ${timeoutMs}ms`);
    }
    throw error;
  }

  const result = await withTimeout(
    Promise.resolve(resultPromise),
    timeoutMs,
    `Custom function timed out after ${timeoutMs}ms`
  );

  return normaliseResult(result, 'Custom function');
}

/**
 * Execute an external script file
 */
async function executeScriptFile(
  scriptPath: string,
  evalContext: CustomEvalContext,
  timeoutMs: number
): Promise<CustomEvalResult> {
  const absolutePath = path.isAbsolute(scriptPath)
    ? scriptPath
    : path.resolve(process.cwd(), scriptPath);

  if (!fs.existsSync(absolutePath)) {
    throw new Error(`Custom evaluator script not found: ${absolutePath}`);
  }

  const ext = path.extname(absolutePath);
  if (!['.js', '.mjs', '.cjs'].includes(ext)) {
    throw new Error(`Unsupported script extension: ${ext}. Use .js, .mjs, or .cjs`);
  }

  const module = (await withTimeout(
    import(pathToFileURL(absolutePath).href),
    timeoutMs,
    `Script import timed out after ${timeoutMs}ms`
  )) as Record<string, unknown> & { default?: Record<string, unknown> | ((...args: unknown[]) => unknown) };

  const candidate =
    module.evaluate ??
    (typeof module.default === 'object' && module.default !== null
      ? (module.default as Record<string, unknown>).evaluate
      : undefined) ??
    module.default;

  if (typeof candidate !== 'function') {
    throw new Error('Script must export an evaluate function');
  }

  const result = await withTimeout(
    Promise.resolve((candidate as (ctx: CustomEvalContext) => unknown)(evalContext)),
    timeoutMs,
    `Evaluation timed out after ${timeoutMs}ms`
  );

  return normaliseResult(result, 'Script evaluate function');
}

/**
 * Call a webhook endpoint for evaluation
 */
async function callWebhook(
  webhookUrl: string,
  evalContext: CustomEvalContext,
  timeoutMs: number
): Promise<CustomEvalResult> {
  let url: URL;
  try {
    url = new URL(webhookUrl);
  } catch {
    throw new Error(`Invalid webhook URL: ${webhookUrl}`);
  }

  if (process.env.NODE_ENV === 'production' && url.protocol !== 'https:') {
    throw new Error('Webhook must use HTTPS in production');
  }

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const response = await fetch(webhookUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'User-Agent': 'ReleaseGate/1.0',
      },
      body: JSON.stringify(evalContext),
      signal: controller.signal,
    });

    if (!response.ok) {
      throw new Error(`Webhook returned ${response.status}: ${await response.text()}`);
    }

    const result = (await response.json()) as unknown;
    return normaliseResult(result, 'Webhook');
  } catch (error) {
    if (error instanceof Error && error.name === 'AbortError') {
      throw new Error(`Webhook timed out after ${timeoutMs}ms`);
    }
    throw error;
  } finally {
    clearTimeout(timeoutId);
  }
}

// =============================================================================
// Main Evaluator
// =============================================================================

export class CustomEvaluator implements Evaluator {
  name = 'custom' as const;

  async evaluate(ctx: EvaluatorContext): Promise<EvaluatorResult> {
    const config = (ctx.config || {}) as CustomConfig;
    const timeoutMs = config.timeout_ms || DEFAULT_TIMEOUT_MS;

    const evalContext: CustomEvalContext = {
      input: ctx.input,
      output: ctx.output,
      expected: ctx.expected,
      config: config.context || {},
    };

    const modes = [
      config.function ? 'function' : null,
      config.script ? 'script' : null,
      config.webhook ? 'webhook' : null,
    ].filter((m): m is string => m !== null);

    if (modes.length === 0) {
      return {
        passed: false,
        score: 0,
        reason: 'No custom evaluation mode specified. Provide function, script, or webhook.',
      };
    }

    if (modes.length > 1) {
      return {
        passed: false,
        score: 0,
        reason: `Multiple evaluation modes specified (${modes.join(', ')}). Use only one.`,
      };
    }

    const mode = config.function ? 'inline_function' : config.script ? 'script_file' : 'webhook';

    try {
      let result: CustomEvalResult;

      if (config.function) {
        result = await executeInlineFunction(config.function, evalContext, timeoutMs);
      } else if (config.script) {
        result = await executeScriptFile(config.script, evalContext, timeoutMs);
      } else {
        result = await callWebhook(config.webhook as string, evalContext, timeoutMs);
      }

      return {
        passed: result.passed,
        score: result.score ?? (result.passed ? 1.0 : 0.0),
        reason: result.reason || (result.passed ? 'Custom evaluation passed' : 'Custom evaluation failed'),
        details: {
          mode,
          timeout_ms: timeoutMs,
          ...result.details,
        },
      };
    } catch (error) {
      return {
        passed: false,
        score: 0,
        reason: `Custom evaluator error: ${error instanceof Error ? error.message : String(error)}`,
        details: {
          error: String(error),
          mode,
        },
      };
    }
  }
}
