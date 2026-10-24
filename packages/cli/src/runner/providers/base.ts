/**
 * Shared provider utilities for LLM API calls.
 */

export const PROVIDER_DEFAULTS = {
  timeoutMs: 60000,
  openaiModel: 'gpt-4o-mini',
  anthropicModel: 'claude-3-haiku-20240307',
  temperature: 0.7,
  anthropicVersion: '2023-06-01',
  azureApiVersion: '2024-02-01',
} as const;

export interface LLMProvider {
  call(input: string): Promise<string>;
}

export interface FetchOptions {
  url: string;
  headers: Record<string, string>;
  body: unknown;
  timeoutMs: number;
  provider: string;
}

/**
 * Custom error class for API errors with status codes.
 */
export class APIError extends Error {
  constructor(
    message: string,
    public statusCode: number,
    public provider: string,
    public retryAfterMs?: number
  ) {
    super(message);
    this.name = 'APIError';
  }

  /**
   * Check if this error is retryable.
   */
  isRetryable(): boolean {
    // 408 = timeout, 429 = rate limit, 5xx = server errors
    return this.statusCode === 408 || this.statusCode === 429 || this.statusCode >= 500;
  }

  /**
   * Get suggested delay multiplier for this error type.
   */
  getDelayMultiplier(): number {
    if (this.statusCode === 429) {
      return 3;
    }
    return 1;
  }
}

/**
 * Parse retry delay from API response headers.
 */
function parseRetryAfterMs(headers: Headers): number | undefined {
  const retryAfter = headers.get('retry-after');
  const rateLimitReset =
    headers.get('x-ratelimit-reset-requests') ||
    headers.get('x-ratelimit-reset-tokens') ||
    headers.get('x-ratelimit-reset') ||
    headers.get('anthropic-ratelimit-reset');

  return (
    parseRetryAfterValue(retryAfter) ??
    parseRetryAfterValue(rateLimitReset)
  );
}

function parseRetryAfterValue(value: string | null): number | undefined {
  if (!value) return undefined;
  const trimmed = value.trim();
  if (!trimmed) return undefined;

  // Numeric seconds (or epoch seconds if very large)
  if (/^\d+(\.\d+)?$/.test(trimmed)) {
    const numeric = Number(trimmed);
    if (!Number.isFinite(numeric)) return undefined;
    if (numeric > 1e9) {
      const deltaMs = numeric * 1000 - Date.now();
      return deltaMs > 0 ? deltaMs : 0;
    }
    return numeric * 1000;
  }

  // Duration formats: 250ms, 2s, 1m, 0.5h
  const durationMatch = trimmed.match(/^(\d+(?:\.\d+)?)(ms|s|m|h)$/i);
  if (durationMatch && durationMatch[1] !== undefined && durationMatch[2] !== undefined) {
    const amount = Number(durationMatch[1]);
    if (!Number.isFinite(amount)) return undefined;
    const unit = durationMatch[2].toLowerCase();
    const multiplier = unit === 'ms' ? 1 : unit === 's' ? 1000 : unit === 'm' ? 60000 : 3600000;
    return amount * multiplier;
  }

  // HTTP date
  const dateMs = Date.parse(trimmed);
  if (!Number.isNaN(dateMs)) {
    const deltaMs = dateMs - Date.now();
    return deltaMs > 0 ? deltaMs : 0;
  }

  return undefined;
}

/**
 * Shared helper for making LLM API calls with timeout and error handling.
 */
export async function makeLLMCall<T>(
  options: FetchOptions,
  parseResponse: (data: T) => string
): Promise<string> {
  const { url, headers, body, timeoutMs, provider } = options;
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const response = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...headers },
      body: JSON.stringify(body),
      signal: controller.signal,
    });

    if (!response.ok) {
      const error = await response.text();
      const retryAfterMs = parseRetryAfterMs(response.headers);
      throw new APIError(
        `${provider} API error: ${response.status} - ${error}`,
        response.status,
        provider,
        retryAfterMs
      );
    }

    const data = (await response.json()) as T;
    return parseResponse(data);
  } catch (error) {
    if (error instanceof Error && error.name === 'AbortError') {
      const timeoutSec = Math.round(timeoutMs / 1000);
      throw new APIError(
        `${provider} API request timed out after ${timeoutSec}s. Try increasing the timeout: releasegate run --timeout ${timeoutMs * 2}`,
        408,
        provider
      );
    }
    throw error;
  } finally {
    clearTimeout(timeoutId);
  }
}
