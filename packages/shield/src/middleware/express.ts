import type { Request, Response, NextFunction, RequestHandler } from 'express';
import { Shield } from '../index.js';
import type { ShieldConfig, AnalysisResult } from '../types.js';

export interface ExpressShieldOptions extends Partial<ShieldConfig> {
  /**
   * Function to extract the input to analyze from the request.
   * Default: req.body.prompt || req.body.message || req.body.input
   */
  getInput?: (req: Request) => string | undefined;

  /**
   * Function to extract user ID for logging/rate limiting.
   * Default: req.headers['x-user-id'] || req.ip
   */
  getUserId?: (req: Request) => string | undefined;

  /**
   * Custom response when request is blocked.
   * Default: 403 with JSON error message
   */
  onBlockResponse?: (res: Response, result: AnalysisResult) => void;

  /**
   * Skip analysis for certain requests.
   * Return true to skip.
   */
  skip?: (req: Request) => boolean;
}

declare global {
  // Express augments its Request type through this namespace; there is no
  // module-syntax alternative for a global augmentation.
  // eslint-disable-next-line @typescript-eslint/no-namespace
  namespace Express {
    interface Request {
      shieldResult?: AnalysisResult;
    }
  }
}

/**
 * Express middleware for runtime prompt injection protection.
 *
 * @example
 * ```ts
 * import express from 'express';
 * import { shieldMiddleware } from '@evidentai/shield/express';
 *
 * const app = express();
 * app.use(express.json());
 *
 * // Protect all routes
 * app.use(shieldMiddleware({
 *   blockThreshold: 'high',
 *   analyzers: ['heuristic', 'llm-judge'],
 *   llm: { provider: 'openai' }
 * }));
 *
 * // Or protect specific routes
 * app.post('/api/chat', shieldMiddleware(), (req, res) => {
 *   // req.shieldResult contains the analysis
 *   res.json({ message: 'Hello!' });
 * });
 * ```
 */
export function shieldMiddleware(options: ExpressShieldOptions = {}): RequestHandler {
  const shield = new Shield({
    enabled: options.enabled ?? true,
    blockThreshold: options.blockThreshold ?? 'high',
    analyzers: options.analyzers ?? ['heuristic'],
    logAll: options.logAll ?? false,
    onThreat: options.onThreat,
    onBlock: options.onBlock,
    llm: options.llm,
    heuristic: options.heuristic,
  });

  const getInput =
    options.getInput ??
    ((req: Request) => {
      const body = req.body as Record<string, unknown> | undefined;
      if (!body) return undefined;
      return (body.prompt ?? body.message ?? body.input ?? body.content) as
        | string
        | undefined;
    });

  const getUserId =
    options.getUserId ??
    ((req: Request) => {
      return (req.headers['x-user-id'] as string) || req.ip;
    });

  const onBlockResponse =
    options.onBlockResponse ??
    ((res: Response, result: AnalysisResult) => {
      res.status(403).json({
        error: 'Request blocked',
        reason: 'Potential prompt injection detected',
        requestId: result.requestId,
        threat: {
          level: result.threat.level,
          confidence: result.threat.confidence,
        },
      });
    });

  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    // Skip if disabled or skip function returns true
    if (!shield.isEnabled() || options.skip?.(req)) {
      next();
      return;
    }

    const input = getInput(req);

    // No input to analyze
    if (!input || typeof input !== 'string') {
      next();
      return;
    }

    try {
      const result = await shield.analyze({
        input,
        userId: getUserId(req),
        metadata: {
          path: req.path,
          method: req.method,
          userAgent: req.headers['user-agent'],
        },
      });

      // Attach result to request for downstream use
      req.shieldResult = result;

      if (result.blocked) {
        onBlockResponse(res, result);
        return;
      }

      next();
    } catch (error) {
      // Log error but don't block on shield failure
      console.error('[Shield] Analysis error:', error);
      next();
    }
  };
}

export { Shield } from '../index.js';
export type { ShieldConfig, AnalysisResult, ThreatDetection, ThreatLevel } from '../types.js';
