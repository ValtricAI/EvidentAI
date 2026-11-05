# @evidentai/shield

**Runtime protection for LLM applications.** Detect and block prompt injection attacks in real-time.

```
┌─────────────────────────────────────────────────────────────┐
│  Your User                                                  │
└─────────────────────┬───────────────────────────────────────┘
                      │ HTTP request
                      ▼
┌─────────────────────────────────────────────────────────────┐
│  @evidentai/shield                                          │
│  ┌────────────────────────────────────────────────────────┐ │
│  │ Layer 1: Fast heuristics (<5ms)                        │ │
│  │ - Known attack patterns (regex)                        │ │
│  │ - Suspicious token sequences                           │ │
│  │ - Delimiter injection detection                        │ │
│  └────────────────────────────────────────────────────────┘ │
│                        │                                    │
│              Pass but suspicious?                           │
│                        ▼                                    │
│  ┌────────────────────────────────────────────────────────┐ │
│  │ Layer 2: LLM-as-judge (~200-400ms)                     │ │
│  │ - Fast model (Claude Haiku, GPT-4o-mini)               │ │
│  │ - Semantic analysis of intent                          │ │
│  └────────────────────────────────────────────────────────┘ │
│                        │                                    │
│                        ▼                                    │
│  Decision: ALLOW / BLOCK / LOG                              │
└─────────────────────┬───────────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────────┐
│  Your LLM (OpenAI, Anthropic, etc.)                         │
└─────────────────────────────────────────────────────────────┘
```

## Installation

```bash
npm install @evidentai/shield
```

## Quick Start

### Express Middleware

```typescript
import express from 'express';
import { shieldMiddleware } from '@evidentai/shield/express';

const app = express();
app.use(express.json());

// Add shield protection
app.use(shieldMiddleware({
  blockThreshold: 'high',
  analyzers: ['heuristic'],
}));

app.post('/api/chat', (req, res) => {
  // req.shieldResult contains the analysis
  if (req.shieldResult?.threat.detected) {
    console.log('Threat detected but not blocked:', req.shieldResult.threat);
  }

  // Your LLM logic here
  res.json({ message: 'Hello!' });
});

app.listen(3000);
```

### Fastify Plugin

```typescript
import Fastify from 'fastify';
import { shieldPlugin } from '@evidentai/shield/fastify';

const app = Fastify();

app.register(shieldPlugin, {
  blockThreshold: 'high',
  analyzers: ['heuristic', 'llm-judge'],
  llm: { provider: 'openai' }
});

app.post('/api/chat', async (req) => {
  return { message: 'Hello!' };
});

app.listen({ port: 3000 });
```

### Standalone Proxy

Use when you can't modify your application code:

```typescript
import { createShieldProxy } from '@evidentai/shield/standalone';

const proxy = createShieldProxy({
  port: 3000,
  target: 'http://localhost:8080', // Your LLM API
  blockThreshold: 'high',
  analyzers: ['heuristic'],
});

proxy.start();
// Requests to localhost:3000 are analyzed and forwarded to localhost:8080
```

### Direct API

```typescript
import { Shield } from '@evidentai/shield';

const shield = new Shield({
  blockThreshold: 'high',
  analyzers: ['heuristic', 'llm-judge'],
  llm: { provider: 'openai' }
});

const result = await shield.analyze({
  input: userMessage,
  userId: 'user123',
});

if (result.blocked) {
  console.log('Blocked:', result.threat.reason);
  return { error: 'Request blocked for safety reasons' };
}

// Proceed with LLM call
```

## Configuration

```typescript
interface ShieldConfig {
  // Enable/disable protection (default: true)
  enabled: boolean;

  // Minimum threat level to block: 'low' | 'medium' | 'high' | 'critical'
  // Default: 'high'
  blockThreshold: ThreatLevel;

  // Which analyzers to use, in order: 'heuristic' | 'ml' | 'llm-judge'
  // Default: ['heuristic']
  analyzers: AnalyzerType[];

  // Log all requests, not just threats (default: false)
  logAll: boolean;

  // Callback when threat detected (even if not blocked)
  onThreat?: (result: AnalysisResult) => void;

  // Callback when request blocked
  onBlock?: (result: AnalysisResult) => void;

  // LLM configuration for llm-judge analyzer
  llm?: {
    provider: 'openai' | 'anthropic' | 'custom';
    model?: string;      // Default: gpt-4o-mini / claude-3-haiku
    apiKey?: string;     // Or use env: OPENAI_API_KEY / ANTHROPIC_API_KEY
    endpoint?: string;   // For custom providers
  };

  // Heuristic analyzer options
  heuristic?: {
    customPatterns?: string[];  // Additional regex patterns
    sensitivity?: 'low' | 'medium' | 'high';  // Default: 'medium'
  };

  // ml analyzer: a classifier backend plus score cut points (see below)
  ml?: {
    backend: 'transformers' | 'http' | 'jev' | 'custom';
    // backend-specific fields, e.g. model / url / apiKey
    criticalAbove?: number;  // Default 0.9  -> 'critical'
    threshold?: number;      // Default 0.5  -> 'high'
    mediumAbove?: number;    // Default 0.3  -> 'medium'
    failClosed?: boolean;    // Default false: a classifier error yields 'none'
  };

  // Escalate uncertain ml scores to the llm-judge (needs `llm`)
  deferral?: {
    enabled: boolean;  // Default false
    lower: number;     // Default 0.3 (inclusive)
    upper: number;     // Default 0.7 (exclusive)
  };
}
```

## Threat Levels

| Level | Description | Examples |
|-------|-------------|----------|
| `critical` | Definite attack | "Ignore all instructions", "Jailbreak", "DAN mode" |
| `high` | Likely attack | Role manipulation, prompt extraction attempts |
| `medium` | Suspicious | Delimiter injection, encoding attempts |
| `low` | Possibly suspicious | Bypass language, unusual patterns |
| `none` | Clean | Normal user input |

## Analyzers

### Heuristic (Layer 1)
- **Speed**: <5ms
- **Method**: Pattern matching with curated attack signatures
- **Best for**: Catching known attacks quickly
- **Detects**:
  - Instruction override attempts
  - Role manipulation
  - System prompt extraction
  - Delimiter/token injection
  - Context manipulation

### ML classifier (Layer 2)
- **Speed**: 10-50ms locally on CPU, network latency for hosted backends
- **Method**: a learned classifier returns P(injection) in [0, 1]; the score is
  mapped to a threat level with the cut points in `ml`
- **Best for**: paraphrased or novel attacks that have no fixed vocabulary
- **Backends** (same config shape in `@evidentai/gateway`):

| Backend | Config | Notes |
|---------|--------|-------|
| `transformers` | `{ backend: 'transformers', model?: string }` | Local ONNX model through `@huggingface/transformers` (install it separately; it is an optional peer dependency). Default model `protectai/deberta-v3-base-prompt-injection-v2` (Apache-2.0). Meta's `meta-llama/Llama-Prompt-Guard-2-86M` and `-22M` work too but are gated: set `HF_TOKEN`. A local directory also works, with an optional `calibration.json` `{"temperature": t}` applied to the logits. Options: `localFilesOnly`, `cacheDir`, `dtype`, `injectionLabel`, `temperature`, `maxChars`. |
| `http` | `{ backend: 'http', url, headers?, scorePath?, textField?, timeoutMs? }` | Your own endpoint: the shield POSTs `{text}` and reads the score at `scorePath` (default `score`). |
| `jev` | `{ backend: 'jev', apiKey?, url?, model?, scoreQuestion?, choiceQuestion?, scorePaths? }` | TypeSafe AI's Jev decision model. Key from `TYPESAFE_API_KEY`. Written against the published API shape (`POST /v1/systemone`, `{model, state, questions}`) but not yet verified against the live service; `scorePaths` lists where the numeric answer is looked for, override it once you have a real response. |
| `custom` | `{ backend: 'custom', name, options? }` | A backend you registered with `registerClassifierBackend(name, factory)`. |

```typescript
import { Shield } from '@evidentai/shield';

const shield = new Shield({
  analyzers: ['heuristic', 'ml'],
  ml: { backend: 'transformers', threshold: 0.6 },
});
```

The classifier is loaded once and cached. By default the analyzer **fails
open**: if the model cannot be loaded or the endpoint is down, the ml result
is level `none` with `error` set and the request proceeds on the other
analyzers. Set `ml.failClosed: true` to treat classifier errors as `critical`.

### LLM-Judge (Layer 3)
- **Speed**: 200-400ms
- **Method**: Uses a small, fast LLM to classify intent
- **Best for**: Catching novel/obfuscated attacks
- **Models**: GPT-4o-mini (OpenAI) or Claude Haiku (Anthropic)

### Deferral: calibrate, then escalate

Classifier scores near the decision boundary are the ones most often wrong.
With `deferral.enabled`, an ml score inside `[lower, upper)` is escalated to
the llm-judge and the judge's verdict replaces the classifier's. Scores
outside the band are decided by the classifier alone, so the judge runs only
on the uncertain minority of requests.

```typescript
const shield = new Shield({
  analyzers: ['heuristic', 'ml'],
  ml: { backend: 'transformers' },
  llm: { provider: 'openai' },
  deferral: { enabled: true, lower: 0.3, upper: 0.7 },
});

const result = await shield.analyze({ input });
if (result.deferred) {
  console.log(result.deferred); // { reason, mlScore, judgeLevel }
}
```

Deferral requires `llm` to be configured; without it the classifier's own
level stands. If `llm-judge` is already in `analyzers` it is not run twice.

## Analysis Result

```typescript
interface AnalysisResult {
  requestId: string;           // Unique ID for tracing
  input: string;               // The analyzed input
  threat: {
    detected: boolean;         // Was any threat found?
    level: ThreatLevel;        // Severity
    confidence: number;        // 0-1 confidence score
    analyzer: AnalyzerType;    // Which analyzer found it
    reason: string;            // Human-readable explanation
    indicators: string[];      // Specific patterns found
    latencyMs: number;         // Time taken
  };
  analyzerResults: ThreatDetection[];  // Individual analyzer results
  blocked: boolean;            // Was the request blocked?
  totalLatencyMs: number;      // Total analysis time
  timestamp: string;           // ISO timestamp
}
```

## Performance

| Analyzer | Latency | API Calls | Cost |
|----------|---------|-----------|------|
| Heuristic only | <5ms | 0 | Free |
| Heuristic + LLM | 200-500ms | 1 | ~$0.0001/request |

## Examples

### Custom Block Response

```typescript
app.use(shieldMiddleware({
  onBlockResponse: (res, result) => {
    res.status(403).json({
      error: 'Your message was flagged by our safety system',
      code: 'PROMPT_INJECTION_DETECTED',
      id: result.requestId,
    });
  }
}));
```

### Skip Certain Routes

```typescript
app.use(shieldMiddleware({
  skip: (req) => {
    // Don't analyze health checks
    return req.path === '/health';
  }
}));
```

### Custom Input Extraction

```typescript
app.use(shieldMiddleware({
  getInput: (req) => {
    // Extract from nested structure
    return req.body.messages?.[0]?.content;
  }
}));
```

### Add Custom Patterns

```typescript
const shield = new Shield({
  heuristic: {
    customPatterns: [
      'secret.*backdoor',
      'admin.*override',
    ],
    sensitivity: 'high',
  }
});
```

## Related

- **[@evidentai/cli](https://npmjs.com/package/@evidentai/cli)** - CI/CD testing for LLM applications (regression testing, PII detection)

## License

MIT
