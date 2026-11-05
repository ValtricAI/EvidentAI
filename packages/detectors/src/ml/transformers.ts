/**
 * Local ONNX classifier via @huggingface/transformers (transformers.js).
 *
 * The dependency is optional and loaded dynamically, so packages that never
 * configure the `transformers` backend do not pull onnxruntime in.
 *
 * Known models:
 * - protectai/deberta-v3-base-prompt-injection-v2  (labels SAFE / INJECTION)
 * - meta-llama/Llama-Prompt-Guard-2-86M, -22M       (LABEL_0 benign / LABEL_1 malicious; gated)
 * - a local directory exported by `packages/evals` training, optionally with a
 *   calibration.json {"temperature": t} applied to the logits
 */

import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import {
  MLClassifierError,
  clamp01,
  type MLClassifier,
  type MLClassifyResult,
  type TransformersClassifierConfig,
} from './types';

// Kept as a plain string so TypeScript and bundlers do not try to resolve it.
const TRANSFORMERS_MODULE = '@huggingface/transformers';

interface LogitsTensor {
  data: ArrayLike<number>;
  dims: number[];
}

interface LoadedModel {
  tokenizer: (text: string, options: Record<string, unknown>) => Record<string, unknown>;
  model: (inputs: Record<string, unknown>) => Promise<{ logits: LogitsTensor }>;
  id2label: Record<string, string>;
  injectionIndex: number;
  temperature: number;
}

const INJECTION_LABEL_PATTERN = /injection|malicious|jailbreak|unsafe|attack|label_1/i;

async function loadTransformers(): Promise<Record<string, unknown>> {
  try {
    return (await import(TRANSFORMERS_MODULE)) as Record<string, unknown>;
  } catch (error) {
    throw new MLClassifierError(
      `The "transformers" backend needs @huggingface/transformers. Install it: pnpm add @huggingface/transformers`,
      'transformers',
      error
    );
  }
}

function readCalibration(modelPath: string): number | undefined {
  const file = join(modelPath, 'calibration.json');
  if (!existsSync(file)) return undefined;
  try {
    const parsed = JSON.parse(readFileSync(file, 'utf8')) as { temperature?: unknown };
    return typeof parsed.temperature === 'number' && parsed.temperature > 0 ? parsed.temperature : undefined;
  } catch {
    return undefined;
  }
}

function pickInjectionIndex(id2label: Record<string, string>, override?: string): number {
  const entries = Object.entries(id2label);
  if (override) {
    const hit = entries.find(([, label]) => label.toLowerCase() === override.toLowerCase());
    if (hit) return Number(hit[0]);
    throw new MLClassifierError(
      `injectionLabel "${override}" not found in model labels: ${entries.map(([, l]) => l).join(', ')}`,
      'transformers'
    );
  }
  const hit = entries.find(([, label]) => INJECTION_LABEL_PATTERN.test(label));
  if (hit) return Number(hit[0]);
  // Binary classifiers conventionally put the positive class last.
  return entries.length > 0 ? entries.length - 1 : 1;
}

function softmax(logits: number[], temperature: number): number[] {
  const scaled = logits.map((l) => l / temperature);
  const max = Math.max(...scaled);
  const exps = scaled.map((l) => Math.exp(l - max));
  const sum = exps.reduce((a, b) => a + b, 0);
  return exps.map((e) => e / sum);
}

export class TransformersClassifier implements MLClassifier {
  readonly name = 'transformers';
  private loaded: Promise<LoadedModel> | null = null;

  constructor(private readonly config: TransformersClassifierConfig) {}

  private load(): Promise<LoadedModel> {
    if (!this.loaded) {
      this.loaded = this.doLoad().catch((error) => {
        this.loaded = null; // allow a retry on the next call
        throw error;
      });
    }
    return this.loaded;
  }

  private async doLoad(): Promise<LoadedModel> {
    const hf = await loadTransformers();
    const env = hf.env as { cacheDir?: string; allowRemoteModels?: boolean; allowLocalModels?: boolean } | undefined;
    if (env) {
      if (this.config.cacheDir) env.cacheDir = this.config.cacheDir;
      if (this.config.localFilesOnly) env.allowRemoteModels = false;
      env.allowLocalModels = true;
    }

    const AutoTokenizer = hf.AutoTokenizer as { from_pretrained: (id: string, o?: Record<string, unknown>) => Promise<unknown> };
    const AutoModel = hf.AutoModelForSequenceClassification as {
      from_pretrained: (id: string, o?: Record<string, unknown>) => Promise<unknown>;
    };

    const options: Record<string, unknown> = {};
    if (this.config.dtype) options.dtype = this.config.dtype;
    if (this.config.localFilesOnly) options.local_files_only = true;

    const isLocalPath = this.config.model.startsWith('/') || this.config.model.startsWith('.') || existsSync(this.config.model);

    let tokenizer: unknown;
    let model: unknown;
    try {
      [tokenizer, model] = await Promise.all([
        AutoTokenizer.from_pretrained(this.config.model, options),
        AutoModel.from_pretrained(this.config.model, options),
      ]);
    } catch (error) {
      throw new MLClassifierError(
        `Could not load model "${this.config.model}": ${error instanceof Error ? error.message : String(error)}`,
        'transformers',
        error
      );
    }

    const id2label = ((model as { config?: { id2label?: Record<string, string> } }).config?.id2label ?? {
      '0': 'SAFE',
      '1': 'INJECTION',
    }) as Record<string, string>;

    const temperature =
      this.config.temperature ?? (isLocalPath ? readCalibration(this.config.model) : undefined) ?? 1;

    return {
      tokenizer: tokenizer as LoadedModel['tokenizer'],
      model: model as LoadedModel['model'],
      id2label,
      injectionIndex: pickInjectionIndex(id2label, this.config.injectionLabel),
      temperature,
    };
  }

  async classify(text: string): Promise<MLClassifyResult> {
    const start = performance.now();
    const loaded = await this.load();

    const input = text.length > this.config.maxChars ? text.slice(0, this.config.maxChars) : text;
    const encoded = loaded.tokenizer(input, { truncation: true, padding: true });
    const output = await loaded.model(encoded);
    const logits = Array.from(output.logits.data as ArrayLike<number>).slice(0, output.logits.dims.at(-1) ?? 2);
    const probs = softmax(logits, loaded.temperature);
    const score = clamp01(probs[loaded.injectionIndex] ?? 0);

    return {
      score,
      label: score >= 0.5 ? 'injection' : 'benign',
      latencyMs: performance.now() - start,
      model: this.config.model,
      raw: { logits, temperature: loaded.temperature, labels: loaded.id2label },
    };
  }
}
