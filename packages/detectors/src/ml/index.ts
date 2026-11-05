/**
 * Classifier factory and backend registry.
 */

import { HttpClassifier } from './http';
import { JevClassifier } from './jev';
import { TransformersClassifier } from './transformers';
import {
  MLClassifierConfigSchema,
  MLClassifierError,
  type MLClassifier,
  type MLClassifierConfig,
  type MLClassifierConfigParsed,
} from './types';

export type ClassifierBackendFactory = (options: Record<string, unknown>) => MLClassifier;

const customBackends = new Map<string, ClassifierBackendFactory>();

/**
 * Register a classifier under a name usable as
 * `{ backend: 'custom', name, options }`. Handy for tests and for in-process
 * models that do not fit the built-in backends.
 */
export function registerClassifierBackend(name: string, factory: ClassifierBackendFactory): void {
  customBackends.set(name, factory);
}

export function unregisterClassifierBackend(name: string): void {
  customBackends.delete(name);
}

export function parseClassifierConfig(config: MLClassifierConfig): MLClassifierConfigParsed {
  return MLClassifierConfigSchema.parse(config);
}

export function createClassifier(config: MLClassifierConfig): MLClassifier {
  const parsed = parseClassifierConfig(config);
  switch (parsed.backend) {
    case 'transformers':
      return new TransformersClassifier(parsed);
    case 'http':
      return new HttpClassifier(parsed);
    case 'jev':
      return new JevClassifier(parsed);
    case 'custom': {
      const factory = customBackends.get(parsed.name);
      if (!factory) {
        throw new MLClassifierError(
          `No classifier backend registered under "${parsed.name}". Call registerClassifierBackend() first.`,
          'custom'
        );
      }
      return factory(parsed.options ?? {});
    }
  }
}

export { HttpClassifier, JevClassifier, TransformersClassifier };
export {
  MLClassifierConfigSchema,
  TransformersClassifierConfigSchema,
  HttpClassifierConfigSchema,
  JevClassifierConfigSchema,
  CustomClassifierConfigSchema,
  ScoreCutpointsSchema,
  DEFAULT_CUTPOINTS,
  MLClassifierError,
  scoreToSeverity,
  clamp01,
  getPath,
  type MLClassifier,
  type MLClassifyResult,
  type MLLabel,
  type MLClassifierConfig,
  type MLClassifierConfigParsed,
  type TransformersClassifierConfig,
  type HttpClassifierConfig,
  type JevClassifierConfig,
  type CustomClassifierConfig,
  type ScoreCutpoints,
} from './types';
