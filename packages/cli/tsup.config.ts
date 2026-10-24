import { defineConfig } from 'tsup';

export default defineConfig({
  entry: {
    index: 'src/index.ts',
    'runner/evaluators/index': 'src/runner/evaluators/index.ts',
  },
  format: ['cjs', 'esm'],
  dts: true,
  clean: true,
  sourcemap: true,
  splitting: false,
  // The shared detector library is a private workspace package: bundle it so
  // the published CLI has no dependency on it.
  noExternal: ['@evidentai/detectors'],
});
