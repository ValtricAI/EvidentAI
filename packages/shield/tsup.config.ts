import { defineConfig } from 'tsup';

export default defineConfig({
  entry: [
    'src/index.ts',
    'src/middleware/express.ts',
    'src/middleware/fastify.ts',
    'src/middleware/standalone.ts',
  ],
  format: ['cjs', 'esm'],
  dts: true,
  clean: true,
  splitting: false,
  sourcemap: true,
  treeshake: true,
  // Private workspace package: bundle it so the published shield is self-contained.
  noExternal: ['@evidentai/detectors'],
});
