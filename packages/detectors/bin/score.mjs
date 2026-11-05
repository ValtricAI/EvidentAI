#!/usr/bin/env node
/**
 * Thin wrapper: runs ./score.ts through the tsx CLI so the TypeScript source
 * of the detector library can be used without a build step.
 *
 *   node packages/detectors/bin/score.mjs --sensitivity medium < in.jsonl > out.jsonl
 */
import { spawnSync } from 'node:child_process';
import { createRequire } from 'node:module';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const require = createRequire(import.meta.url);
const tsxCli = require.resolve('tsx/cli');

const result = spawnSync(
  process.execPath,
  [tsxCli, resolve(here, 'score.ts'), ...process.argv.slice(2)],
  { stdio: 'inherit' }
);
process.exit(result.status ?? 1);
