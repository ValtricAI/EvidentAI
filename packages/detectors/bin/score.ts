/**
 * Score texts with the regex injection library, for the Python eval harness.
 *
 * Reads JSON lines from stdin, each `{ "id": string, "text": string }`, and
 * writes one JSON line per input:
 *
 *   { "id", "score", "detected", "severity", "techniques": [...], "latencyMs" }
 *
 * `score` is an ordinal proxy in [0, 1] derived from the highest severity and
 * the number of matches so that AUROC can be computed alongside learned
 * classifiers: none 0, low 0.25, medium 0.5, high 0.75, critical 0.9, plus
 * 0.01 per additional match (capped at 1).
 *
 * Run through the `score.mjs` wrapper (which invokes tsx):
 *   node packages/detectors/bin/score.mjs --sensitivity medium < in.jsonl > out.jsonl
 */

import { createInterface } from 'node:readline';
// Import the regex module directly (not the package index) so this bridge has
// no dependency on the optional ML backends.
import { detectInjection, highestSeverity } from '../src/injection';
import type { Sensitivity } from '../src/types';

const args = process.argv.slice(2);
const sensIdx = args.indexOf('--sensitivity');
const sensitivity = (sensIdx !== -1 ? args[sensIdx + 1] : 'medium') as Sensitivity;
if (!['low', 'medium', 'high'].includes(sensitivity)) {
  console.error(`invalid --sensitivity ${sensitivity}`);
  process.exit(2);
}

const SEVERITY_SCORE: Record<string, number> = { none: 0, low: 0.25, medium: 0.5, high: 0.75, critical: 0.9 };

async function main(): Promise<void> {
  const rl = createInterface({ input: process.stdin, crlfDelay: Infinity });
  const out: string[] = [];
  for await (const line of rl) {
    if (!line.trim()) continue;
    const row = JSON.parse(line) as { id: unknown; text?: unknown };
    const t0 = performance.now();
    const matches = detectInjection(String(row.text ?? ''), { sensitivity });
    const latencyMs = performance.now() - t0;
    const severity = highestSeverity(matches);
    const score = Math.min(1, (SEVERITY_SCORE[severity] ?? 0) + Math.max(0, matches.length - 1) * 0.01);
    out.push(
      JSON.stringify({
        id: row.id,
        score,
        detected: matches.length > 0,
        severity,
        techniques: [...new Set(matches.map((m) => m.technique))],
        latencyMs,
      })
    );
    if (out.length >= 500) {
      process.stdout.write(out.join('\n') + '\n');
      out.length = 0;
    }
  }
  if (out.length) process.stdout.write(out.join('\n') + '\n');
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
