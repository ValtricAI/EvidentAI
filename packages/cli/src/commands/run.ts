/**
 * Run Command
 *
 * The main CLI entrypoint for executing test suites.
 * Usage: releasegate run [options]
 *
 * Features:
 * - Config file discovery and loading
 * - Test execution with progress reporting
 * - Multiple output formats (JSON, TAP, JUnit, GitHub PR markdown)
 * - CI/CD integration with exit codes
 * - Result uploading to ReleaseGate cloud
 */

import { Command } from 'commander';
import * as fs from 'fs';
import * as path from 'path';
import { loadConfig } from '../config/loader';
import type { Config } from '../config/types';
import { execute, type RunResult, type ProgressEvent } from '../runner/executor';
import { ConsoleReporter, getReporter, isReporterFormat, REPORTER_FORMATS, type ReporterFormat } from '../runner/reporters';
import { getGitInfo } from '../utils/git';
import { hashConfig } from '../utils/hash';
import { colorize } from '../utils/logger';

// =============================================================================
// Types
// =============================================================================

interface RunOptions {
  config?: string;
  suite?: string[];
  concurrency?: string;
  timeout?: string;
  retries?: string;
  retryDelay?: string;
  verbose?: boolean;
  quiet?: boolean;
  output?: string;
  format?: string;
  upload?: boolean;
  noThresholds?: boolean;
  dryRun?: boolean;
}

// =============================================================================
// Progress Reporter
// =============================================================================

class ProgressReporter {
  private verbose: boolean;
  private quiet: boolean;

  constructor(verbose: boolean, quiet: boolean) {
    this.verbose = verbose;
    this.quiet = quiet;
  }

  onProgress(event: ProgressEvent): void {
    if (this.quiet) return;

    switch (event.type) {
      case 'suite_start':
        console.log(`\n▶ Suite: ${event.suite}`);
        break;

      case 'test_end':
        if (this.verbose || !event.passed) {
          const status = event.passed ? '✓' : '✗';
          const colorName = event.passed ? 'green' : 'red';
          console.log(`  ${colorize(status, colorName as 'green' | 'red')} ${event.testCase} (${event.current}/${event.total})`);
        } else {
          // Simple progress indicator
          process.stdout.write('.');
        }
        break;

      case 'suite_end':
        if (!this.verbose) {
          console.log(''); // New line after dots
        }
        break;
    }
  }

  log(message: string): void {
    if (!this.quiet) {
      console.log(message);
    }
  }

  error(message: string): void {
    console.error(colorize(`✗ ${message}`, 'red'));
  }

  warn(message: string): void {
    if (!this.quiet) {
      console.warn(colorize(`⚠ ${message}`, 'yellow'));
    }
  }
}

// =============================================================================
// API Payload Types
// =============================================================================

interface ApiRunCreate {
  project_id: string;
  git?: {
    sha: string;
    ref?: string;
    message?: string;
    pr_number?: number;
  };
  config_hash: string;
  started_at: string;
  finished_at: string;
  duration_ms: number;
  status: 'passed' | 'failed' | 'error';
  total: number;
  passed: number;
  failed: number;
  pass_rate: number;
  suites: Array<{
    name: string;
    total: number;
    passed: number;
    failed: number;
    pass_rate: number;
    cases: Array<{
      name: string;
      input: string;
      output: string;
      passed: boolean;
      score: number;
      evaluator: string;
      evaluator_result: {
        passed: boolean;
        score: number;
        reason?: string;
        details?: Record<string, unknown>;
      };
      latency_ms: number;
      tokens_used?: number;
      cost_usd?: number;
      error?: string;
    }>;
  }>;
  metrics: {
    pii_detected: number;
    prompt_injection_attempts: number;
    avg_latency_ms: number;
    total_tokens: number;
    total_cost_usd: number;
  };
  thresholds_met: boolean;
  threshold_violations?: string[];
}

// =============================================================================
// Transform RunResult to API Payload
// =============================================================================

function transformToApiPayload(
  result: RunResult,
  config: Config,
  startedAt: Date
): ApiRunCreate {
  // Collect metrics from evaluator results
  let piiDetected = 0;
  let promptInjectionAttempts = 0;
  let totalLatencyMs = 0;
  let totalCases = 0;

  for (const suite of result.suites) {
    for (const tc of suite.testCases) {
      totalLatencyMs += tc.latencyMs;
      totalCases++;

      // Check evaluator type for metrics
      if (tc.evaluator === 'pii' && !tc.result.passed) {
        piiDetected += (tc.result.details?.total_matches as number) || 1;
      }
      if (tc.evaluator === 'prompt-injection' && !tc.result.passed) {
        promptInjectionAttempts += (tc.result.details?.total_matches as number) || 1;
      }
    }
  }

  return {
    project_id: config.project.id || config.project.name,
    git: getGitInfo() || undefined,
    config_hash: hashConfig(config),
    started_at: startedAt.toISOString(),
    finished_at: result.timestamp,
    duration_ms: result.durationMs,
    status: result.thresholdsResult.passed ? 'passed' : 'failed',
    total: result.total,
    passed: result.passed,
    failed: result.failed,
    pass_rate: result.passRate,
    suites: result.suites.map((suite) => ({
      name: suite.name,
      total: suite.total,
      passed: suite.passed,
      failed: suite.failed,
      pass_rate: suite.passRate,
      cases: suite.testCases.map((tc) => ({
        name: tc.name,
        input: tc.input,
        output: tc.output,
        passed: tc.result.passed,
        score: tc.result.score,
        evaluator: tc.evaluator,
        evaluator_result: {
          passed: tc.result.passed,
          score: tc.result.score,
          reason: tc.result.reason,
          details: tc.result.details,
        },
        latency_ms: tc.latencyMs,
      })),
    })),
    metrics: {
      pii_detected: piiDetected,
      prompt_injection_attempts: promptInjectionAttempts,
      avg_latency_ms: totalCases > 0 ? totalLatencyMs / totalCases : 0,
      total_tokens: 0, // Not tracked yet
      total_cost_usd: 0, // Not tracked yet
    },
    thresholds_met: result.thresholdsResult.passed,
    threshold_violations: result.thresholdsResult.checks
      .filter((c) => !c.passed)
      .map((c) => `${c.name}: ${(c.actual * 100).toFixed(1)}% < ${(c.threshold * 100).toFixed(1)}%`),
  };
}

// =============================================================================
// Result Uploader
// =============================================================================

async function uploadResults(
  result: RunResult,
  config: Config,
  startedAt: Date,
  apiKey?: string
): Promise<boolean> {
  const key = apiKey || process.env.RELEASEGATE_API_KEY;
  if (!key) {
    console.warn('⚠ No API key found. Set RELEASEGATE_API_KEY to upload results.');
    return false;
  }

  const endpoint = process.env.RELEASEGATE_API_URL || 'https://api.releasegate.dev';

  try {
    // Transform to API format
    const payload = transformToApiPayload(result, config, startedAt);

    const response = await fetch(`${endpoint}/api/v1/runs`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-API-Key': key,
      },
      body: JSON.stringify(payload),
    });

    if (!response.ok) {
      const error = await response.text();
      console.error(`✗ Upload failed: ${response.status} - ${error}`);
      return false;
    }

    const data = (await response.json()) as { id: string; dashboard_url: string };
    console.log(`✓ Results uploaded: ${data.dashboard_url}`);
    return true;
  } catch (error) {
    console.error(`✗ Upload failed: ${error instanceof Error ? error.message : String(error)}`);
    return false;
  }
}

// =============================================================================
// Main Run Command
// =============================================================================

// =============================================================================
// CLI Option Validation
// =============================================================================

interface ValidatedOptions {
  concurrency: number;
  timeout: number;
  retries: number;
  retryDelay: number;
  format: ReporterFormat;
}

function validateOptions(options: RunOptions): ValidatedOptions {
  const errors: string[] = [];

  const concurrency = parseInt(options.concurrency || '5', 10);
  if (isNaN(concurrency) || concurrency < 1 || concurrency > 100) {
    errors.push(`--concurrency must be between 1 and 100 (got: ${options.concurrency})`);
  }

  const timeout = parseInt(options.timeout || '60000', 10);
  if (isNaN(timeout) || timeout < 1000 || timeout > 600000) {
    errors.push(`--timeout must be between 1000ms and 600000ms (10 min) (got: ${options.timeout})`);
  }

  const retries = parseInt(options.retries || '3', 10);
  if (isNaN(retries) || retries < 0 || retries > 10) {
    errors.push(`--retries must be between 0 and 10 (got: ${options.retries})`);
  }

  const retryDelay = parseInt(options.retryDelay || '1000', 10);
  if (isNaN(retryDelay) || retryDelay < 100 || retryDelay > 60000) {
    errors.push(`--retry-delay must be between 100ms and 60000ms (got: ${options.retryDelay})`);
  }

  const formatOption = options.format || 'pretty';
  if (!isReporterFormat(formatOption)) {
    errors.push(`--format must be one of ${REPORTER_FORMATS.join(', ')} (got: ${formatOption})`);
  }

  if (errors.length > 0) {
    throw new Error(`Invalid options:\n  ${errors.join('\n  ')}`);
  }

  return { concurrency, timeout, retries, retryDelay, format: formatOption as ReporterFormat };
}

// =============================================================================
// Main Run Command
// =============================================================================

export function createRunCommand(): Command {
  const command = new Command('run')
    .description('Run test suites against your LLM application')
    .option('-c, --config <path>', 'Path to configuration file')
    .option('-s, --suite <names...>', 'Run specific suites only')
    .option('--concurrency <n>', 'Max concurrent test executions (default: 5, range: 1-100)', '5')
    .option('--timeout <ms>', 'Request timeout in milliseconds (default: 60000, range: 1000-600000)', '60000')
    .option('--retries <n>', 'Max retry attempts per LLM call (default: 3, range: 0-10)', '3')
    .option('--retry-delay <ms>', 'Base retry delay in milliseconds (default: 1000, range: 100-60000)', '1000')
    .option('-v, --verbose', 'Show detailed output for each test')
    .option('-q, --quiet', 'Suppress all output except errors')
    .option('-o, --output <path>', 'Write results to file')
    .option('-f, --format <format>', `Output format: ${REPORTER_FORMATS.join(', ')}`, 'pretty')
    .option('--upload', 'Upload results to ReleaseGate cloud')
    .option('--no-thresholds', 'Skip threshold checks (always exit 0)')
    .option('--dry-run', 'Load config and show what would run without executing')
    .addHelpText('after', `
Examples:
  $ releasegate run                           Run all test suites
  $ releasegate run --suite accuracy safety   Run specific suites only
  $ releasegate run --verbose                 Show detailed test output
  $ releasegate run --dry-run                 Preview without executing
  $ releasegate run -o results.json -f json   Output results to JSON file
  $ releasegate run -o comment.md -f github-pr Write a markdown summary for a PR comment
  $ releasegate run --timeout 120000          Increase timeout to 2 minutes
  $ releasegate run --upload                  Upload results to dashboard

Exit codes:
  0  All tests passed and thresholds met
  1  Tests failed or thresholds not met
`)
    .action(async (options: RunOptions) => {
      await runCommand(options);
    });

  return command;
}

async function runCommand(options: RunOptions): Promise<void> {
  const reporter = new ProgressReporter(
    options.verbose ?? false,
    options.quiet ?? false
  );

  try {
    // Validate CLI options first
    const validatedOpts = validateOptions(options);

    // Load configuration
    reporter.log('Loading configuration...');
    const { config, configPath, warnings } = loadConfig({
      configPath: options.config,
    });

    reporter.log(`Using config: ${configPath}`);
    for (const warning of warnings) {
      reporter.warn(warning);
    }

    // Filter suites if specified
    if (options.suite && options.suite.length > 0) {
      const suiteSet = new Set(options.suite);
      config.suites = config.suites.filter((s) => suiteSet.has(s.name));
      if (config.suites.length === 0) {
        reporter.error(`No matching suites found for: ${options.suite.join(', ')}`);
        process.exit(1);
      }
      reporter.log(`Running ${config.suites.length} suite(s): ${config.suites.map((s) => s.name).join(', ')}`);
    }

    // Dry run - just show what would run
    if (options.dryRun) {
      reporter.log('\n--- Dry Run Mode ---\n');
      reporter.log(`Project: ${config.project.name}`);
      reporter.log(`Provider: ${config.provider.name} (${(config.provider as { model?: string }).model || 'default model'})`);
      reporter.log(`\nSuites:`);
      for (const suite of config.suites) {
        reporter.log(`  - ${suite.name} (${suite.cases.length} tests)`);
        for (const testCase of suite.cases) {
          reporter.log(`    • ${testCase.name} [${testCase.evaluator}]`);
        }
      }
      reporter.log(`\nThresholds:`);
      if (config.thresholds) {
        if (config.thresholds.pass_rate) {
          reporter.log(`  - pass_rate: ${(config.thresholds.pass_rate * 100).toFixed(0)}%`);
        }
        if (config.thresholds.average_score) {
          reporter.log(`  - average_score: ${(config.thresholds.average_score * 100).toFixed(0)}%`);
        }
      } else {
        reporter.log('  (none configured)');
      }
      reporter.log('\n--- End Dry Run ---');
      return;
    }

    // Calculate total tests for progress display
    const totalTests = config.suites.reduce((sum, s) => sum + s.cases.length, 0);
    reporter.log(`\nRunning ${totalTests} tests across ${config.suites.length} suite(s)...\n`);

    const startedAt = new Date();
    const result = await execute(config, {
      concurrency: validatedOpts.concurrency,
      timeoutMs: validatedOpts.timeout,
      maxRetries: validatedOpts.retries,
      retryDelayMs: validatedOpts.retryDelay,
      verbose: options.verbose,
      onProgress: (event) => reporter.onProgress(event),
    });

    // Format output
    const outputReporter = getReporter(validatedOpts.format);
    const output = outputReporter.format(result);

    // Write to file or console
    if (options.output) {
      const outputPath = path.isAbsolute(options.output)
        ? options.output
        : path.resolve(process.cwd(), options.output);

      // Ensure directory exists
      const dir = path.dirname(outputPath);
      if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
      }

      fs.writeFileSync(outputPath, output, 'utf-8');
      reporter.log(`Results written to: ${outputPath}`);
    }

    // Always show pretty output to console unless quiet
    if (!options.quiet) {
      const consoleReporter = new ConsoleReporter();
      console.log(consoleReporter.format(result));
    }

    // Show threshold violations in detail if any
    if (!result.thresholdsResult.passed && !options.quiet) {
      console.log(`\n${colorize('Threshold violations:', 'red')}`);
      for (const check of result.thresholdsResult.checks) {
        if (!check.passed) {
          const actualPct = (check.actual * 100).toFixed(1);
          const thresholdPct = (check.threshold * 100).toFixed(1);
          console.log(colorize(`  ✗ ${check.name}: ${actualPct}% (required: ${thresholdPct}%)`, 'red'));
        }
      }
      console.log('');
    }

    // Upload if requested
    if (options.upload || config.upload?.enabled) {
      await uploadResults(result, config, startedAt, config.upload?.api_key);
    }

    // Exit with appropriate code
    if (!options.noThresholds && !result.thresholdsResult.passed) {
      process.exit(1);
    }
  } catch (error) {
    reporter.error(error instanceof Error ? error.message : String(error));
    process.exit(1);
  }
}

// Direct execution support
export { runCommand };
