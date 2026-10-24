import { ConsoleReporter } from './console';
import { JsonReporter } from './json';
import { TapReporter } from './tap';
import { JUnitReporter } from './junit';
import { GithubPrReporter } from './github-pr';

export const REPORTER_FORMATS = ['pretty', 'json', 'tap', 'junit', 'github-pr'] as const;
export type ReporterFormat = (typeof REPORTER_FORMATS)[number];

export function isReporterFormat(value: string): value is ReporterFormat {
  return (REPORTER_FORMATS as readonly string[]).includes(value);
}

export function getReporter(format: ReporterFormat) {
  switch (format) {
    case 'json':
      return new JsonReporter();
    case 'tap':
      return new TapReporter();
    case 'junit':
      return new JUnitReporter();
    case 'github-pr':
      return new GithubPrReporter();
    case 'pretty':
    default:
      return new ConsoleReporter();
  }
}

export { ConsoleReporter } from './console';
export { JsonReporter } from './json';
export { TapReporter } from './tap';
export { JUnitReporter } from './junit';
export { GithubPrReporter } from './github-pr';
