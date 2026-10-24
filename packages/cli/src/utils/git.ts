/**
 * Git Context Extraction
 *
 * Collects git information from the current repository for run tracking.
 */

import { execSync } from 'child_process';

export interface GitInfo {
  sha: string;
  ref?: string;
  message?: string;
  pr_number?: number;
}

/**
 * Execute a git command and return the output
 */
function execGit(command: string): string | null {
  try {
    return execSync(`git ${command}`, {
      encoding: 'utf-8',
      stdio: ['pipe', 'pipe', 'pipe'],
    }).trim();
  } catch {
    return null;
  }
}

/**
 * Get PR number from CI environment variables
 */
function getPRNumber(): number | undefined {
  // GitHub Actions
  const ghPR = process.env.GITHUB_PR_NUMBER || process.env.GITHUB_EVENT_NUMBER;
  if (ghPR) return parseInt(ghPR, 10);

  // GitLab CI
  const glPR = process.env.CI_MERGE_REQUEST_IID;
  if (glPR) return parseInt(glPR, 10);

  // CircleCI
  const circlePR = process.env.CIRCLE_PR_NUMBER;
  if (circlePR) return parseInt(circlePR, 10);

  // Azure DevOps
  const azurePR = process.env.SYSTEM_PULLREQUEST_PULLREQUESTID;
  if (azurePR) return parseInt(azurePR, 10);

  // Bitbucket
  const bbPR = process.env.BITBUCKET_PR_ID;
  if (bbPR) return parseInt(bbPR, 10);

  return undefined;
}

/**
 * Get git information from the current repository
 * Returns null if not in a git repository
 */
export function getGitInfo(): GitInfo | null {
  // Check if we're in a git repository
  const sha = execGit('rev-parse HEAD');
  if (!sha) {
    return null;
  }

  // Get branch/ref
  let ref = execGit('symbolic-ref --short HEAD');
  if (!ref) {
    // Might be in detached HEAD state, try to get the ref from CI env
    ref = process.env.GITHUB_REF ||
          process.env.CI_COMMIT_REF_NAME ||
          process.env.CIRCLE_BRANCH ||
          process.env.BUILD_SOURCEBRANCHNAME ||
          process.env.BITBUCKET_BRANCH ||
          null;
  }

  // Get commit message
  const message = execGit('log -1 --format=%s');

  // Get PR number
  const pr_number = getPRNumber();

  return {
    sha,
    ref: ref || undefined,
    message: message || undefined,
    pr_number,
  };
}

export default getGitInfo;
