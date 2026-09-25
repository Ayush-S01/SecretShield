/**
 * Remediation Guidance
 *
 * Produces actionable remediation advice based on the finding context.
 * The text is deliberately calibrated to the situation:
 *
 * - Uncommitted local file → advise removal + use env var (no rotation advice)
 * - Committed finding → advise removal + history rewrite + rotation
 * - Public exposure → advise immediate rotation (future use case)
 *
 * SecretShield does NOT tell a developer to rotate a credential merely
 * because a local uncommitted value was detected.
 */

import { SecretShieldSeverity } from '../models/SecretShieldFinding';

export interface RemediationContext {
  ruleId: string;
  severity: SecretShieldSeverity;
  isCommitted: boolean;
}

/**
 * Returns actionable remediation text for a finding.
 */
export function buildRemediation(ctx: RemediationContext): string {
  if (ctx.isCommitted) {
    return (
      `This secret appears to have been committed to Git history. ` +
      `Take the following steps:\n` +
      `1. Remove the secret from the file immediately.\n` +
      `2. Rotate/revoke the credential — it may have been exposed.\n` +
      `3. Rewrite Git history (git filter-repo or BFG Repo Cleaner) to remove the secret.\n` +
      `4. Use an environment variable or a secrets manager instead.\n` +
      `5. Audit access logs for the affected credential.`
    );
  }

  return (
    `A potential secret was detected in your local (uncommitted) code. ` +
    `Steps to fix:\n` +
    `1. Remove the credential value from the source file.\n` +
    `2. Store it in an environment variable (e.g. via a .env file excluded from Git).\n` +
    `3. Reference it in code as process.env.YOUR_VAR_NAME or equivalent.\n` +
    `4. Add .env to your .gitignore file.\n` +
    `Note: Do NOT commit this file. There is no need to rotate the credential ` +
    `unless it has already been shared or committed.`
  );
}

/**
 * Returns a short single-line summary for the Problems panel.
 */
export function buildShortMessage(ruleId: string, severity: SecretShieldSeverity): string {
  return `[SecretShield] Potential secret detected — Rule: ${ruleId} | Severity: ${severity}`;
}
