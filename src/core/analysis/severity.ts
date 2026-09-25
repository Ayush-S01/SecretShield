/**
 * Severity Mapping
 *
 * Determines SecretShield severity from Gitleaks rule information.
 *
 * Mapping logic (transparent, deterministic — no ML):
 *
 * - Rules matching known high-value secret types → CRITICAL
 * - Rules matching cloud provider keys, OAuth tokens → HIGH
 * - Rules matching generic API keys, tokens → MEDIUM
 * - Rules matching potential secrets with low confidence → LOW
 * - Everything else (informational) → INFO
 *
 * This mapping is intentionally conservative. When in doubt, severity
 * is elevated rather than suppressed.
 */

import { SecretShieldSeverity } from '../models/SecretShieldFinding';

/** Gitleaks rule IDs (or prefixes) that map to CRITICAL severity. */
const CRITICAL_RULES = new Set([
  'private-key',
  'rsa-private-key',
  'openssh-private-key',
  'pgp-private-key',
  'aws-secret-access-key',
  'gcp-service-account-key',
  'stripe-secret-key',
  'stripe-restricted-key',
  'paypal-braintree-access-token',
  'hashicorp-vault-service-token',
  'age-secret-key',
]);

/** Gitleaks rule ID prefixes that map to HIGH severity. */
const HIGH_RULE_PREFIXES = [
  'aws',
  'gcp',
  'google',
  'azure',
  'github',
  'gitlab',
  'npm',
  'slack',
  'twilio',
  'sendgrid',
  'mailchimp',
  'jwt',
  'oauth',
  'databricks',
  'digitalocean',
  'heroku',
  'shopify',
  'dropbox',
];

/**
 * Maps a Gitleaks rule ID to a SecretShield severity level.
 *
 * @param ruleId  The Gitleaks rule/detector ID (e.g. "aws-access-token")
 * @returns       The corresponding SecretShieldSeverity
 */
export function mapSeverity(ruleId: string): SecretShieldSeverity {
  const lower = ruleId.toLowerCase();

  if (CRITICAL_RULES.has(lower)) {
    return 'CRITICAL';
  }

  for (const prefix of HIGH_RULE_PREFIXES) {
    if (lower.startsWith(prefix)) {
      return 'HIGH';
    }
  }

  // Generic API key patterns
  if (lower.includes('key') || lower.includes('token') || lower.includes('secret')) {
    return 'MEDIUM';
  }

  return 'LOW';
}

/**
 * Returns the VS Code DiagnosticSeverity number equivalent for a given severity.
 * (0=Error, 1=Warning, 2=Information, 3=Hint)
 */
export function toVsCodeSeverityNumber(severity: SecretShieldSeverity): number {
  switch (severity) {
    case 'CRITICAL':
    case 'HIGH':
      return 0; // Error
    case 'MEDIUM':
      return 1; // Warning
    case 'LOW':
      return 2; // Information
    case 'INFO':
      return 3; // Hint
  }
}
