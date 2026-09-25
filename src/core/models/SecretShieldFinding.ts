/**
 * SecretShield Finding Model
 *
 * Normalized representation of a secret detection finding.
 * This abstracts the raw Gitleaks JSON so the rest of the extension
 * does not depend on the Gitleaks output format directly.
 */

export type SecretShieldSeverity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

export interface SecretShieldFinding {
  /** Absolute path to the file containing the potential secret. */
  filePath: string;

  /** 1-based line number where the secret was found. */
  line: number;

  /** 1-based start column (may be 0 if not reported by scanner). */
  startColumn: number;

  /** 1-based end column (may be 0 if not reported by scanner). */
  endColumn: number;

  /** The Gitleaks rule/detector ID that triggered (e.g. "aws-access-token"). */
  ruleId: string;

  /** Human-readable description of the rule. */
  description: string;

  /** Normalized severity derived from rule type and available information. */
  severity: SecretShieldSeverity;

  /** Always "Gitleaks" for MVP — identifies the detection engine. */
  source: 'Gitleaks';

  /** Gitleaks fingerprint (unique identifier for deduplication). */
  fingerprint: string;

  /** Commit hash if found in Git history; empty string for working-tree findings. */
  commit: string;

  /** Actionable remediation guidance. */
  remediation: string;

  /**
   * Whether this finding came from Git history (committed) vs working tree (uncommitted).
   * Affects the remediation text shown to the developer.
   */
  isCommitted: boolean;
}
