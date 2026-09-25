/**
 * Gitleaks Parser
 *
 * Parses the structured JSON output of Gitleaks into SecretShieldFinding objects.
 *
 * Gitleaks JSON output schema (v8.x):
 * [
 *   {
 *     "Description": "...",
 *     "StartLine": 12,
 *     "EndLine": 12,
 *     "StartColumn": 15,
 *     "EndColumn": 42,
 *     "Match": "...",       // May contain the secret — we do NOT log this
 *     "Secret": "...",      // The matched secret — we do NOT log this
 *     "File": "src/config.ts",
 *     "SymlinkFile": "",
 *     "Commit": "",
 *     "Entropy": 3.5,
 *     "Author": "",
 *     "Email": "",
 *     "Date": "",
 *     "Message": "",
 *     "Tags": [],
 *     "RuleID": "aws-access-token",
 *     "Fingerprint": "abc123..."
 *   }
 * ]
 */

import * as path from 'path';
import { SecretShieldFinding } from '../models/SecretShieldFinding';
import { mapSeverity } from '../analysis/severity';
import { buildRemediation } from '../analysis/remediation';

/** Raw structure of a single Gitleaks JSON finding (v8.x format). */
export interface RawGitleaksFinding {
  Description?: string;
  StartLine?: number;
  EndLine?: number;
  StartColumn?: number;
  EndColumn?: number;
  Match?: string;
  Secret?: string;
  File?: string;
  SymlinkFile?: string;
  Commit?: string;
  Entropy?: number;
  Author?: string;
  Email?: string;
  Date?: string;
  Message?: string;
  Tags?: string[];
  RuleID?: string;
  Fingerprint?: string;
}

/**
 * Parses raw Gitleaks JSON output into an array of SecretShieldFindings.
 *
 * @param jsonOutput  Raw stdout from gitleaks (JSON array string)
 * @param baseDir     The base directory used during the scan (for path normalization)
 * @returns           Array of normalized findings
 * @throws            If the JSON is malformed
 */
export function parseGitleaksOutput(
  jsonOutput: string,
  baseDir: string
): SecretShieldFinding[] {
  const trimmed = jsonOutput.trim();

  // Gitleaks outputs null when no findings
  if (!trimmed || trimmed === 'null' || trimmed === '[]') {
    return [];
  }

  let rawFindings: RawGitleaksFinding[];
  try {
    rawFindings = JSON.parse(trimmed);
  } catch (err) {
    throw new Error(`Failed to parse Gitleaks JSON output: ${(err as Error).message}`);
  }

  if (!Array.isArray(rawFindings)) {
    throw new Error('Gitleaks output was not a JSON array');
  }

  return rawFindings
    .filter((raw) => raw && typeof raw === 'object')
    .map((raw) => normalizeFinding(raw, baseDir));
}

function normalizeFinding(raw: RawGitleaksFinding, baseDir: string): SecretShieldFinding {
  const ruleId = raw.RuleID || 'unknown-rule';
  const description = raw.Description || ruleId;
  const severity = mapSeverity(ruleId);

  // Resolve file path to absolute
  const rawFile = raw.File || '';
  const filePath = rawFile
    ? path.isAbsolute(rawFile)
      ? rawFile
      : path.resolve(baseDir, rawFile)
    : '';

  const line = raw.StartLine ?? 1;
  const startColumn = raw.StartColumn ?? 1;
  const endColumn = raw.EndColumn ?? startColumn;
  const commit = raw.Commit || '';
  const isCommitted = commit.length > 0;
  const fingerprint = raw.Fingerprint || `${filePath}:${line}:${ruleId}`;

  const remediation = buildRemediation({ ruleId, severity, isCommitted });

  return {
    filePath,
    line,
    startColumn,
    endColumn,
    ruleId,
    description,
    severity,
    source: 'Gitleaks',
    fingerprint,
    commit,
    remediation,
    isCommitted,
  };
}
