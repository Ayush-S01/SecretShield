/**
 * VS Code Diagnostics Manager
 *
 * Converts SecretShieldFindings into VS Code Diagnostics and manages
 * the DiagnosticCollection lifecycle.
 *
 * Key guarantees:
 * - Diagnostics are keyed by URI, not by finding identity
 * - Clearing a document replaces (not appends) its diagnostics
 * - Secret values are NEVER placed in diagnostic messages
 */

import * as vscode from 'vscode';
import * as path from 'path';
import { SecretShieldFinding, SecretShieldSeverity } from '../core/models/SecretShieldFinding';
import { buildShortMessage } from '../core/analysis/remediation';

const DIAGNOSTIC_SOURCE = 'SecretShield';

export class DiagnosticsManager {
  private readonly collection: vscode.DiagnosticCollection;

  constructor() {
    this.collection = vscode.languages.createDiagnosticCollection(DIAGNOSTIC_SOURCE);
  }

  /**
   * Updates diagnostics for a specific file URI.
   * Replaces any previous diagnostics for that URI.
   */
  updateForFile(uri: vscode.Uri, findings: SecretShieldFinding[]): void {
    const diagnostics = findings
      .filter((f) => f.filePath !== '')
      .map((f) => this.findingToDiagnostic(f));

    this.collection.set(uri, diagnostics);
  }

  /**
   * Clears diagnostics for a specific file URI.
   */
  clearForFile(uri: vscode.Uri): void {
    this.collection.set(uri, []);
  }

  /**
   * Clears all diagnostics across all files.
   */
  clearAll(): void {
    this.collection.clear();
  }

  /**
   * Returns the total number of active findings across all files.
   */
  getTotalFindingCount(): number {
    let count = 0;
    this.collection.forEach((uri, diagnostics) => {
      count += diagnostics.length;
    });
    return count;
  }

  dispose(): void {
    this.collection.dispose();
  }

  // ---------------------------------------------------------------------------
  // Private
  // ---------------------------------------------------------------------------

  private findingToDiagnostic(finding: SecretShieldFinding): vscode.Diagnostic {
    const range = this.findingToRange(finding);
    const severity = this.toVsCodeSeverity(finding.severity);

    const shortMsg = buildShortMessage(finding.ruleId, finding.severity);
    const diagnostic = new vscode.Diagnostic(range, shortMsg, severity);

    diagnostic.source = DIAGNOSTIC_SOURCE;
    diagnostic.code = finding.ruleId;

    // Hover markdown — shown when the developer hovers over the underline
    // NOTE: We deliberately omit the matched secret value
    const hoverLines = [
      `## 🛡 SecretShield`,
      ``,
      `**Potential secret detected in local (uncommitted) code.**`,
      ``,
      `| Field | Value |`,
      `|-------|-------|`,
      `| **Detector** | \`${finding.ruleId}\` |`,
      `| **Description** | ${finding.description} |`,
      `| **Severity** | ${finding.severity} |`,
      `| **Source** | ${finding.source} |`,
      `| **File** | \`${path.basename(finding.filePath)}\` |`,
      `| **Line** | ${finding.line} |`,
      finding.isCommitted ? `| **Commit** | \`${finding.commit.substring(0, 8)}\` |` : '',
      ``,
      `### Recommended Action`,
      ``,
      finding.remediation.replace(/\n/g, '  \n'),
    ]
      .filter((l) => l !== undefined)
      .join('\n');

    diagnostic.relatedInformation = [
      new vscode.DiagnosticRelatedInformation(
        new vscode.Location(
          vscode.Uri.file(finding.filePath),
          range
        ),
        `${DIAGNOSTIC_SOURCE}: ${finding.ruleId}`
      ),
    ];

    // Store hover as message (VS Code shows this in Problems + hover tooltip)
    // We override the main message to be short; use related info for detail
    const md = new vscode.MarkdownString(hoverLines);
    md.isTrusted = true;

    // Attach hover as code description (shown in hover widget)
    // This works via the diagnostic's message + a code action
    (diagnostic as vscode.Diagnostic & { _hoverMessage?: vscode.MarkdownString })._hoverMessage = md;

    return diagnostic;
  }

  private findingToRange(finding: SecretShieldFinding): vscode.Range {
    // VS Code ranges are 0-based; Gitleaks StartColumn is 1-based.
    // Gitleaks EndColumn is inclusive, VS Code end position is exclusive.
    const line = Math.max(0, finding.line - 1);
    const startCol = Math.max(0, finding.startColumn - 1);
    
    // By keeping finding.endColumn as is, we satisfy VS Code's exclusive end position
    const endCol = finding.endColumn > finding.startColumn
      ? finding.endColumn
      : startCol + 20; // fallback width

    return new vscode.Range(
      new vscode.Position(line, startCol),
      new vscode.Position(line, endCol)
    );
  }

  private toVsCodeSeverity(severity: SecretShieldSeverity): vscode.DiagnosticSeverity {
    switch (severity) {
      case 'CRITICAL':
      case 'HIGH':
        return vscode.DiagnosticSeverity.Error;
      case 'MEDIUM':
        return vscode.DiagnosticSeverity.Warning;
      case 'LOW':
        return vscode.DiagnosticSeverity.Information;
      case 'INFO':
        return vscode.DiagnosticSeverity.Hint;
    }
  }
}
