/**
 * SecretShield Scanner Orchestrator
 *
 * Manages the scan lifecycle:
 * - Debounced real-time scanning on document change
 * - Scan on save
 * - Manual file / workspace scan
 * - Concurrency: only the latest scan wins; stale results are discarded
 * - Process cancellation when a newer scan starts
 */

import * as vscode from 'vscode';
import * as path from 'path';
import {
  scanFileContent,
  scanWorkspace,
  detectGitleaksVersion,
  resolveGitleaksPath,
  GitleaksVersionInfo,
} from '../core/scanner/gitleaksRunner';
import { SecretShieldFinding } from '../core/models/SecretShieldFinding';
import { DiagnosticsManager } from './diagnostics';
import { StatusBarManager } from './statusBar';
import { getSettings } from '../config/settings';

export class SecretShieldScanner {
  private readonly diagnostics: DiagnosticsManager;
  private readonly statusBar: StatusBarManager;

  /** Debounce timer handle. */
  private debounceTimer: ReturnType<typeof setTimeout> | undefined;

  /** AbortController for the currently running scan (allows cancellation). */
  private currentScanController: AbortController | undefined;

  /** Document version at the time the last scan was started (stale-result guard). */
  private lastScanVersion = -1;

  /** Cached gitleaks version info. */
  private gitleaksInfo: GitleaksVersionInfo | undefined;

  /** Output channel for diagnostic messages. */
  private readonly outputChannel: vscode.OutputChannel;

  constructor(
    diagnostics: DiagnosticsManager,
    statusBar: StatusBarManager,
    outputChannel: vscode.OutputChannel
  ) {
    this.diagnostics = diagnostics;
    this.statusBar = statusBar;
    this.outputChannel = outputChannel;
  }

  // ---------------------------------------------------------------------------
  // Public API
  // ---------------------------------------------------------------------------

  /**
   * Initializes the scanner: resolves and verifies the Gitleaks executable.
   */
  async initialize(): Promise<void> {
    this.gitleaksInfo = await this.resolveAndVerifyGitleaks();
    if (!this.gitleaksInfo.found) {
      this.statusBar.setState('no-gitleaks');
      this.log(
        `[SecretShield] Gitleaks not found. Configure secretshield.gitleaksPath.\n` +
          `  Error: ${this.gitleaksInfo.error ?? 'not found on PATH'}`
      );
    } else {
      this.statusBar.setState('ready');
      this.log(
        `[SecretShield] Gitleaks ready: ${this.gitleaksInfo.version} at ${this.gitleaksInfo.executablePath}`
      );
    }
  }

  /**
   * Called on document change — debounces a file scan.
   */
  onDocumentChanged(document: vscode.TextDocument): void {
    const settings = getSettings();
    if (!settings.enableRealtimeScan) {
      return;
    }
    if (!this.isScannableDocument(document)) {
      return;
    }

    // Cancel any existing debounce timer
    if (this.debounceTimer) {
      clearTimeout(this.debounceTimer);
    }

    this.debounceTimer = setTimeout(() => {
      this.scanDocument(document, 'realtime').catch((err) =>
        this.handleError(err, 'real-time scan')
      );
    }, settings.debounceMs);
  }

  /**
   * Called when a document is saved.
   */
  async onDocumentSaved(document: vscode.TextDocument): Promise<void> {
    const settings = getSettings();
    if (!settings.scanOnSave) {
      return;
    }
    if (!this.isScannableDocument(document)) {
      return;
    }
    await this.scanDocument(document, 'save');
  }

  /**
   * Manually scans the active editor document.
   */
  async scanCurrentFile(): Promise<void> {
    const editor = vscode.window.activeTextEditor;
    if (!editor) {
      vscode.window.showInformationMessage('SecretShield: No active file to scan.');
      return;
    }
    await this.scanDocument(editor.document, 'manual');
  }

  /**
   * Scans the entire workspace.
   */
  async scanWorkspaceFolders(): Promise<void> {
    if (!this.ensureGitleaks()) {
      return;
    }

    const folders = vscode.workspace.workspaceFolders;
    if (!folders || folders.length === 0) {
      vscode.window.showInformationMessage(
        'SecretShield: No workspace folder is open.'
      );
      return;
    }

    const settings = getSettings();
    this.statusBar.setState('scanning');
    this.outputChannel.appendLine('[SecretShield] Starting workspace scan...');

    // Cancel any in-flight scan
    this.cancelCurrentScan();
    const controller = new AbortController();
    this.currentScanController = controller;

    let totalFindings: SecretShieldFinding[] = [];

    try {
      for (const folder of folders) {
        if (controller.signal.aborted) {
          break;
        }
        this.outputChannel.appendLine(
          `[SecretShield] Scanning folder: ${folder.uri.fsPath}`
        );

        const findings = await scanWorkspace({
          gitleaksPath: this.gitleaksInfo!.executablePath,
          workspaceRoot: folder.uri.fsPath,
          excludePatterns: settings.excludePatterns,
          timeoutMs: settings.scanTimeoutMs,
          signal: controller.signal,
        });

        // Group findings by file and update diagnostics
        const byFile = new Map<string, SecretShieldFinding[]>();
        for (const f of findings) {
          const list = byFile.get(f.filePath) ?? [];
          list.push(f);
          byFile.set(f.filePath, list);
        }

        for (const [filePath, fileFindings] of byFile) {
          const uri = vscode.Uri.file(filePath);
          this.diagnostics.updateForFile(uri, fileFindings);
        }

        totalFindings = totalFindings.concat(findings);
        this.logFindings(findings, folder.uri.fsPath);
      }

      const total = totalFindings.length;
      const totalDiag = this.diagnostics.getTotalFindingCount();

      if (total === 0) {
        this.statusBar.setState('clean');
        vscode.window.showInformationMessage(
          '🛡 SecretShield: Workspace scan complete. No secrets detected.'
        );
      } else {
        this.statusBar.setState('findings', totalDiag);
        vscode.window.showWarningMessage(
          `🛡 SecretShield: Workspace scan found ${total} potential secret${total === 1 ? '' : 's'}. Check Problems panel.`
        );
      }
    } catch (err) {
      if ((err as Error).message === 'Scan cancelled') {
        this.outputChannel.appendLine('[SecretShield] Workspace scan cancelled.');
      } else {
        this.handleError(err as Error, 'workspace scan');
      }
    } finally {
      if (this.currentScanController === controller) {
        this.currentScanController = undefined;
      }
    }
  }

  /**
   * Clears all diagnostics and resets the status bar.
   */
  clearFindings(): void {
    this.diagnostics.clearAll();
    this.statusBar.setState('clean');
    this.outputChannel.appendLine('[SecretShield] All findings cleared.');
    vscode.window.showInformationMessage('🛡 SecretShield: All findings cleared.');
  }

  /**
   * Checks and displays Gitleaks status.
   */
  async checkGitleaks(): Promise<void> {
    this.gitleaksInfo = await this.resolveAndVerifyGitleaks();
    const info = this.gitleaksInfo;

    const installInstructions = info.found
      ? 'SecretShield is ready to scan.'
      : [
          'To install Gitleaks:',
          '  Windows: winget install gitleaks',
          '  macOS:   brew install gitleaks',
          '  Linux:   see https://github.com/gitleaks/gitleaks',
          '',
          'Or set the path in settings:',
          '  secretshield.gitleaksPath = "/path/to/gitleaks"',
        ].join('\n');

    const outputText = [
      '🛡 SecretShield — Gitleaks Status',
      '',
      info.found ? '✅ Gitleaks detected' : '❌ Gitleaks NOT FOUND',
      '',
      `Version:    ${info.version || 'N/A'}`,
      `Executable: ${info.executablePath || 'N/A'}`,
      `Status:     ${info.found ? 'READY' : 'NOT FOUND'}`,
      info.error ? `Error:      ${info.error}` : '',
      '',
      installInstructions,
    ]
      .filter((l) => l !== undefined)
      .join('\n');

    this.outputChannel.appendLine(outputText);
    this.outputChannel.show();

    if (info.found) {
      vscode.window.showInformationMessage(
        `🛡 SecretShield: Gitleaks ${info.version} found at ${info.executablePath}`
      );
      this.statusBar.setState('ready');
    } else {
      vscode.window.showErrorMessage(
        `🛡 SecretShield: Gitleaks not found. ${info.error || ''} — Run "SecretShield: Check Gitleaks" for instructions.`
      );
      this.statusBar.setState('no-gitleaks');
    }
  }

  // ---------------------------------------------------------------------------
  // Private — Core Scan Flow
  // ---------------------------------------------------------------------------

  private async scanDocument(
    document: vscode.TextDocument,
    trigger: 'realtime' | 'save' | 'manual'
  ): Promise<void> {
    if (!this.ensureGitleaks()) {
      return;
    }

    // Cancel any previously running scan
    this.cancelCurrentScan();

    const controller = new AbortController();
    this.currentScanController = controller;
    const scanVersion = document.version;
    this.lastScanVersion = scanVersion;

    const settings = getSettings();
    this.statusBar.setState('scanning');

    try {
      const findings = await scanFileContent({
        gitleaksPath: this.gitleaksInfo!.executablePath,
        content: document.getText(),
        originalFilePath: document.uri.fsPath,
        timeoutMs: settings.scanTimeoutMs,
        signal: controller.signal,
      });

      // Stale-result guard: discard if the document has changed since we started
      if (document.version !== scanVersion) {
        this.outputChannel.appendLine(
          `[SecretShield] Discarding stale results (doc v${scanVersion} → v${document.version})`
        );
        return;
      }

      // Fix file paths — temp file path → original file path
      const normalizedFindings = findings.map((f) => ({
        ...f,
        filePath: document.uri.fsPath,
      }));

      this.diagnostics.updateForFile(document.uri, normalizedFindings);

      const totalDiag = this.diagnostics.getTotalFindingCount();

      if (normalizedFindings.length === 0) {
        this.statusBar.setState('clean');
      } else {
        this.statusBar.setState('findings', totalDiag);
        this.logFindings(normalizedFindings, document.uri.fsPath);

        if (trigger === 'manual') {
          vscode.window.showWarningMessage(
            `🛡 SecretShield: ${normalizedFindings.length} potential secret${normalizedFindings.length === 1 ? '' : 's'} found. Check Problems panel.`
          );
        }
      }
    } catch (err) {
      const error = err as Error;
      if (error.message === 'Scan cancelled') {
        return; // Normal cancellation — no error display
      }
      this.handleError(error, `${trigger} scan`);
    } finally {
      if (this.currentScanController === controller) {
        this.currentScanController = undefined;
      }
    }
  }

  // ---------------------------------------------------------------------------
  // Private — Helpers
  // ---------------------------------------------------------------------------

  private cancelCurrentScan(): void {
    if (this.currentScanController) {
      this.currentScanController.abort();
      this.currentScanController = undefined;
    }
    if (this.debounceTimer) {
      clearTimeout(this.debounceTimer);
      this.debounceTimer = undefined;
    }
  }

  private ensureGitleaks(): boolean {
    if (!this.gitleaksInfo?.found) {
      vscode.window.showErrorMessage(
        '🛡 SecretShield: Gitleaks not found. Run "SecretShield: Check Gitleaks" for setup instructions.'
      );
      this.statusBar.setState('no-gitleaks');
      return false;
    }
    return true;
  }

  private async resolveAndVerifyGitleaks(): Promise<GitleaksVersionInfo> {
    const settings = getSettings();
    const execPath = resolveGitleaksPath(settings.gitleaksPath);
    return detectGitleaksVersion(execPath);
  }

  private handleError(err: Error, context: string): void {
    const msg = `[SecretShield] Error during ${context}: ${err.message}`;
    this.outputChannel.appendLine(msg);
    this.statusBar.setState('error');
    vscode.window.showErrorMessage(
      `🛡 SecretShield: ${err.message}. Check the SecretShield output channel for details.`
    );
  }

  private isScannableDocument(document: vscode.TextDocument): boolean {
    // Skip non-file URIs (e.g. output channels, git diff views)
    if (document.uri.scheme !== 'file') {
      return false;
    }
    return true;
  }

  private log(message: string): void {
    this.outputChannel.appendLine(message);
  }

  private logFindings(findings: SecretShieldFinding[], context: string): void {
    for (const f of findings) {
      // IMPORTANT: We log rule + location ONLY. Never the secret value itself.
      this.outputChannel.appendLine(
        `[SecretShield] Finding: ${f.ruleId} | ${path.relative(context, f.filePath) || f.filePath} | Line ${f.line} | Severity: ${f.severity}`
      );
    }
  }
}
