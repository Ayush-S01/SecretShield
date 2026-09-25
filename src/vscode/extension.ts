/**
 * SecretShield VS Code Extension Entry Point
 *
 * Activation sequence:
 *  1. Create output channel
 *  2. Initialize diagnostics collection
 *  3. Initialize status bar
 *  4. Initialize scanner (finds Gitleaks)
 *  5. Register commands
 *  6. Register document change listeners
 *  7. Register save listeners
 *  8. Register configuration change listener
 */

import * as vscode from 'vscode';
import { DiagnosticsManager } from './diagnostics';
import { StatusBarManager } from './statusBar';
import { SecretShieldScanner } from './scanner';
import { registerCommands } from './commands';

export async function activate(context: vscode.ExtensionContext): Promise<void> {
  // 1. Output channel (visible in View → Output → SecretShield)
  const outputChannel = vscode.window.createOutputChannel('SecretShield');
  context.subscriptions.push(outputChannel);
  outputChannel.appendLine('[SecretShield] Extension activating...');

  // 2. Diagnostics collection
  const diagnosticsManager = new DiagnosticsManager();
  context.subscriptions.push({ dispose: () => diagnosticsManager.dispose() });

  // 3. Status bar
  const statusBarManager = new StatusBarManager();
  context.subscriptions.push({ dispose: () => statusBarManager.dispose() });

  // 4. Scanner orchestrator
  const scanner = new SecretShieldScanner(
    diagnosticsManager,
    statusBarManager,
    outputChannel
  );
  await scanner.initialize();

  // 5. Register commands
  registerCommands(context, scanner);

  // 6. Document change listener (real-time debounced scanning)
  context.subscriptions.push(
    vscode.workspace.onDidChangeTextDocument((event) => {
      // Only react if the content actually changed (not just cursor/selection)
      if (event.contentChanges.length > 0) {
        scanner.onDocumentChanged(event.document);
      }
    })
  );

  // 6b. Scan when a document is opened (so squiggles appear without needing to type)
  context.subscriptions.push(
    vscode.workspace.onDidOpenTextDocument((document) => {
      scanner.onDocumentChanged(document);
    })
  );

  // 6c. Scan the currently active editor on startup (if a file is already open)
  if (vscode.window.activeTextEditor) {
    scanner.onDocumentChanged(vscode.window.activeTextEditor.document);
  }

  // 6d. Scan when the active editor changes (switching tabs)
  context.subscriptions.push(
    vscode.window.onDidChangeActiveTextEditor((editor) => {
      if (editor) {
        scanner.onDocumentChanged(editor.document);
      }
    })
  );

  // 7. Document save listener
  context.subscriptions.push(
    vscode.workspace.onDidSaveTextDocument(async (document) => {
      await scanner.onDocumentSaved(document);
    })
  );

  // 8. Configuration change — reinitialize when settings change
  context.subscriptions.push(
    vscode.workspace.onDidChangeConfiguration(async (event) => {
      if (event.affectsConfiguration('secretshield')) {
        outputChannel.appendLine('[SecretShield] Configuration changed, reinitializing...');
        await scanner.initialize();
      }
    })
  );

  outputChannel.appendLine('[SecretShield] Extension activated. Ready to protect your code.');
}

export function deactivate(): void {
  // VS Code disposes subscriptions automatically.
  // Nothing additional needed here.
}
