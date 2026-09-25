/**
 * VS Code Commands
 *
 * Registers all SecretShield Command Palette commands.
 * Each command delegates to the scanner or settings.
 * Every command actually works — no stubs.
 */

import * as vscode from 'vscode';
import { SecretShieldScanner } from './scanner';

export function registerCommands(
  context: vscode.ExtensionContext,
  scanner: SecretShieldScanner
): void {
  context.subscriptions.push(
    vscode.commands.registerCommand(
      'secretshield.scanCurrentFile',
      async () => {
        await scanner.scanCurrentFile();
      }
    ),

    vscode.commands.registerCommand(
      'secretshield.scanWorkspace',
      async () => {
        await scanner.scanWorkspaceFolders();
      }
    ),

    vscode.commands.registerCommand(
      'secretshield.clearFindings',
      () => {
        scanner.clearFindings();
      }
    ),

    vscode.commands.registerCommand(
      'secretshield.checkGitleaks',
      async () => {
        await scanner.checkGitleaks();
      }
    ),

    vscode.commands.registerCommand(
      'secretshield.openSettings',
      () => {
        vscode.commands.executeCommand(
          'workbench.action.openSettings',
          'secretshield'
        );
      }
    )
  );
}
