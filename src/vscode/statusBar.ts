/**
 * Status Bar Manager
 *
 * Manages the SecretShield status bar item.
 *
 * States:
 *   Ready      → 🛡 SecretShield: Ready
 *   Scanning   → 🛡 SecretShield: Scanning...
 *   Clean      → 🛡 SecretShield: Clean
 *   Findings   → 🛡 SecretShield: 3 Findings
 *   Error      → 🛡 SecretShield: Error
 *   NoGitleaks → 🛡 SecretShield: Gitleaks not found
 */

import * as vscode from 'vscode';

type StatusBarState = 'ready' | 'scanning' | 'clean' | 'findings' | 'error' | 'no-gitleaks';

export class StatusBarManager {
  private readonly item: vscode.StatusBarItem;
  private currentState: StatusBarState = 'ready';
  private findingCount = 0;

  constructor() {
    this.item = vscode.window.createStatusBarItem(
      vscode.StatusBarAlignment.Left,
      100
    );
    this.item.command = 'workbench.actions.view.problems';
    this.item.tooltip = 'SecretShield — Click to open Problems panel';
    this.setState('ready');
    this.item.show();
  }

  setState(state: StatusBarState, count?: number): void {
    this.currentState = state;
    if (count !== undefined) {
      this.findingCount = count;
    }

    switch (state) {
      case 'ready':
        this.item.text = '🛡 SecretShield: Ready';
        this.item.backgroundColor = undefined;
        this.item.tooltip = 'SecretShield is active and monitoring your code';
        break;

      case 'scanning':
        this.item.text = '🛡 SecretShield: Scanning...';
        this.item.backgroundColor = undefined;
        this.item.tooltip = 'SecretShield is scanning the current file';
        break;

      case 'clean':
        this.item.text = '🛡 SecretShield: Clean';
        this.item.backgroundColor = undefined;
        this.item.tooltip = 'No secrets detected in the current file';
        break;

      case 'findings':
        const n = this.findingCount;
        this.item.text = `🛡 SecretShield: ${n} ${n === 1 ? 'Finding' : 'Findings'}`;
        this.item.backgroundColor = new vscode.ThemeColor(
          'statusBarItem.errorBackground'
        );
        this.item.tooltip = `SecretShield detected ${n} potential secret${n === 1 ? '' : 's'} — click to view`;
        break;

      case 'error':
        this.item.text = '🛡 SecretShield: Error';
        this.item.backgroundColor = new vscode.ThemeColor(
          'statusBarItem.warningBackground'
        );
        this.item.tooltip = 'SecretShield encountered an error — check the output panel';
        break;

      case 'no-gitleaks':
        this.item.text = '🛡 SecretShield: Gitleaks not found';
        this.item.backgroundColor = new vscode.ThemeColor(
          'statusBarItem.warningBackground'
        );
        this.item.tooltip =
          'Gitleaks is not installed or not on PATH. Run "SecretShield: Check Gitleaks" for details.';
        break;
    }
  }

  dispose(): void {
    this.item.dispose();
  }
}
