/**
 * SecretShield Settings
 *
 * Typed accessor for VS Code configuration values.
 * All configuration reads go through this module.
 */

import * as vscode from 'vscode';

const SECTION = 'secretshield';

export interface SecretShieldSettings {
  gitleaksPath: string;
  enableRealtimeScan: boolean;
  scanOnSave: boolean;
  debounceMs: number;
  excludePatterns: string[];
  scanTimeoutMs: number;
}

export function getSettings(): SecretShieldSettings {
  const cfg = vscode.workspace.getConfiguration(SECTION);
  return {
    gitleaksPath: cfg.get<string>('gitleaksPath', ''),
    enableRealtimeScan: cfg.get<boolean>('enableRealtimeScan', true),
    scanOnSave: cfg.get<boolean>('scanOnSave', true),
    debounceMs: cfg.get<number>('debounceMs', 750),
    excludePatterns: cfg.get<string[]>('excludePatterns', [
      'node_modules',
      '.git',
      'dist',
      'build',
      'out',
      '*.lock',
      'package-lock.json',
      'yarn.lock',
    ]),
    scanTimeoutMs: cfg.get<number>('scanTimeoutMs', 30000),
  };
}
