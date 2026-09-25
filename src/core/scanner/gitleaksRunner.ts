/**
 * Gitleaks Runner
 *
 * Executes the real Gitleaks executable as a child process and returns
 * parsed SecretShieldFindings.
 *
 * Architecture:
 *   SecretShield → GitleaksRunner → child_process.spawn → gitleaks → JSON → Parser
 *
 * Rules:
 * - NEVER log actual secret values
 * - NEVER upload source code anywhere
 * - Use --no-git and temp files for in-memory editor content
 * - Support cancellation via AbortController
 */

import * as cp from 'child_process';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { parseGitleaksOutput } from './gitleaksParser';
import { SecretShieldFinding } from '../models/SecretShieldFinding';

export interface GitleaksVersionInfo {
  found: boolean;
  version: string;
  executablePath: string;
  error?: string;
}

export interface ScanOptions {
  /** Absolute path to the gitleaks binary. */
  gitleaksPath: string;
  /** Timeout in milliseconds. */
  timeoutMs: number;
  /** AbortSignal for cancellation. */
  signal?: AbortSignal;
}

export interface FileScanOptions extends ScanOptions {
  /** The full text content of the file (may be unsaved). */
  content: string;
  /** Original file path (used for error messages and path resolution only). */
  originalFilePath: string;
}

export interface WorkspaceScanOptions extends ScanOptions {
  /** Absolute path to the workspace/project root. */
  workspaceRoot: string;
  /** Patterns to exclude (passed as --ignore-path or inline). */
  excludePatterns: string[];
}

// ---------------------------------------------------------------------------
// Version Detection
// ---------------------------------------------------------------------------

/**
 * Detects the Gitleaks version by running `gitleaks version`.
 */
export async function detectGitleaksVersion(
  gitleaksPath: string
): Promise<GitleaksVersionInfo> {
  if (!gitleaksPath) {
    return { found: false, version: '', executablePath: '', error: 'No path provided' };
  }

  return new Promise((resolve) => {
    const proc = cp.spawn(gitleaksPath, ['version'], {
      timeout: 5000,
      windowsHide: true,
    });

    let stdout = '';
    let stderr = '';

    proc.stdout.on('data', (d: Buffer) => (stdout += d.toString()));
    proc.stderr.on('data', (d: Buffer) => (stderr += d.toString()));

    proc.on('error', (err) => {
      resolve({
        found: false,
        version: '',
        executablePath: gitleaksPath,
        error: err.message,
      });
    });

    proc.on('close', (code) => {
      const output = (stdout + stderr).trim();
      // Gitleaks version output: "v8.18.0" or "gitleaks version 8.18.0"
      const match = output.match(/v?\d+\.\d+\.\d+/);
      if (match) {
        resolve({
          found: true,
          version: match[0].startsWith('v') ? match[0] : `v${match[0]}`,
          executablePath: gitleaksPath,
        });
      } else if (code === 0) {
        resolve({
          found: true,
          version: output || 'unknown',
          executablePath: gitleaksPath,
        });
      } else {
        resolve({
          found: false,
          version: '',
          executablePath: gitleaksPath,
          error: output || `Process exited with code ${code}`,
        });
      }
    });
  });
}

// ---------------------------------------------------------------------------
// Resolve Gitleaks executable
// ---------------------------------------------------------------------------

/**
 * Resolves the gitleaks executable path.
 * Priority:
 *   1. Explicit user-configured path (if non-empty)
 *   2. "gitleaks" from PATH
 */
export function resolveGitleaksPath(configuredPath: string): string {
  if (configuredPath && configuredPath.trim().length > 0) {
    return configuredPath.trim();
  }
  // Fall back to PATH — let the OS locate it
  return process.platform === 'win32' ? 'gitleaks.exe' : 'gitleaks';
}

// ---------------------------------------------------------------------------
// File Scan (current document — may be unsaved)
// ---------------------------------------------------------------------------

export async function scanFileContent(
  opts: FileScanOptions
): Promise<SecretShieldFinding[]> {
  const tmpDir = os.tmpdir();
  const ext = path.extname(opts.originalFilePath) || '.tmp';
  const tmpFile = path.join(tmpDir, `secretshield-scan-${Date.now()}${ext}`);

  try {
    fs.writeFileSync(tmpFile, opts.content, 'utf8');
    return await runGitleaksDetect(tmpFile, opts, path.dirname(opts.originalFilePath));
  } finally {
    // Always clean up — never leave temp files behind
    try {
      if (fs.existsSync(tmpFile)) {
        fs.unlinkSync(tmpFile);
      }
    } catch {
      // Ignore cleanup errors
    }
  }
}

// ---------------------------------------------------------------------------
// Workspace Scan
// ---------------------------------------------------------------------------

/**
 * Scans the entire workspace using `gitleaks detect --no-git`.
 */
export async function scanWorkspace(
  opts: WorkspaceScanOptions
): Promise<SecretShieldFinding[]> {
  const args = buildDetectArgs(opts.workspaceRoot, opts.excludePatterns);

  return new Promise<SecretShieldFinding[]>((resolve, reject) => {
    const proc = cp.spawn(opts.gitleaksPath, args, {
      cwd: opts.workspaceRoot,
      windowsHide: true,
    });

    let stdout = '';
    let stderr = '';

    proc.stdout.on('data', (d: Buffer) => (stdout += d.toString()));
    proc.stderr.on('data', (d: Buffer) => (stderr += d.toString()));

    const timer = setTimeout(() => {
      proc.kill();
      reject(new Error(`Gitleaks timed out after ${opts.timeoutMs}ms`));
    }, opts.timeoutMs);

    if (opts.signal) {
      opts.signal.addEventListener('abort', () => {
        proc.kill();
        clearTimeout(timer);
        reject(new Error('Scan cancelled'));
      });
    }

    proc.on('error', (err) => {
      clearTimeout(timer);
      reject(new Error(`Failed to start Gitleaks: ${err.message}`));
    });

    proc.on('close', (code) => {
      clearTimeout(timer);
      // Gitleaks exits 1 when findings are present, 0 when clean
      // Exit code 2+ usually means error
      if (code !== null && code >= 2) {
        const errMsg = stderr.trim() || stdout.trim();
        reject(new Error(`Gitleaks exited with code ${code}: ${errMsg}`));
        return;
      }
      try {
        const findings = parseGitleaksOutput(stdout, opts.workspaceRoot);
        resolve(findings);
      } catch (parseErr) {
        reject(parseErr);
      }
    });
  });
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

async function runGitleaksDetect(
  targetFile: string,
  opts: ScanOptions,
  baseDir: string
): Promise<SecretShieldFinding[]> {
  // Gitleaks v8 flags (verified against v8.30.1):
  //   detect         = subcommand
  //   --no-git       = treat as plain directory, not Git repo
  //   -f json        = JSON output format
  //   -r -           = write report to stdout (dash = stdout)
  //   --no-banner    = suppress logo/banner from stderr
  //   --source       = path to scan
  // Exit code: 0 = no findings, 1 = findings found, >1 = error
  const args = [
    'detect',
    '--no-git',
    '-f', 'json',
    '-r', '-',
    '--no-banner',
    '--source', targetFile,
  ];

  return new Promise<SecretShieldFinding[]>((resolve, reject) => {
    const proc = cp.spawn(opts.gitleaksPath, args, {
      windowsHide: true,
    });

    let stdout = '';
    let stderr = '';

    proc.stdout.on('data', (d: Buffer) => (stdout += d.toString()));
    proc.stderr.on('data', (d: Buffer) => (stderr += d.toString()));

    const timer = setTimeout(() => {
      proc.kill();
      reject(new Error(`Gitleaks timed out after ${opts.timeoutMs}ms`));
    }, opts.timeoutMs);

    if (opts.signal) {
      opts.signal.addEventListener('abort', () => {
        proc.kill();
        clearTimeout(timer);
        reject(new Error('Scan cancelled'));
      });
    }

    proc.on('error', (err) => {
      clearTimeout(timer);
      reject(new Error(`Failed to start Gitleaks: ${err.message}`));
    });

    proc.on('close', (code) => {
      clearTimeout(timer);
      // Gitleaks exit codes:
      //   0 = no findings
      //   1 = findings found (normal, not an error)
      //   2+ = actual error
      if (code !== null && code >= 2) {
        const errMsg = stderr.trim() || stdout.trim();
        reject(new Error(`Gitleaks exited with code ${code}: ${errMsg}`));
        return;
      }

      const jsonOutput = stdout.trim();

      try {
        const findings = parseGitleaksOutput(jsonOutput, baseDir);
        resolve(findings);
      } catch (parseErr) {
        reject(parseErr);
      }
    });
  });
}

function buildDetectArgs(workspaceRoot: string, _excludePatterns: string[]): string[] {
  // Gitleaks v8 uses a .gitleaksignore file or --gitleaks-ignore-path for ignoring files.
  // Exclusions are handled via a .gitleaks.toml config file or .gitleaksignore.
  // The extension creates a .gitleaks.toml with path exclusions when needed.
  // For workspace scans, we use the standard detect flags.
  const args = [
    'detect',
    '--no-git',
    '-f', 'json',
    '-r', '-',
    '--no-banner',
    '--source', workspaceRoot,
  ];

  return args;
}

