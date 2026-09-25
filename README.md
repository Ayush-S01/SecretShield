# 🛡 SecretShield

**IDE-native secret leakage prevention engine powered by Gitleaks.**

SecretShield detects accidental credential exposure **while you write code** — before secrets ever reach Git or CI/CD.

---

## What It Does

```
Developer writes a secret
        ↓
SecretShield notices (750ms debounce)
        ↓
Gitleaks scans locally
        ↓
SecretShield explains the finding
        ↓
VS Code shows inline warning + Problems panel entry
        ↓
Developer fixes it
        ↓
Safe commit
```

**Everything runs locally. No source code is ever uploaded anywhere.**

---

## Requirements

### 1. Install Gitleaks

SecretShield requires the **real Gitleaks executable** to be installed locally.

#### Windows
```bash
winget install gitleaks
```

#### macOS
```bash
brew install gitleaks
```

#### Linux
```bash
# Download from https://github.com/gitleaks/gitleaks/releases
# Move to /usr/local/bin/gitleaks and chmod +x
```

#### Verify installation
```bash
gitleaks version
```

You should see output like `v8.18.0`.

### 2. Install VS Code Extension

#### Development Mode (from source)
```bash
# 1. Clone / open this project in VS Code
cd SecretShield

# 2. Install dependencies
npm install

# 3. Compile TypeScript
npm run compile

# 4. Press F5 in VS Code to launch the Extension Development Host
```

#### Packaged VSIX
```bash
npm run package
# Installs the generated .vsix:
code --install-extension secretshield-0.1.0.vsix
```

---

## Configuration

All settings are under `secretshield.*` in VS Code settings.

| Setting | Default | Description |
|---------|---------|-------------|
| `secretshield.gitleaksPath` | `""` | Absolute path to Gitleaks binary. Leave empty to use PATH. |
| `secretshield.enableRealtimeScan` | `true` | Scan as you type (debounced). |
| `secretshield.scanOnSave` | `true` | Scan when file is saved. |
| `secretshield.debounceMs` | `750` | Milliseconds to wait after typing stops before scanning. |
| `secretshield.excludePatterns` | `["node_modules", ".git", ...]` | Glob patterns excluded from workspace scans. |
| `secretshield.scanTimeoutMs` | `30000` | Maximum scan time in ms before timeout. |

### Configuring a custom Gitleaks path
If Gitleaks is not on your PATH, set the explicit path:
```json
{
  "secretshield.gitleaksPath": "C:\\tools\\gitleaks.exe"
}
```

---

## Commands

Open the Command Palette (`Ctrl+Shift+P`) and type `SecretShield`:

| Command | Description |
|---------|-------------|
| `SecretShield: Scan Current File` | Manually scan the active editor file. |
| `SecretShield: Scan Workspace` | Scan all files in the workspace. |
| `SecretShield: Clear Findings` | Remove all SecretShield diagnostics. |
| `SecretShield: Check Gitleaks` | Verify Gitleaks is installed and show version. |
| `SecretShield: Open Settings` | Open SecretShield settings. |

---

## Status Bar

The status bar shows the current SecretShield state:

| Status | Meaning |
|--------|---------|
| `🛡 SecretShield: Ready` | Active, monitoring code changes |
| `🛡 SecretShield: Scanning...` | Scan in progress |
| `🛡 SecretShield: Clean` | No secrets found in current file |
| `🛡 SecretShield: 2 Findings` | Secrets detected — click to open Problems |
| `🛡 SecretShield: Gitleaks not found` | Gitleaks not installed or misconfigured |

Click the status bar item to open the Problems panel.

---

## End-to-End Demo

### Step 1: Confirm Gitleaks is working
Run `SecretShield: Check Gitleaks` from the Command Palette.

You should see:
```
🛡 SecretShield — Gitleaks Status

✅ Gitleaks detected

Version:    v8.18.0
Executable: /usr/local/bin/gitleaks
Status:     READY
```

### Step 2: Trigger detection

Open `test-fixtures/demo-secret.ts`. It contains:
```typescript
const FAKE_GITHUB_TOKEN = "ghp_AAAAABBBBCCCCDDDDEEEEFFFFGGGGHHHH1234";
```

Within ~750ms, SecretShield will:
1. Invoke Gitleaks locally
2. Parse the JSON output
3. Create a VS Code diagnostic on that line

You will see:
- Red squiggly underline on the token value
- Problems panel entry: `[SecretShield] Potential secret detected — Rule: github-pat | Severity: HIGH`
- Hover tooltip with full details and remediation advice
- Status bar: `🛡 SecretShield: 1 Finding`

### Step 3: Fix and verify cleanup

Delete or comment out the `FAKE_GITHUB_TOKEN` line and save.
Within 750ms, SecretShield rescans and the diagnostic disappears.

### Step 4: Workspace scan

Run `SecretShield: Scan Workspace`.
SecretShield invokes Gitleaks against the entire project and reports all findings.

---

## Architecture

```
src/
├── core/                          # IDE-agnostic detection engine
│   ├── models/
│   │   └── SecretShieldFinding.ts # Normalized finding data model
│   ├── scanner/
│   │   ├── gitleaksRunner.ts      # Child process execution + temp-file strategy
│   │   └── gitleaksParser.ts      # Gitleaks JSON → SecretShieldFinding
│   └── analysis/
│       ├── severity.ts            # Rule ID → CRITICAL/HIGH/MEDIUM/LOW/INFO
│       └── remediation.ts        # Context-aware remediation text
│
├── vscode/                        # VS Code adapter layer
│   ├── extension.ts               # Activation entry point
│   ├── scanner.ts                 # Scan orchestrator (debounce, concurrency)
│   ├── diagnostics.ts             # DiagnosticsCollection manager
│   ├── statusBar.ts               # Status bar indicator
│   └── commands.ts                # Command Palette registrations
│
└── config/
    └── settings.ts                # Typed settings accessor
```

### Key Design Decisions

**Temp-file strategy for unsaved content:**
VS Code documents may contain unsaved changes. SecretShield writes the current document text to a temporary file in the OS temp directory (never inside the workspace), scans it with `gitleaks detect --no-git`, then immediately deletes it. This means unsaved secrets are caught before the developer even saves.

**Stale-result prevention:**
Each scan captures the document version at start. If the document version has changed by the time results arrive, the results are discarded and not displayed. This prevents flicker from racing scans.

**Concurrency control:**
Only one file scan runs at a time per document. A new scan cancels the previous one via `AbortController`. The debounce timer is also cancelled/reset on each keystroke.

**Secret value protection:**
SecretShield never logs the actual matched secret value. The output channel shows only: rule ID, file path, line number, and severity.

---

## Severity Mapping

SecretShield maps Gitleaks rule IDs to severity levels using a deterministic table:

| Severity | Examples |
|----------|---------|
| **CRITICAL** | `private-key`, `rsa-private-key`, `aws-secret-access-key`, `stripe-secret-key` |
| **HIGH** | Rules starting with `aws-`, `gcp-`, `github-`, `gitlab-`, `slack-`, `jwt-`, etc. |
| **MEDIUM** | Rules containing `key`, `token`, or `secret` |
| **LOW** | All other rules |

This mapping is transparent and documented. SecretShield does **not** claim AI-powered risk analysis.

---

## Gitleaks Integration

SecretShield uses these Gitleaks CLI commands:

**File scan (real-time):**
```bash
gitleaks detect --no-git --report-format json --report-path stdout --source /tmp/secretshield-scan-XYZ.ts --exit-code 0
```

**Workspace scan:**
```bash
gitleaks detect --no-git --report-format json --report-path stdout --source /path/to/workspace
```

**Version check:**
```bash
gitleaks version
```

JSON output is parsed directly. No wrapper scripts. No fake regex engines.

---

## Privacy & Security

- ✅ All scanning is **100% local**
- ✅ No source code is uploaded anywhere
- ✅ No telemetry or analytics
- ✅ No account required
- ✅ Works offline
- ✅ Secret values are never logged

---

## Troubleshooting

### "Gitleaks not found"
1. Verify: `gitleaks version` in your terminal
2. If not found: install via `winget install gitleaks` (Windows) or `brew install gitleaks` (macOS)
3. Or set `secretshield.gitleaksPath` to the full path of the executable

### Diagnostics not appearing
1. Check the **SecretShield** output channel (`View → Output → SecretShield`)
2. Run `SecretShield: Check Gitleaks` to verify Gitleaks is working
3. Try `SecretShield: Scan Current File` manually

### Extension not activating
1. Ensure the extension is compiled: `npm run compile`
2. Reload the Extension Development Host: `Ctrl+Shift+P → Developer: Reload Window`

---

## License

MIT
