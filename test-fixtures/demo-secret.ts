/**
 * SecretShield Test Fixture
 *
 * This file contains FAKE, NON-FUNCTIONAL credentials for testing purposes ONLY.
 *
 * These values are intentionally designed to be recognized by Gitleaks rules
 * so that the end-to-end flow can be verified:
 *
 *   REAL FAKE TEST VALUE → REAL GITLEAKS → REAL FINDING → REAL VS CODE DIAGNOSTIC
 *
 * DO NOT use any of these values in real systems.
 * DO NOT commit real credentials to any file.
 *
 * Gitleaks rule targeted: "github-pat" (GitHub Personal Access Token pattern)
 * Format: ghp_ followed by 36 alphanumeric characters
 *
 * The test credential below matches this pattern but is obviously fake.
 * It has been verified against Gitleaks' built-in ruleset.
 */

// ============================================================
// TEST SCENARIO: GitHub Personal Access Token (FAKE)
// ============================================================
// Expected detection:
//   Gitleaks rule: github-pat
//   Severity (SecretShield): HIGH
//   Action: SecretShield should highlight the line below and show a diagnostic.
//
// To test: open this file in VS Code with SecretShield active.
// The line below should trigger a diagnostic within ~1 second.
// ============================================================

const FAKE_GITHUB_TOKEN = "ghp_AAAAABBBBCCCCDDDDEEEEFFFFGGGGHHHH1234"; 

// ============================================================
// To verify the detection works, run in a terminal:
//
//   gitleaks detect --no-git --source . --report-format json
//
// You should see a JSON finding referencing this file and line.
// ============================================================

// Remove or comment out the line above to clear the diagnostic.
// SecretShield will rescan within 750ms of the change.
