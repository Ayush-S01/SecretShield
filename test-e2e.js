/**
 * SecretShield End-to-End Verification Script
 *
 * This script verifies the complete pipeline:
 *   FAKE TEST TOKEN → GITLEAKS → PARSER → SecretShieldFinding
 *
 * Run with:
 *   node out/test-e2e.js <path-to-gitleaks>
 *
 * Or with default gitleaks from PATH:
 *   node out/test-e2e.js
 */

const { scanFileContent, detectGitleaksVersion, resolveGitleaksPath } = require('./out/core/scanner/gitleaksRunner');
const fs = require('fs');
const path = require('path');
const os = require('os');

async function main() {
  const gitleaksPath = process.argv[2] || resolveGitleaksPath('');

  console.log('==============================================');
  console.log('SecretShield End-to-End Verification');
  console.log('==============================================\n');

  // Step 1: Check Gitleaks version
  console.log('Step 1: Detecting Gitleaks version...');
  const versionInfo = await detectGitleaksVersion(gitleaksPath);
  if (!versionInfo.found) {
    console.error(`❌ Gitleaks not found: ${versionInfo.error}`);
    console.error('   Install: winget install gitleaks (Windows) or brew install gitleaks (macOS)');
    process.exit(1);
  }
  console.log(`✅ Gitleaks detected`);
  console.log(`   Version:    ${versionInfo.version}`);
  console.log(`   Executable: ${versionInfo.executablePath}\n`);

  // Step 2: Create temp test file with fake secret
  const fakeToken = 'ghp_AAAAABBBBCCCCDDDDEEEEFFFFGGGGHHHH1234';
  const testContent = `// Test file for SecretShield verification
const FAKE_GITHUB_TOKEN = "${fakeToken}";
`;

  const tmpFile = path.join(os.tmpdir(), `secretshield-test-${Date.now()}.ts`);
  try {
    fs.writeFileSync(tmpFile, testContent, 'utf8');
    console.log('Step 2: Created test file with fake GitHub PAT token');
    console.log(`   Token pattern: ghp_AAAA...1234 (fake, non-functional)`);
    console.log(`   File: ${tmpFile}\n`);

    // Step 3: Run real Gitleaks
    console.log('Step 3: Running real Gitleaks against test content...');
    const findings = await scanFileContent({
      gitleaksPath: versionInfo.executablePath,
      content: testContent,
      originalFilePath: tmpFile,
      timeoutMs: 15000,
    });

    // Step 4: Check results
    if (findings.length === 0) {
      console.error('❌ No findings returned by Gitleaks.');
      console.error('   The fake token may not match Gitleaks rules in this version.');
      console.error('   Try: gitleaks detect --no-git --source ' + tmpFile + ' --report-format json');
      process.exit(1);
    }

    console.log(`✅ Gitleaks returned ${findings.length} finding(s)\n`);
    console.log('Step 4: SecretShield parsed the findings:\n');

    for (const finding of findings) {
      console.log('  ─────────────────────────────────────────');
      console.log(`  Rule:        ${finding.ruleId}`);
      console.log(`  Description: ${finding.description}`);
      console.log(`  Severity:    ${finding.severity}`);
      console.log(`  Source:      ${finding.source}`);
      console.log(`  Line:        ${finding.line}`);
      console.log(`  Columns:     ${finding.startColumn}–${finding.endColumn}`);
      console.log(`  Fingerprint: ${finding.fingerprint}`);
      console.log(`  Is Committed: ${finding.isCommitted}`);
      // NOTE: We do NOT print the secret value itself
      console.log('');
    }

    console.log('==============================================');
    console.log('✅ END-TO-END VERIFICATION PASSED');
    console.log('');
    console.log('The complete pipeline works:');
    console.log('  Fake token → Real Gitleaks → Real Finding → SecretShield Parser');
    console.log('');
    console.log('You can now:');
    console.log('  1. Open VS Code in this folder');
    console.log('  2. Press F5 to launch the Extension Development Host');
    console.log('  3. Open test-fixtures/demo-secret.ts');
    console.log('  4. Watch SecretShield highlight the fake token within ~750ms');
    console.log('==============================================');

  } finally {
    try { fs.unlinkSync(tmpFile); } catch {}
  }
}

main().catch((err) => {
  console.error('❌ Verification failed:', err.message);
  process.exit(1);
});
