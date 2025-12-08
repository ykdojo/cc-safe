import { test, describe } from 'node:test';
import assert from 'node:assert';
import { checkPermission, isInsideContainer } from '../bin/cc-safe.js';

describe('isInsideContainer', () => {
  test('detects docker exec', () => {
    assert.strictEqual(isInsideContainer('docker exec my-container sudo apt update'), true);
  });

  test('detects docker run', () => {
    assert.strictEqual(isInsideContainer('docker run ubuntu sudo apt install vim'), true);
  });

  test('detects podman exec', () => {
    assert.strictEqual(isInsideContainer('podman exec container sudo rm -rf /tmp'), true);
  });

  test('detects kubectl exec', () => {
    assert.strictEqual(isInsideContainer('kubectl exec pod-name -- sudo cat /etc/passwd'), true);
  });

  test('detects orb -m (Orbstack VM)', () => {
    assert.strictEqual(isInsideContainer('orb -m browser-vm sudo apt update'), true);
  });

  test('detects orb run (Orbstack VM)', () => {
    assert.strictEqual(isInsideContainer('orb run my-vm -- sudo systemctl restart nginx'), true);
  });

  test('returns false for host commands', () => {
    assert.strictEqual(isInsideContainer('sudo apt update'), false);
  });

  test('returns false for commands without container prefix', () => {
    assert.strictEqual(isInsideContainer('Bash(sudo rm -rf /tmp)'), false);
  });
});

describe('checkPermission - sudo detection', () => {
  test('flags sudo on host', () => {
    const issues = checkPermission('Bash(sudo apt update)');
    assert.strictEqual(issues.length, 1);
    assert.strictEqual(issues[0].name, 'sudo');
    assert.strictEqual(issues[0].severity, 'HIGH');
  });

  test('flags sudo with wildcard', () => {
    const issues = checkPermission('Bash(sudo du:*)');
    assert.strictEqual(issues.length, 1);
    assert.strictEqual(issues[0].name, 'sudo');
  });

  test('does not flag sudo in docker exec', () => {
    const issues = checkPermission('Bash(docker exec my-container sudo apt update)');
    assert.strictEqual(issues.length, 0);
  });

  test('does not flag sudo in orb VM', () => {
    const issues = checkPermission('Bash(orb -m browser-vm sudo apt install firefox)');
    assert.strictEqual(issues.length, 0);
  });

  test('does not flag commands without sudo', () => {
    const issues = checkPermission('Bash(npm install)');
    assert.strictEqual(issues.length, 0);
  });

  test('does not flag non-Bash permissions', () => {
    const issues = checkPermission('WebSearch');
    assert.strictEqual(issues.length, 0);
  });

  // Edge cases
  test('flags sudo even in complex tmux commands', () => {
    const issues = checkPermission("Bash('some command with sudo node patch-cli.js' Enter)");
    assert.strictEqual(issues.length, 1);
  });

  test('does not flag "sudo" as part of another word', () => {
    const issues = checkPermission('Bash(pseudocode generator)');
    assert.strictEqual(issues.length, 0);
  });
});

describe('checkPermission - rm -rf detection', () => {
  test('flags rm -rf on host', () => {
    const issues = checkPermission('Bash(rm -rf /tmp/foo)');
    assert.strictEqual(issues.length, 1);
    assert.strictEqual(issues[0].name, 'rm -rf');
    assert.strictEqual(issues[0].severity, 'HIGH');
  });

  test('flags rm -rf with wildcard', () => {
    const issues = checkPermission('Bash(rm -rf:*)');
    assert.strictEqual(issues.length, 1);
  });

  test('flags rm -f (force without recursive)', () => {
    const issues = checkPermission('Bash(rm -f file.txt)');
    assert.strictEqual(issues.length, 1);
  });

  test('flags rm --force', () => {
    const issues = checkPermission('Bash(rm --force file.txt)');
    assert.strictEqual(issues.length, 1);
  });

  test('does not flag rm -rf in docker exec', () => {
    const issues = checkPermission('Bash(docker exec container rm -rf /tmp)');
    assert.strictEqual(issues.length, 0);
  });

  test('does not flag regular rm without force flags', () => {
    const issues = checkPermission('Bash(rm file.txt)');
    assert.strictEqual(issues.length, 0);
  });
});

describe('checkPermission - Bash(*) wildcard detection', () => {
  test('flags Bash(*) - allows any command', () => {
    const issues = checkPermission('Bash(*)');
    assert.strictEqual(issues.length, 1);
    assert.strictEqual(issues[0].name, 'Bash(*)');
    assert.strictEqual(issues[0].severity, 'HIGH');
  });

  test('does not flag Bash with specific command', () => {
    const issues = checkPermission('Bash(npm install)');
    assert.strictEqual(issues.length, 0);
  });

  test('does not flag Bash with wildcard in argument', () => {
    const issues = checkPermission('Bash(ls *.js)');
    assert.strictEqual(issues.length, 0);
  });
});
