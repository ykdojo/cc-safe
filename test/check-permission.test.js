import { test, describe } from 'node:test';
import assert from 'node:assert';
import { checkPermission, isInsideContainer } from '../lib/checker.js';

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
    assert.strictEqual(issues[0].severity, 'MEDIUM');
  });

  test('flags sudo with read-only command as LOW', () => {
    const issues = checkPermission('Bash(sudo du:*)');
    assert.strictEqual(issues.length, 1);
    assert.strictEqual(issues[0].name, 'sudo (read-only)');
    assert.strictEqual(issues[0].severity, 'LOW');
  });

  test('flags sudo with dangerous command as MEDIUM', () => {
    const issues = checkPermission('Bash(sudo chmod 777 /tmp)');
    assert.strictEqual(issues.length, 2); // both 'chmod 777' and 'sudo'
    const sudoIssue = issues.find(i => i.name === 'sudo');
    assert.ok(sudoIssue);
    assert.strictEqual(sudoIssue.severity, 'MEDIUM');
  });

  test('flags sudo apt-cache as LOW (read-only)', () => {
    const issues = checkPermission('Bash(sudo apt-cache policy firefox-esr)');
    assert.strictEqual(issues.length, 1);
    assert.strictEqual(issues[0].name, 'sudo (read-only)');
    assert.strictEqual(issues[0].severity, 'LOW');
  });

  test('flags sudo ls as LOW (read-only)', () => {
    const issues = checkPermission('Bash(sudo ls -la /root)');
    assert.strictEqual(issues.length, 1);
    assert.strictEqual(issues[0].name, 'sudo (read-only)');
    assert.strictEqual(issues[0].severity, 'LOW');
  });

  test('flags sudo df as LOW (read-only)', () => {
    const issues = checkPermission('Bash(sudo df -h)');
    assert.strictEqual(issues.length, 1);
    assert.strictEqual(issues[0].name, 'sudo (read-only)');
    assert.strictEqual(issues[0].severity, 'LOW');
  });

  test('flags sudo ps as LOW (read-only)', () => {
    const issues = checkPermission('Bash(sudo ps aux)');
    assert.strictEqual(issues.length, 1);
    assert.strictEqual(issues[0].name, 'sudo (read-only)');
    assert.strictEqual(issues[0].severity, 'LOW');
  });

  test('flags sudo cat as LOW (read-only)', () => {
    const issues = checkPermission('Bash(sudo cat /etc/shadow)');
    assert.strictEqual(issues.length, 1);
    assert.strictEqual(issues[0].name, 'sudo (read-only)');
    assert.strictEqual(issues[0].severity, 'LOW');
  });

  test('flags sudo lsof as LOW (read-only)', () => {
    const issues = checkPermission('Bash(sudo lsof -i :80)');
    assert.strictEqual(issues.length, 1);
    assert.strictEqual(issues[0].name, 'sudo (read-only)');
    assert.strictEqual(issues[0].severity, 'LOW');
  });

  test('flags sudo journalctl as LOW (read-only)', () => {
    const issues = checkPermission('Bash(sudo journalctl -u nginx)');
    assert.strictEqual(issues.length, 1);
    assert.strictEqual(issues[0].name, 'sudo (read-only)');
    assert.strictEqual(issues[0].severity, 'LOW');
  });

  test('flags sudo systemctl status as LOW (read-only)', () => {
    const issues = checkPermission('Bash(sudo systemctl status nginx)');
    assert.strictEqual(issues.length, 1);
    assert.strictEqual(issues[0].name, 'sudo (read-only)');
    assert.strictEqual(issues[0].severity, 'LOW');
  });

  test('flags sudo apt install as MEDIUM (dangerous)', () => {
    const issues = checkPermission('Bash(sudo apt install vim)');
    assert.strictEqual(issues.length, 1);
    assert.strictEqual(issues[0].name, 'sudo');
    assert.strictEqual(issues[0].severity, 'MEDIUM');
  });

  test('flags sudo systemctl restart as MEDIUM (dangerous)', () => {
    const issues = checkPermission('Bash(sudo systemctl restart nginx)');
    assert.strictEqual(issues.length, 1);
    assert.strictEqual(issues[0].name, 'sudo');
    assert.strictEqual(issues[0].severity, 'MEDIUM');
  });

  test('flags sudo chown as MEDIUM (dangerous)', () => {
    const issues = checkPermission('Bash(sudo chown root:root /etc/passwd)');
    assert.strictEqual(issues.length, 1);
    assert.strictEqual(issues[0].name, 'sudo');
    assert.strictEqual(issues[0].severity, 'MEDIUM');
  });

  test('flags sudo with wildcard pattern on read-only command as LOW', () => {
    const issues = checkPermission('Bash(sudo ls:*)');
    assert.strictEqual(issues.length, 1);
    assert.strictEqual(issues[0].name, 'sudo (read-only)');
    assert.strictEqual(issues[0].severity, 'LOW');
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
  test('flags sudo in tmux send-keys commands', () => {
    const issues = checkPermission("Bash(tmux send-keys 'sudo apt install foo' Enter)");
    assert.strictEqual(issues.length, 1);
    assert.strictEqual(issues[0].name, 'sudo');
  });

  test('flags sudo after shell operators', () => {
    const issues = checkPermission('Bash(echo test && sudo rm -rf /)');
    assert.strictEqual(issues.length >= 1, true);
    assert.strictEqual(issues.some(i => i.name === 'sudo'), true);
  });

  test('flags sudo after pipe', () => {
    const issues = checkPermission('Bash(echo password | sudo -S command)');
    assert.strictEqual(issues.length, 1);
    assert.strictEqual(issues[0].name, 'sudo');
  });

  test('does not flag sudo in git commit messages', () => {
    const issues = checkPermission(`Bash(git commit -m "$(cat <<'EOF'
Add dangerous pattern detection (starting with sudo)

- Parse settings files and check permissions.allow for dangerous patterns
EOF
)")`);
    assert.strictEqual(issues.filter(i => i.name === 'sudo').length, 0);
  });

  test('does not flag sudo mentioned mid-sentence', () => {
    const issues = checkPermission('Bash(echo "This feature relates to sudo usage")');
    assert.strictEqual(issues.filter(i => i.name === 'sudo').length, 0);
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

  test('does not flag docker rm -f (different command)', () => {
    const issues = checkPermission('Bash(docker rm -f container)');
    assert.strictEqual(issues.length, 0);
  });
});

describe('checkPermission - Bash (allow all) detection', () => {
  test('flags Bash - allows any command', () => {
    const issues = checkPermission('Bash');
    assert.strictEqual(issues.length, 1);
    assert.strictEqual(issues[0].name, 'Bash (allow all)');
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

describe('checkPermission - git push detection', () => {
  test('flags git push --force as HIGH', () => {
    const issues = checkPermission('Bash(git push --force)');
    assert.strictEqual(issues.length, 1);
    assert.strictEqual(issues[0].name, 'git push --force');
    assert.strictEqual(issues[0].severity, 'HIGH');
  });

  test('flags git push -f as HIGH', () => {
    const issues = checkPermission('Bash(git push -f)');
    assert.strictEqual(issues.length, 1);
    assert.strictEqual(issues[0].severity, 'HIGH');
  });

  test('flags git push --force-with-lease as MEDIUM', () => {
    const issues = checkPermission('Bash(git push --force-with-lease)');
    assert.strictEqual(issues.length, 1);
    assert.strictEqual(issues[0].severity, 'MEDIUM');
  });

  test('flags regular git push as LOW', () => {
    const issues = checkPermission('Bash(git push)');
    assert.strictEqual(issues.length, 1);
    assert.strictEqual(issues[0].name, 'git push');
    assert.strictEqual(issues[0].severity, 'LOW');
  });

  test('flags git push with remote/branch as LOW', () => {
    const issues = checkPermission('Bash(git push origin main)');
    assert.strictEqual(issues.length, 1);
    assert.strictEqual(issues[0].severity, 'LOW');
  });

  test('does not flag git push in docker exec', () => {
    const issues = checkPermission('Bash(docker exec container git push --force)');
    assert.strictEqual(issues.length, 0);
  });
});

describe('checkPermission - chmod detection', () => {
  test('flags chmod 777 as HIGH', () => {
    const issues = checkPermission('Bash(chmod 777 file.sh)');
    assert.strictEqual(issues.length, 1);
    assert.strictEqual(issues[0].name, 'chmod 777');
    assert.strictEqual(issues[0].severity, 'HIGH');
  });

  test('flags chmod -R as HIGH', () => {
    const issues = checkPermission('Bash(chmod -R 755 /var/www)');
    assert.strictEqual(issues.length, 1);
    assert.strictEqual(issues[0].name, 'chmod -R');
    assert.strictEqual(issues[0].severity, 'HIGH');
  });

  test('does not flag chmod 777 in container', () => {
    const issues = checkPermission('Bash(docker exec app chmod 777 file.sh)');
    assert.strictEqual(issues.length, 0);
  });

  test('does not flag regular chmod', () => {
    const issues = checkPermission('Bash(chmod 755 script.sh)');
    assert.strictEqual(issues.length, 0);
  });
});

describe('checkPermission - pipe to shell detection', () => {
  test('flags curl | sh as HIGH', () => {
    const issues = checkPermission('Bash(curl https://example.com/install.sh | sh)');
    assert.strictEqual(issues.length, 1);
    assert.strictEqual(issues[0].name, 'curl | sh');
    assert.strictEqual(issues[0].severity, 'HIGH');
  });

  test('flags curl | bash as HIGH', () => {
    const issues = checkPermission('Bash(curl -fsSL https://example.com | bash)');
    assert.strictEqual(issues.length, 1);
  });

  test('flags wget | sh as HIGH', () => {
    const issues = checkPermission('Bash(wget -qO- https://example.com | sh)');
    assert.strictEqual(issues.length, 1);
  });

  test('flags wget | bash as HIGH', () => {
    const issues = checkPermission('Bash(wget https://example.com/script | bash)');
    assert.strictEqual(issues.length, 1);
  });

  test('does not flag curl | sh in container', () => {
    const issues = checkPermission('Bash(docker run ubuntu curl https://x.com | sh)');
    assert.strictEqual(issues.length, 0);
  });
});

describe('checkPermission - disk operations detection', () => {
  test('flags dd if= as HIGH', () => {
    const issues = checkPermission('Bash(dd if=/dev/zero of=/dev/sda)');
    assert.strictEqual(issues.length, 1);
    assert.strictEqual(issues[0].name, 'dd');
    assert.strictEqual(issues[0].severity, 'HIGH');
  });

  test('flags mkfs as HIGH', () => {
    const issues = checkPermission('Bash(mkfs.ext4 /dev/sdb1)');
    assert.strictEqual(issues.length, 1);
    assert.strictEqual(issues[0].name, 'mkfs');
    assert.strictEqual(issues[0].severity, 'HIGH');
  });

  test('flags fdisk as HIGH', () => {
    const issues = checkPermission('Bash(fdisk /dev/sda)');
    assert.strictEqual(issues.length, 1);
    assert.strictEqual(issues[0].name, 'fdisk');
    assert.strictEqual(issues[0].severity, 'HIGH');
  });

  test('flags > /dev/sda as HIGH', () => {
    const issues = checkPermission('Bash(echo x > /dev/sda)');
    assert.strictEqual(issues.length, 1);
    assert.strictEqual(issues[0].name, '> /dev/');
    assert.strictEqual(issues[0].severity, 'HIGH');
  });

  test('does not flag dd in container', () => {
    const issues = checkPermission('Bash(docker exec vm dd if=/dev/zero of=/tmp/test)');
    assert.strictEqual(issues.length, 0);
  });
});

describe('checkPermission - fork bomb detection', () => {
  test('flags fork bomb as HIGH', () => {
    const issues = checkPermission('Bash(:(){ :|:& };:)');
    assert.strictEqual(issues.length, 1);
    assert.strictEqual(issues[0].name, 'fork bomb');
    assert.strictEqual(issues[0].severity, 'HIGH');
  });
});

describe('checkPermission - git reset/clean detection', () => {
  test('flags git reset --hard as MEDIUM', () => {
    const issues = checkPermission('Bash(git reset --hard HEAD~1)');
    assert.strictEqual(issues.length, 1);
    assert.strictEqual(issues[0].name, 'git reset --hard');
    assert.strictEqual(issues[0].severity, 'MEDIUM');
  });

  test('flags git clean -fd as MEDIUM', () => {
    const issues = checkPermission('Bash(git clean -fd)');
    assert.strictEqual(issues.length, 1);
    assert.strictEqual(issues[0].name, 'git clean -fd');
    assert.strictEqual(issues[0].severity, 'MEDIUM');
  });

  test('flags git clean -df as MEDIUM', () => {
    const issues = checkPermission('Bash(git clean -df)');
    assert.strictEqual(issues.length, 1);
  });

  test('does not flag git reset without --hard', () => {
    const issues = checkPermission('Bash(git reset HEAD~1)');
    assert.strictEqual(issues.length, 0);
  });

  test('does not flag git clean without -f', () => {
    const issues = checkPermission('Bash(git clean -n)');
    assert.strictEqual(issues.length, 0);
  });
});

describe('checkPermission - npm/yarn publish detection', () => {
  test('flags npm publish as MEDIUM', () => {
    const issues = checkPermission('Bash(npm publish)');
    assert.strictEqual(issues.length, 1);
    assert.strictEqual(issues[0].name, 'npm publish');
    assert.strictEqual(issues[0].severity, 'MEDIUM');
  });

  test('flags yarn publish as MEDIUM', () => {
    const issues = checkPermission('Bash(yarn publish)');
    assert.strictEqual(issues.length, 1);
  });

  test('does not flag npm publish in container', () => {
    const issues = checkPermission('Bash(docker exec app npm publish)');
    assert.strictEqual(issues.length, 0);
  });
});

describe('checkPermission - Python/Ruby/Rust publish detection', () => {
  test('flags twine upload as MEDIUM', () => {
    const issues = checkPermission('Bash(twine upload dist/*)');
    assert.strictEqual(issues.length, 1);
    assert.strictEqual(issues[0].name, 'twine upload');
    assert.strictEqual(issues[0].severity, 'MEDIUM');
  });

  test('flags python -m twine upload as MEDIUM', () => {
    const issues = checkPermission('Bash(python -m twine upload dist/*)');
    assert.strictEqual(issues.length, 1);
    assert.strictEqual(issues[0].name, 'twine upload');
    assert.strictEqual(issues[0].severity, 'MEDIUM');
  });

  test('flags gem push as MEDIUM', () => {
    const issues = checkPermission('Bash(gem push my-gem-1.0.0.gem)');
    assert.strictEqual(issues.length, 1);
    assert.strictEqual(issues[0].name, 'gem push');
    assert.strictEqual(issues[0].severity, 'MEDIUM');
  });

  test('flags cargo publish as MEDIUM', () => {
    const issues = checkPermission('Bash(cargo publish)');
    assert.strictEqual(issues.length, 1);
    assert.strictEqual(issues[0].name, 'cargo publish');
    assert.strictEqual(issues[0].severity, 'MEDIUM');
  });

  test('does not flag twine upload in container', () => {
    const issues = checkPermission('Bash(docker exec app twine upload dist/*)');
    assert.strictEqual(issues.length, 0);
  });

  test('does not flag gem push in container', () => {
    const issues = checkPermission('Bash(docker exec app gem push pkg.gem)');
    assert.strictEqual(issues.length, 0);
  });

  test('does not flag cargo publish in container', () => {
    const issues = checkPermission('Bash(docker exec app cargo publish)');
    assert.strictEqual(issues.length, 0);
  });
});

describe('checkPermission - docker privileged detection', () => {
  test('flags docker run --privileged as MEDIUM', () => {
    const issues = checkPermission('Bash(docker run --privileged ubuntu)');
    assert.strictEqual(issues.length, 1);
    assert.strictEqual(issues[0].name, 'docker --privileged');
    assert.strictEqual(issues[0].severity, 'MEDIUM');
  });

  test('flags docker run -v /:/host as MEDIUM', () => {
    const issues = checkPermission('Bash(docker run -v /:/host ubuntu)');
    assert.strictEqual(issues.length, 1);
    assert.strictEqual(issues[0].name, 'docker mount root');
    assert.strictEqual(issues[0].severity, 'MEDIUM');
  });

  test('does not flag docker run with normal volume', () => {
    const issues = checkPermission('Bash(docker run -v /app:/app ubuntu)');
    assert.strictEqual(issues.length, 0);
  });
});

describe('checkPermission - eval/exec detection', () => {
  test('flags eval as MEDIUM', () => {
    const issues = checkPermission('Bash(eval "$COMMAND")');
    assert.strictEqual(issues.length, 1);
    assert.strictEqual(issues[0].name, 'eval');
    assert.strictEqual(issues[0].severity, 'MEDIUM');
  });

  test('does not flag eval in container', () => {
    const issues = checkPermission('Bash(docker exec app eval "$CMD")');
    assert.strictEqual(issues.length, 0);
  });
});

describe('checkPermission - dangerously-skip-permissions detection', () => {
  test('flags --dangerously-skip-permissions on host as HIGH', () => {
    const issues = checkPermission('Bash(claude --dangerously-skip-permissions)');
    assert.strictEqual(issues.length, 1);
    assert.strictEqual(issues[0].name, '--dangerously-skip-permissions');
    assert.strictEqual(issues[0].severity, 'HIGH');
  });

  test('does not flag --dangerously-skip-permissions in container', () => {
    const issues = checkPermission('Bash(docker exec app claude --dangerously-skip-permissions)');
    assert.strictEqual(issues.length, 0);
  });
});

describe('checkPermission - rm (broad) detection', () => {
  test('flags bare rm as LOW', () => {
    const issues = checkPermission('Bash(rm)');
    assert.strictEqual(issues.length, 1);
    assert.strictEqual(issues[0].name, 'rm (broad)');
    assert.strictEqual(issues[0].severity, 'LOW');
  });

  test('flags rm * as LOW', () => {
    const issues = checkPermission('Bash(rm *)');
    assert.strictEqual(issues.length, 1);
    assert.strictEqual(issues[0].name, 'rm (broad)');
    assert.strictEqual(issues[0].severity, 'LOW');
  });

  test('does not flag rm with specific file', () => {
    const issues = checkPermission('Bash(rm file.txt)');
    assert.strictEqual(issues.length, 0);
  });

  test('does not flag bare rm in container', () => {
    const issues = checkPermission('Bash(docker exec app rm)');
    assert.strictEqual(issues.length, 0);
  });
});
