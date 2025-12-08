// Container/VM command prefixes - commands run inside these are safe
const CONTAINER_PREFIXES = [
  'docker exec',
  'podman exec',
  'nerdctl exec',
  'kubectl exec',
  'docker run',
  'podman run',
  'orb run',
  'orb -m',
];

// Check if command runs inside a container/VM
export function isInsideContainer(command) {
  const lowerCmd = command.toLowerCase();
  return CONTAINER_PREFIXES.some(prefix => lowerCmd.includes(prefix));
}

// Dangerous patterns with severity
const DANGEROUS_PATTERNS = [
  {
    name: 'sudo',
    pattern: /\bsudo\b/,
    severity: 'MEDIUM',
    description: 'Runs commands as root/administrator'
  },
  {
    name: 'rm -rf',
    pattern: /(?<!docker |podman )\brm\s+(-[a-zA-Z]*f|-f[a-zA-Z]*|--force)/,
    severity: 'HIGH',
    description: 'Force-deletes files without confirmation'
  },
  {
    name: 'Bash (allow all)',
    pattern: /^Bash$/,
    severity: 'HIGH',
    description: 'Allows ANY bash command without approval'
  },
  {
    name: 'chmod 777',
    pattern: /\bchmod\s+777\b/,
    severity: 'HIGH',
    description: 'Makes files readable/writable/executable by everyone'
  },
  {
    name: 'chmod -R',
    pattern: /\bchmod\s+-[a-zA-Z]*R/,
    severity: 'HIGH',
    description: 'Recursively changes permissions on entire directory trees'
  },
  {
    name: 'curl | sh',
    pattern: /\b(curl|wget)\b.*\|\s*(sh|bash)\b/,
    severity: 'HIGH',
    description: 'Downloads and executes code from the internet without review'
  },
  {
    name: 'dd',
    pattern: /\bdd\s+if=/,
    severity: 'HIGH',
    description: 'Low-level disk copy, can overwrite entire disks'
  },
  {
    name: 'mkfs',
    pattern: /\bmkfs\b/,
    severity: 'HIGH',
    description: 'Creates filesystems, destroys existing data'
  },
  {
    name: 'fdisk',
    pattern: /\bfdisk\b/,
    severity: 'HIGH',
    description: 'Modifies disk partition tables'
  },
  {
    name: '> /dev/',
    pattern: />\s*\/dev\/(sd|hd|nvme|vd)/,
    severity: 'HIGH',
    description: 'Writes directly to raw disk devices'
  },
  {
    name: 'fork bomb',
    pattern: /:\(\)\s*\{\s*:\|:&\s*\}\s*;:/,
    severity: 'HIGH',
    description: 'Spawns processes until system crashes'
  },
  {
    name: '--dangerously-skip-permissions',
    pattern: /--dangerously-skip-permissions/,
    severity: 'HIGH',
    description: 'Bypasses all Claude Code safety checks on host'
  },
  {
    name: 'git reset --hard',
    pattern: /\bgit\s+reset\s+--hard\b/,
    severity: 'MEDIUM',
    description: 'Discards all uncommitted changes permanently'
  },
  {
    name: 'git clean -fd',
    pattern: /\bgit\s+clean\s+-[a-zA-Z]*[fd][a-zA-Z]*[fd]/,
    severity: 'MEDIUM',
    description: 'Deletes all untracked files and directories'
  },
  {
    name: 'npm publish',
    pattern: /\b(npm|yarn)\s+publish\b/,
    severity: 'MEDIUM',
    description: 'Publishes package to public registry'
  },
  {
    name: 'twine upload',
    pattern: /\btwine\s+upload\b/,
    severity: 'MEDIUM',
    description: 'Publishes Python package to PyPI'
  },
  {
    name: 'gem push',
    pattern: /\bgem\s+push\b/,
    severity: 'MEDIUM',
    description: 'Publishes Ruby gem to RubyGems'
  },
  {
    name: 'cargo publish',
    pattern: /\bcargo\s+publish\b/,
    severity: 'MEDIUM',
    description: 'Publishes Rust crate to crates.io'
  },
  {
    name: 'docker --privileged',
    pattern: /\bdocker\s+run\b.*--privileged/,
    severity: 'MEDIUM',
    description: 'Container gets full access to host system',
    skipContainerCheck: true
  },
  {
    name: 'docker mount root',
    pattern: /\bdocker\s+run\b.*-v\s+\/:/,
    severity: 'MEDIUM',
    description: 'Mounts entire host filesystem into container',
    skipContainerCheck: true
  },
  {
    name: 'eval',
    pattern: /\beval\s+/,
    severity: 'MEDIUM',
    description: 'Executes strings as code, potential injection risk'
  },
];

// Special handling for git push - check most specific first
function checkGitPush(permission) {
  if (!/\bgit\s+push\b/.test(permission)) {
    return null;
  }

  // Check force flags (but not force-with-lease)
  if (/\bgit\s+push\b.*\s(-f|--force)(?!-with-lease)\b/.test(permission) ||
      /\bgit\s+push\s+(-f|--force)(?!-with-lease)\b/.test(permission)) {
    return {
      name: 'git push --force',
      severity: 'HIGH',
      description: 'Overwrites remote git history, can destroy work',
      permission
    };
  }

  // Check force-with-lease
  if (/\bgit\s+push\b.*--force-with-lease\b/.test(permission)) {
    return {
      name: 'git push --force-with-lease',
      severity: 'MEDIUM',
      description: 'Safer force push but still rewrites history',
      permission
    };
  }

  // Regular git push
  return {
    name: 'git push',
    severity: 'LOW',
    description: 'Pushes commits to remote repository',
    permission
  };
}

// Check a single permission entry for dangerous patterns
export function checkPermission(permission) {
  const issues = [];
  const inContainer = isInsideContainer(permission);

  for (const { name, pattern, severity, description, skipContainerCheck } of DANGEROUS_PATTERNS) {
    // Skip container commands unless this pattern should bypass that check
    if (inContainer && !skipContainerCheck) {
      continue;
    }
    if (pattern.test(permission)) {
      issues.push({ name, severity, description, permission });
    }
  }

  // Check git push separately (mutually exclusive patterns)
  if (!inContainer) {
    const gitPushIssue = checkGitPush(permission);
    if (gitPushIssue) {
      issues.push(gitPushIssue);
    }
  }

  return issues;
}
