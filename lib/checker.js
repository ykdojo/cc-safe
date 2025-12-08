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

// Safe read-only commands that are LOW risk even with sudo
const SAFE_SUDO_COMMANDS = [
  'apt-cache',   // read-only package queries
  'du',          // disk usage reporting
  'df',          // disk space
  'ls',          // listing files
  'cat',         // reading files (info disclosure only)
  'head',        // reading files
  'tail',        // reading files
  'less',        // reading files
  'more',        // reading files
  'ps',          // process listing
  'top',         // process monitoring
  'htop',        // process monitoring
  'lsof',        // open files
  'netstat',     // network info
  'ss',          // socket stats
  'ip',          // network config (read)
  'ifconfig',    // network config (read)
  'uname',       // system info
  'whoami',      // current user
  'id',          // user/group info
  'which',       // command location
  'whereis',     // command location
  'file',        // file type info
  'stat',        // file stats
  'find',        // file search (read-only)
  'locate',      // file search
  'grep',        // text search
  'awk',         // text processing
  'sed',         // text processing (can be dangerous but typically read)
  'wc',          // word count
  'diff',        // file comparison
  'md5sum',      // checksums
  'sha256sum',   // checksums
  'shasum',      // checksums
  'env',         // environment vars
  'printenv',    // environment vars
  'dmesg',       // kernel messages
  'journalctl',  // system logs
  'systemctl status', // service status (read-only)
  'free',        // memory info
  'vmstat',      // virtual memory stats
  'iostat',      // io stats
  'uptime',      // system uptime
  'hostname',    // hostname
  'date',        // date/time
  'cal',         // calendar
  'lsblk',       // block devices
  'blkid',       // block device attributes
  'fdisk -l',    // partition list (read-only)
  'parted -l',   // partition list (read-only)
  'mount',       // mount info (without args)
  'lscpu',       // cpu info
  'lsmem',       // memory info
  'lspci',       // pci devices
  'lsusb',       // usb devices
  'dmidecode',   // hardware info
];

// Dangerous patterns with severity
const DANGEROUS_PATTERNS = [
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
  {
    name: 'rm (broad)',
    pattern: /\brm(\s*\*|\s*$|\))/,
    severity: 'LOW',
    description: 'May allow deletion of any files'
  },
];

// Special handling for sudo - distinguish safe read-only commands from dangerous ones
function checkSudo(permission) {
  // Match sudo at command position: start of string, after Bash(, after shell operators,
  // or at start of quoted strings (for tmux send-keys etc.)
  const sudoPattern = /(?:^|Bash\(|[;&|]\s*|['"]\s*)sudo\s+(\S+)/;
  const match = permission.match(sudoPattern);

  if (!match) {
    return null;
  }

  const sudoCommand = match[1].toLowerCase();

  // Check if the command after sudo is in our safe list
  const isSafe = SAFE_SUDO_COMMANDS.some(safe => {
    // Handle multi-word safe commands like "systemctl status"
    if (safe.includes(' ')) {
      return permission.toLowerCase().includes(`sudo ${safe}`);
    }
    return sudoCommand === safe || sudoCommand.startsWith(safe + ':');
  });

  if (isSafe) {
    return {
      name: 'sudo (read-only)',
      severity: 'LOW',
      description: 'Runs read-only command as root (info disclosure only)',
      permission
    };
  }

  return {
    name: 'sudo',
    severity: 'MEDIUM',
    description: 'Runs commands as root/administrator',
    permission
  };
}

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

    // Check sudo separately (distinguishes safe vs dangerous commands)
    const sudoIssue = checkSudo(permission);
    if (sudoIssue) {
      issues.push(sudoIssue);
    }
  }

  return issues;
}
