#!/usr/bin/env node

import { spawnSync } from 'node:child_process';
import { glob, readFile } from 'node:fs/promises';
import { resolve, join } from 'node:path';
import { platform } from 'node:os';

const HELP_TEXT = `
cc-safe - Security linter for Claude Code settings files

Scans directories for .claude/settings.json and .claude/settings.local.json
files, flagging dangerous patterns in approved commands that could compromise
your host machine.

USAGE
  cc-safe <directory> [options]

EXAMPLES
  cc-safe .                  Scan current directory
  cc-safe ~/projects         Scan a specific directory
  cc-safe . --no-low         Hide LOW severity findings

OPTIONS
  --no-low       Hide LOW severity findings (show only HIGH and MEDIUM)
  --help, -h     Show this help message

SEVERITY LEVELS
  HIGH    Critical security risks (sudo, rm -rf, chmod 777, etc.)
  MEDIUM  Potentially dangerous operations (git reset --hard, npm publish)
  LOW     Worth noting but less risky (git push)

TIP
  In Claude Code: "Use cc-safe to check my Claude Code settings for security issues"

MORE INFO
  https://github.com/ykdojo/cc-safe
`.trim();

function showHelp() {
  console.log(HELP_TEXT);
}

const IGNORE_DIRS = ['node_modules', '.git', 'dist', 'build', 'vendor'];

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
    severity: 'HIGH',
    description: 'Runs commands as root/administrator'
  },
  {
    name: 'rm -rf',
    pattern: /(?<!docker |podman )\brm\s+(-[a-zA-Z]*f|-f[a-zA-Z]*|--force)/,
    severity: 'HIGH',
    description: 'Force-deletes files without confirmation'
  },
  {
    name: 'Bash(*)',
    pattern: /^Bash\(\*\)$/,
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

// Analyze a settings file for dangerous patterns
async function analyzeSettingsFile(filePath) {
  try {
    const content = await readFile(filePath, 'utf-8');
    const settings = JSON.parse(content);

    const allowList = settings?.permissions?.allow || [];
    const issues = [];

    for (const permission of allowList) {
      issues.push(...checkPermission(permission));
    }

    return issues;
  } catch (err) {
    // Skip files that can't be read or parsed
    return [];
  }
}

// Use native find on Mac/Linux for speed
function findSettingsFilesUnix(targetDir) {
  const args = [
    targetDir,
    '-type', 'f',
    '(', '-name', 'settings.json', '-o', '-name', 'settings.local.json', ')',
    '-path', '*/.claude/*'
  ];

  const result = spawnSync('find', args, {
    encoding: 'utf-8',
    maxBuffer: 10 * 1024 * 1024
  });

  if (result.error) {
    return [];
  }

  // find returns non-zero on permission errors, but still outputs valid results
  return result.stdout.trim().split('\n').filter(Boolean);
}

// Fallback to Node glob for Windows
async function findSettingsFilesWindows(targetDir) {
  const patterns = [
    '.claude/settings.json',
    '.claude/settings.local.json',
    '**/*/.claude/settings.json',
    '**/*/.claude/settings.local.json',
  ];

  const files = [];

  for (const pattern of patterns) {
    const matches = glob(pattern, {
      cwd: targetDir,
      exclude: (name) => IGNORE_DIRS.some(dir => name.includes(dir)),
    });

    for await (const file of matches) {
      files.push(join(targetDir, file));
    }
  }

  return files;
}

async function findSettingsFiles(targetDir) {
  const os = platform();

  if (os === 'darwin' || os === 'linux') {
    return findSettingsFilesUnix(targetDir);
  } else {
    return findSettingsFilesWindows(targetDir);
  }
}

async function main() {
  const args = process.argv.slice(2);

  // Show help if --help, -h, or no arguments
  if (args.includes('--help') || args.includes('-h')) {
    showHelp();
    return;
  }

  const noLow = args.includes('--no-low');
  const dirArg = args.find(a => !a.startsWith('--'));

  // No directory provided - show help
  if (!dirArg) {
    showHelp();
    return;
  }

  const targetDir = resolve(dirArg);

  console.log(`Scanning for Claude Code settings files in: ${targetDir}\n`);

  const files = await findSettingsFiles(targetDir);

  if (files.length === 0) {
    console.log('No Claude Code settings files found.');
    return;
  }

  console.log(`Found ${files.length} settings file(s), analyzing...\n`);

  const allFindings = [];

  for (const file of files) {
    let issues = await analyzeSettingsFile(file);
    if (noLow) {
      issues = issues.filter(i => i.severity !== 'LOW');
    }
    if (issues.length > 0) {
      allFindings.push({ file, issues });
    }
  }

  if (allFindings.length === 0) {
    console.log('No dangerous patterns found.');
    return;
  }

  // Report findings
  let totalHigh = 0;
  let totalMedium = 0;
  let totalLow = 0;

  for (const { file, issues } of allFindings) {
    console.log(file);
    for (const { name, severity, permission } of issues) {
      console.log(`  [${severity}] ${name}: "${permission}"`);
      if (severity === 'HIGH') totalHigh++;
      else if (severity === 'MEDIUM') totalMedium++;
      else if (severity === 'LOW') totalLow++;
    }
    console.log();
  }

  const parts = [];
  if (totalHigh > 0) parts.push(`${totalHigh} high`);
  if (totalMedium > 0) parts.push(`${totalMedium} medium`);
  if (totalLow > 0) parts.push(`${totalLow} low`);
  console.log(`Summary: ${parts.join(', ')} risk pattern(s) found`);
  process.exit(1);
}

// Only run main when executed directly (not imported for testing)
if (process.argv[1]?.endsWith('cc-safe.js')) {
  main().catch(console.error);
}
