#!/usr/bin/env node

import { spawnSync } from 'node:child_process';
import { glob, readFile } from 'node:fs/promises';
import { resolve, join } from 'node:path';
import { platform } from 'node:os';

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
    pattern: /\brm\s+(-[a-zA-Z]*f|-f[a-zA-Z]*|--force)/,
    severity: 'HIGH',
    description: 'Force-deletes files without confirmation'
  },
  {
    name: 'Bash(*)',
    pattern: /^Bash\(\*\)$/,
    severity: 'HIGH',
    description: 'Allows ANY bash command without approval'
  }
];

// Check a single permission entry for dangerous patterns
export function checkPermission(permission) {
  const issues = [];

  // Skip if running inside a container
  if (isInsideContainer(permission)) {
    return issues;
  }

  for (const { name, pattern, severity, description } of DANGEROUS_PATTERNS) {
    if (pattern.test(permission)) {
      issues.push({ name, severity, description, permission });
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
  const targetDir = resolve(process.argv[2] || '.');

  console.log(`Scanning for Claude Code settings files in: ${targetDir}\n`);

  const files = await findSettingsFiles(targetDir);

  if (files.length === 0) {
    console.log('No Claude Code settings files found.');
    return;
  }

  console.log(`Found ${files.length} settings file(s), analyzing...\n`);

  const allFindings = [];

  for (const file of files) {
    const issues = await analyzeSettingsFile(file);
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

  for (const { file, issues } of allFindings) {
    console.log(file);
    for (const { name, severity, permission } of issues) {
      console.log(`  [${severity}] ${name}: "${permission}"`);
      if (severity === 'HIGH') totalHigh++;
      else if (severity === 'MEDIUM') totalMedium++;
    }
    console.log();
  }

  console.log(`Summary: ${totalHigh} high, ${totalMedium} medium risk pattern(s) found`);
  process.exit(1);
}

// Only run main when executed directly (not imported for testing)
if (process.argv[1]?.endsWith('cc-safe.js')) {
  main().catch(console.error);
}
