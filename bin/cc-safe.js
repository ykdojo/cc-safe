#!/usr/bin/env node

import { spawnSync } from 'node:child_process';
import { glob, readFile } from 'node:fs/promises';
import { resolve, join } from 'node:path';
import { platform } from 'node:os';
import { checkPermission } from '../lib/checker.js';

const HELP_TEXT = `
cc-safe - Security scanner for Claude Code settings files

Scans directories for .claude/settings.json and .claude/settings.local.json
files, flagging dangerous patterns in approved commands that could compromise
your host machine.

USAGE
  cc-safe <directory> [options]

EXAMPLES
  cc-safe .                  Scan current directory and all subfolders
  cc-safe ~/projects         Scan a specific directory and all subfolders
  cc-safe . --no-low         Hide LOW severity findings

OPTIONS
  --no-low       Hide LOW severity findings (show only HIGH and MEDIUM)
  --help, -h     Show this help message

SEVERITY LEVELS
  HIGH    Critical security risks (rm -rf, chmod 777, Bash, etc.)
  MEDIUM  Potentially dangerous operations (sudo with system commands, git reset --hard)
  LOW     Worth noting but less risky (sudo with read-only commands, git push, broad rm)

TIP
  In Claude Code: "Use cc-safe to check my Claude Code settings for security issues"

MORE INFO
  https://github.com/ykdojo/cc-safe
`.trim();

function showHelp() {
  console.log(HELP_TEXT);
}

const IGNORE_DIRS = ['node_modules', '.git', 'dist', 'build', 'vendor'];

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
  const files = result.stdout.trim().split('\n').filter(Boolean);

  // On macOS, /System/Volumes/Data/Users is a firmlink to /Users - skip duplicates
  return files.filter(f => !f.startsWith('/System/Volumes/Data/'));
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
}

main().catch(console.error);
