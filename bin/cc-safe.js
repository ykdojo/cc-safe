#!/usr/bin/env node

import { spawnSync } from 'node:child_process';
import { glob } from 'node:fs/promises';
import { resolve, join } from 'node:path';
import { platform } from 'node:os';

const IGNORE_DIRS = ['node_modules', '.git', 'dist', 'build', 'vendor'];

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
  } else {
    console.log(`Found ${files.length} settings file(s):\n`);
    for (const file of files) {
      console.log(`  ${file}`);
    }
  }
}

main().catch(console.error);
