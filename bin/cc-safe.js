#!/usr/bin/env node

import { glob } from 'node:fs/promises';
import { resolve, join } from 'node:path';

const SETTINGS_PATTERNS = [
  '.claude/settings.json',
  '.claude/settings.local.json',
  '**/*/.claude/settings.json',
  '**/*/.claude/settings.local.json',
];

const IGNORE_DIRS = ['node_modules', '.git', 'dist', 'build', 'vendor'];

async function findSettingsFiles(targetDir) {
  const files = [];

  for (const pattern of SETTINGS_PATTERNS) {
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
