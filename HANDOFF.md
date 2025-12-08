# cc-safe Handoff Document

## Project Overview

**cc-safe** is a security linter for Claude Code settings files. It scans directories to find Claude Code configuration files and flags dangerous patterns in approved commands.

**Repository:** https://github.com/ykdojo/cc-safe

## Current State

The tool is functional with pattern detection implemented.

### What's Implemented

1. **CLI with help command:**
   - `cc-safe` (no args) → shows help
   - `cc-safe --help` or `-h` → shows help
   - `cc-safe <directory>` → scans that directory
   - `cc-safe <directory> --no-low` → hides LOW severity findings

2. **Hybrid file search:**
   - Mac/Linux: Uses native `find` command via `spawnSync` for speed
   - Windows: Falls back to Node.js glob

3. **Pattern detection:**
   - Scans `.claude/settings.json` and `.claude/settings.local.json`
   - Detects dangerous patterns in `permissions.allow` arrays
   - Three severity levels: HIGH, MEDIUM, LOW
   - Container-aware (commands inside docker/podman are generally safe)

4. **Usage:**
   ```bash
   cc-safe .                  # scan current directory
   cc-safe ~/projects         # scan specific directory
   cc-safe . --no-low         # hide LOW severity findings
   cc-safe --help             # show help
   ```

## Project Structure

```
cc-safe/
├── bin/cc-safe.js           # CLI entry point (main logic)
├── test/check-permission.test.js  # Tests for pattern detection
├── package.json             # npm config, "type": "module"
├── LICENSE                  # Proprietary (All Rights Reserved)
├── .gitignore               # node_modules, .DS_Store
└── HANDOFF.md               # This file
```

## Technical Notes

- Package uses ES modules (`"type": "module"`)
- Node.js 22+ (uses built-in `node:fs/promises` glob)
- No external dependencies
- `find` command returns exit code 1 on permission errors but still outputs valid results - this is handled
- Commands inside containers (docker exec, podman exec, etc.) are generally safe and skipped
