# cc-safe Handoff Document

## Project Overview

**cc-safe** is a security linter for Claude Code settings files. It scans directories to find Claude Code configuration files and will flag dangerous patterns in approved commands.

**Repository:** https://github.com/ykdojo/cc-safe

## Current State

The file finder is complete. The tool can recursively find Claude Code settings files:
- `.claude/settings.json` (project settings, shared/committed)
- `.claude/settings.local.json` (project settings, personal/not committed)

### What's Implemented

1. **Hybrid file search:**
   - Mac/Linux: Uses native `find` command via `spawnSync` for speed
   - Windows: Falls back to Node.js glob

2. **Performance:**
   - ~8 seconds on a projects folder with 29 settings files
   - ~29 seconds on entire home directory (33 files)

3. **Usage:**
   ```bash
   node bin/cc-safe.js              # scan current directory
   node bin/cc-safe.js /some/path   # scan specific directory
   ```

## Project Structure

```
cc-safe/
├── bin/cc-safe.js   # CLI entry point (main logic)
├── package.json     # npm config, "type": "module"
├── LICENSE          # Proprietary (All Rights Reserved)
├── .gitignore       # node_modules, .DS_Store
└── HANDOFF.md       # This file
```

## Next Task: Dangerous Pattern Detection

Parse the found settings files and flag dangerous patterns in `permissions.allow` arrays.

### Settings File Format

```json
{
  "permissions": {
    "allow": [
      "Bash(rm -rf:*)",
      "Bash(git push --force:*)",
      "WebSearch"
    ],
    "deny": [],
    "ask": []
  }
}
```

### Dangerous Patterns to Flag

**High Risk:**
- `rm -rf`, `rm -f`, `rm --force`
- `git push --force`, `git push -f`
- `chmod 777`, `chmod -R`
- `sudo` anything
- `curl | sh`, `curl | bash`, `wget | sh` (pipe to shell)
- `dd if=`
- `mkfs`, `fdisk`
- `> /dev/sda` or similar device writes
- `:(){ :|:& };:` (fork bomb patterns)

**Medium Risk:**
- `git reset --hard`
- `git clean -fd`
- `npm publish`, `yarn publish`
- `docker run --privileged`
- `docker run -v /:/host`
- `eval`, `exec` in shell contexts

**Configuration Red Flags:**
- Overly permissive patterns like `Bash(*)`
- `--dangerously-skip-permissions` in any command

### Implementation Approach

1. Read each found settings file as JSON
2. Extract `permissions.allow` array
3. Check each entry against dangerous patterns (regex)
4. Output findings with severity levels (high/medium)
5. Return appropriate exit code (0 = clean, 1 = issues found)

### Example Output (suggested)

```
Scanning: /Users/yk/Desktop/projects

Found 2 issues in 1 file:

/Users/yk/Desktop/projects/foo/.claude/settings.local.json
  [HIGH] rm -rf: "Bash(rm -rf:*)"
  [MEDIUM] git reset --hard: "Bash(git reset --hard:*)"

Summary: 1 high, 1 medium risk pattern(s) found
```

## Technical Notes

- Package uses ES modules (`"type": "module"`)
- Node.js 25+ (uses built-in `node:fs/promises` glob)
- No external dependencies yet
- `find` command returns exit code 1 on permission errors but still outputs valid results - this is handled

## Commits So Far

1. `9916474` - Initial commit: settings file finder
2. `c10b531` - Use native find on Mac/Linux for faster file search
