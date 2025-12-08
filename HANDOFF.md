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

**Important:** Commands run inside containers (e.g., `docker exec`, `podman exec`) are generally safe and should NOT be flagged. The danger is when these commands run directly on the host machine.

**High Risk:**

| Pattern | Description |
|---------|-------------|
| `rm -rf`, `rm -f`, `rm --force` | Force-deletes files without confirmation. Can wipe entire directories or system files if misused. |
| `git push --force`, `git push -f` | Overwrites remote git history. Can destroy teammates' work and cause data loss in shared repos. |
| `chmod 777` | Makes files readable/writable/executable by everyone. Major security hole - any user or process can modify or execute the file. |
| `chmod -R` | Recursively changes permissions on entire directory trees. One mistake can expose thousands of files. |
| `sudo` | Runs commands as root/administrator. Gives full system access - a bad command can destroy the OS. |
| `curl \| sh`, `curl \| bash`, `wget \| sh` | Downloads and immediately executes code from the internet. You're running arbitrary code without reviewing it first - classic malware vector. |
| `dd if=` | Low-level disk copy tool. Can overwrite entire disks, bootloaders, or partitions. One wrong `of=` target and your disk is gone. |
| `mkfs` | Creates filesystems. Destroys all existing data on the target device. |
| `fdisk` | Modifies disk partition tables. Can make disks unbootable or destroy partition layouts. |
| `> /dev/sda` | Writes directly to raw disk devices. Bypasses filesystem, destroys everything on the disk. |
| `:(){ :\|:& };:` | Fork bomb. Spawns processes exponentially until system runs out of resources and crashes. |

**Medium Risk:**

| Pattern | Description |
|---------|-------------|
| `git reset --hard` | Discards all uncommitted changes permanently. No way to recover unsaved work. |
| `git clean -fd` | Deletes all untracked files and directories. Can remove files you meant to keep but forgot to commit. |
| `npm publish`, `yarn publish` | Publishes package to public registry. Accidental publish can leak private code or break downstream users. |
| `docker run --privileged` | Container gets full access to host system. Defeats the security isolation that containers provide. |
| `docker run -v /:/host` | Mounts entire host filesystem into container. Container can read/modify any file on host. |
| `eval`, `exec` | Executes strings as code. If the string comes from user input, it's a code injection vulnerability. |

**Configuration Red Flags:**

| Pattern | Description |
|---------|-------------|
| `Bash(*)` | Allows ANY bash command without approval. Defeats the entire permission system. |
| `--dangerously-skip-permissions` | Only flag if NOT inside a container command. Running Claude Code with skipped permissions on the host machine bypasses all safety checks. Inside containers (docker exec, etc.) this is acceptable since the container provides isolation. |

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
