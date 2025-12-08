# cc-safe

Security linter for Claude Code settings files. Scans for dangerous patterns in your approved commands that could compromise your host machine. You can run it manually or ask Claude Code to run it with `npx cc-safe .`

## Installation

```bash
npm install -g cc-safe
```

## Usage

```bash
cc-safe <directory> [options]
```

### Examples

```bash
cc-safe .                  # Scan current directory
cc-safe ~/projects         # Scan a specific directory
cc-safe . --no-low         # Hide LOW severity findings
cc-safe --help             # Show help
```

### Options

| Option | Description |
|--------|-------------|
| `--no-low` | Hide LOW severity findings (show only HIGH and MEDIUM) |
| `--help`, `-h` | Show help message |

## What It Detects

cc-safe scans `.claude/settings.json` and `.claude/settings.local.json` files for risky patterns in the `permissions.allow` array.

### Severity Levels

**HIGH** - Critical security risks:
- `sudo` - Runs commands as root
- `rm -rf` / `rm -f` - Force-deletes files
- `Bash(*)` - Allows ANY bash command
- `chmod 777` - World-writable permissions
- `chmod -R` - Recursive permission changes
- `curl | sh` - Downloads and executes code
- `dd if=` - Raw disk operations
- `mkfs`, `fdisk` - Disk formatting
- `> /dev/sd*` - Direct device writes
- `git push --force` - Destroys remote history
- `--dangerously-skip-permissions` - Bypasses all safety checks

**MEDIUM** - Potentially dangerous:
- `git reset --hard` - Discards uncommitted changes
- `git clean -fd` - Deletes untracked files
- `npm publish` / `yarn publish` - Publishes to registry
- `docker run --privileged` - Full host access
- `docker run -v /:/` - Mounts entire host filesystem
- `eval` - Code injection risk
- `git push --force-with-lease` - Safer but still rewrites history

**LOW** - Worth noting:
- `git push` - Pushes to remote repository

### Container Awareness

Commands inside containers are generally safe and skipped:
- `docker exec ...`
- `podman exec ...`
- `kubectl exec ...`
- `docker run ...` (except `--privileged` and root mounts)

## Example Output

```
$ cc-safe ~/projects

Scanning for Claude Code settings files in: /Users/you/projects

Found 3 settings file(s), analyzing...

/Users/you/projects/webapp/.claude/settings.json
  [HIGH] sudo: "Bash(sudo *)"
  [HIGH] Bash(*): "Bash(*)"

/Users/you/projects/scripts/.claude/settings.local.json
  [MEDIUM] git reset --hard: "Bash(git reset --hard)"

Summary: 2 high, 1 medium risk pattern(s) found
```

## Requirements

- Node.js 22+

## License

See [LICENSE](LICENSE)
