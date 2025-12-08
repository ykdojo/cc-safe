# cc-safe

Security scanner for Claude Code settings files. Recursively scans all subdirectories for dangerous patterns in your approved commands that could compromise your host machine. You can run it manually or ask Claude Code to run it with `npx cc-safe .`

## Motivation

A user [reported on Reddit](https://www.reddit.com/r/ClaudeAI/comments/1pgxckk/claude_cli_deleted_my_entire_home_directory_wiped/) that Claude Code ran `rm -rf tests/ patches/ plan/ ~/` - that trailing `~/` wiped their entire home directory.

It's easy to dismiss this as a "vibe coder" mistake, but when you're approving dozens of commands across multiple projects, mistakes happen. The permission prompt becomes muscle memory, and one bad approval can be catastrophic.

cc-safe automates what's hard to do manually: scan all your approved commands across all projects and flag the dangerous ones before they cause damage.

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
cc-safe .                  # Scan current directory and all subfolders
cc-safe ~/projects         # Scan a specific directory recursively
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
- `rm -rf` / `rm -f` - Force-deletes files
- `Bash` - Allows ANY bash command (without specifier)
- `chmod 777` - World-writable permissions
- `chmod -R` - Recursive permission changes
- `curl | sh` - Downloads and executes code
- `dd if=` - Raw disk operations
- `mkfs`, `fdisk` - Disk formatting
- `> /dev/sd*` - Direct device writes
- `git push --force` - Destroys remote history
- `--dangerously-skip-permissions` - Bypasses all safety checks

**MEDIUM** - Potentially dangerous:
- `sudo` - Runs commands as root
- `git reset --hard` - Discards uncommitted changes
- `git clean -fd` - Deletes untracked files
- `npm publish` / `yarn publish` - Publishes to npm registry
- `twine upload` - Publishes to PyPI (Python)
- `gem push` - Publishes to RubyGems
- `cargo publish` - Publishes to crates.io (Rust)
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
  [HIGH] Bash (allow all): "Bash"

/Users/you/projects/scripts/.claude/settings.local.json
  [MEDIUM] git reset --hard: "Bash(git reset --hard)"

Summary: 2 high, 1 medium risk pattern(s) found
```

## Requirements

- Node.js 22+

## License

See [LICENSE](LICENSE)
