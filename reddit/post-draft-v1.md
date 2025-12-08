# Reddit Post Draft - r/ClaudeAI

## Title
I built a security scanner for Claude Code after seeing that post about the deleted home directory

---

## Post Body

I saw [this post](https://www.reddit.com/r/ClaudeAI/comments/1pgxckk/claude_cli_deleted_my_entire_home_directory_wiped/) where someone's Claude Code ran `rm -rf tests/ patches/ plan/ ~/` and wiped their home directory.

It's easy to dismiss it as a vibe coder mistake, but I don't want to make the same kind of mistakes. So I built **cc-safe** - a CLI that scans your `.claude/settings.json` files for risky approved commands.

### What it detects

- `sudo`, `rm -rf`, `Bash`, `chmod 777`, `curl | sh`
- `git reset --hard`, `npm publish`, `docker run --privileged`
- And more - container-aware so `docker exec` commands are skipped

### Usage

You can run it manually or ask Claude Code to run it for you with `npx cc-safe .`

```bash
npm install -g cc-safe
cc-safe ~/projects
```

GitHub: [link]

What other patterns should be detected?
