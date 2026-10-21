# The skillguard skill

A skill that makes your agent run `skillguard` before it installs any other skill, plugin, hook, rules file or
MCP server, and report what it finds in plain language.

## Install

Copy the `skillguard` folder into your agent's skills directory:

| Agent | Folder |
|---|---|
| Claude Code (all projects) | `~/.claude/skills/skillguard` |
| Claude Code (one project) | `.claude/skills/skillguard` |
| Codex | `~/.codex/skills/skillguard` |
| Agents that read the shared folder | `~/.agents/skills/skillguard` |

The skill needs the `skillguard` binary on your `PATH`. If it's missing, the agent offers to install it and
waits for your answer.

## Use

Ask your agent to install something, for example "install the pdf skill from someone/skills". It scans the
source first, then installs, asks you, or refuses with the reasons, depending on what it finds. You can also
ask it directly: "is this plugin safe?", or "audit my installed skills".
