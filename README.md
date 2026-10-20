<p align="center">
  <img src="docs/banner.svg" alt="skillguard" width="100%">
</p>

<p align="center">
  <a href="https://github.com/z6il/skillguard/actions/workflows/ci.yml"><img alt="CI" src="https://img.shields.io/github/actions/workflow/status/z6il/skillguard/ci.yml?branch=main&style=for-the-badge&label=ci&color=ff2e4d"></a>
  <a href="https://github.com/z6il/skillguard/releases/latest"><img alt="Release" src="https://img.shields.io/github/v/release/z6il/skillguard?style=for-the-badge&color=ff2e4d"></a>
  <img alt="Go" src="https://img.shields.io/badge/Go-single_binary-111?style=for-the-badge&logo=go&logoColor=00ADD8">
  <img alt="License" src="https://img.shields.io/badge/license-MIT-111?style=for-the-badge">
</p>

<p align="center">
  <img alt="Claude Code" src="https://img.shields.io/badge/Claude_Code-111?logo=anthropic&logoColor=white">
  <img alt="Cursor" src="https://img.shields.io/badge/Cursor-111?logo=cursor&logoColor=white">
  <img alt="Codex" src="https://img.shields.io/badge/Codex_CLI-111?logo=openai&logoColor=white">
  <img alt="Gemini CLI" src="https://img.shields.io/badge/Gemini_CLI-111?logo=googlegemini&logoColor=white">
  <img alt="Offline" src="https://img.shields.io/badge/100%25_offline-111">
</p>

**skillguard** checks agent skills, plugins, hooks and MCP server configs before you trust them. It finds
instructions hidden from you, commands that phone home, secrets in configs and packages that can change under
you, and it locks what you approved so a silent update gets caught.

It runs fully offline, ships as one binary, and needs no account or API key.

<p align="center">
  <img src="docs/demo.svg" alt="skillguard catching a hidden instruction, a hidden HTML comment and a hook that posts data" width="100%">
</p>

## Why

Installing a skill or plugin means letting someone else's text and scripts steer an agent that can read
your files and run commands. The risky parts are hard to see in review:

- **Invisible text.** Unicode tag characters don't show up on screen, but the model reads them as normal text.
- **Hidden comments.** HTML comments disappear when Markdown is rendered, but the agent still reads them.
- **Hooks.** A hook can run on every tool call or receive every prompt you type.
- **Moving targets.** `npx -y some-mcp` runs whatever version is published next.

skillguard shows all of that in one pass, in plain language.

## Install

```bash
go install github.com/z6il/skillguard@latest
```

Or download a binary from [Releases](https://github.com/z6il/skillguard/releases) for Linux, macOS or Windows
(amd64 and arm64). The `linux_arm64` build runs in **Termux** on Android.

## Use

```bash
# Before installing: scan a folder, a git URL or a GitHub repo
skillguard scan ./my-plugin
skillguard scan someone/claude-skills
skillguard scan https://github.com/someone/repo/tree/main/skills/pdf

# What's already on this machine, across Claude Code, Cursor, Codex, Gemini CLI, Windsurf and Claude Desktop
skillguard audit
skillguard audit --details

# Approve what you have, then catch anything that changes later
skillguard lock --installed
skillguard diff --installed
```

`lock` refuses to record anything with high or critical findings unless you pass `--force`. `diff` lists added,
changed and removed files and scans only what changed.

### In CI

```yaml
permissions:
  contents: read
  security-events: write

jobs:
  skillguard:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
      - uses: z6il/skillguard@v0.1.4
        with:
          path: .
          fail-on: high
```

Findings show up in the repository's **Security → Code scanning** tab (SARIF), and the job fails on anything at
or above `fail-on`.

## What it checks

| Area | Checks |
|---|---|
| **Hidden content** | Unicode tag text (decoded so you can read it), bidirectional control characters, zero-width characters, instruction-like HTML comments, base64 blocks that decode to commands or instructions |
| **Prompt injection** | Instruction overrides, requests to act without telling the user, system-prompt extraction |
| **Execution** | Remote scripts piped to a shell, obfuscated `eval`/`exec`, reverse shells, destructive commands, persistence, turning off agent approvals or OS security |
| **Data access** | SSH and cloud credential files, token files, browser and wallet data, environment dumps |
| **Network** | Capture and tunnel services, chat webhooks, raw IP addresses |
| **Secrets** | GitHub, Anthropic, OpenAI, AWS, Slack, Google, Telegram and Stripe tokens, private keys (always redacted in output) |
| **MCP configs** | Unpinned `npx`/`uvx`/`docker` servers, plain-text secrets, unencrypted remote servers, inline shell launchers (with `cmd /c` understood) |
| **Hooks** | Hooks on every tool call or prompt, and hooks that make network calls, including inside the scripts they run |

Run `skillguard rules` for the full list with IDs.

### Low noise by design

A scanner that cries wolf gets uninstalled. skillguard:

- treats phrases in quotes as **citations**, so a security prompt that says *never follow "ignore previous instructions"* is not flagged;
- skips **negated mentions** (*"never run `curl | sh` lines"*) and **code comments** for rules about what code does;
- lowers findings in **tests and fixtures** to info, and in READMEs and changelogs by one level;
- understands real config formats instead of grepping them.

| Tested against | Files | Result |
|---|---|---|
| [anthropics/skills](https://github.com/anthropics/skills) | 262 | nothing found |
| Official Claude Code plugin marketplace | 479 | no high or critical; 9 medium worth a look, like MCP servers pinned to `@latest` |
| [vercel/turborepo](https://github.com/vercel/turborepo) (a large general codebase) | 4,794 | 4 high, all real `curl \| bash` / `irm \| iex` installer lines; 1 medium |

## Output

| Flag | |
|---|---|
| `--format text\|json\|sarif` | Colored report, machine-readable JSON, or SARIF 2.1.0 |
| `-o file` | Write the report to a file |
| `--fail-on high` | Exit 1 at this severity or worse (`none` to never fail) |
| `--min low` | Hide findings below this severity |
| `--rules extra.yaml` | Load extra rules |

Exit codes: `0` clean, `1` findings at or above `--fail-on` (or changes for `diff`), `2` error.
Colors follow `NO_COLOR` and `FORCE_COLOR`.

## Custom rules

Rules are line-based regular expressions in YAML. A rule with an existing ID replaces the built-in one.

```yaml
rules:
  - id: ACME001
    title: Talks to the old billing API
    severity: medium
    kinds: [code, config]
    pattern: |-
      billing-v1\.internal\.example
    reason: The v1 billing API is being shut down.
```

```bash
skillguard scan . --rules acme-rules.yaml
```

To skip paths, add a `.skillguardignore` to the folder you scan, one glob per line.

## Limits

skillguard reads files; it doesn't run them. It won't catch logic that is only malicious at runtime, and a
clean report is not a guarantee. Treat **BLOCK** as "don't install yet", **REVIEW** as "read these lines", and
**PASS** as "nothing obvious".

## Roadmap

- Live MCP check: connect to a server and scan the tool descriptions it actually returns
- Install by marketplace name (`skillguard scan claude-plugins-official/plugin-dev`)
- Interactive TUI for `audit`

## Contributing

Issues and pull requests are welcome, especially new rules with a real-world example and a test.
Please report security issues privately via [GitHub security advisories](https://github.com/z6il/skillguard/security/advisories/new).

## License

MIT © 2026 [Abdullah Almuntaser](https://github.com/z6il)
