# Agent Hardening Kit

![Agent Hardening Kit banner](assets/readme-banner.svg)

One command to score whether a repository is ready for AI coding agents, MCP servers, prompt workflows, CI, and public release.

[中文](README.zh-CN.md) · [Checks](docs/checks.md) · [GitHub Actions](docs/github-actions.md) · [PowerShell](docs/powershell.md) · [Threat Model](docs/threat-model.md)

```bash
npx github:aolingge/agent-hardening-kit --path . --markdown
```

![CLI preview](assets/cli-preview.svg)

## Why This Exists

AI agents now read issues, edit code, call MCP tools, run shell commands, and publish releases. That creates a new repo-level checklist: prompts need untrusted-input boundaries, MCP configs need permission notes, secrets must not leak into examples, destructive commands need guards, and CI should produce evidence.

Agent Hardening Kit turns that checklist into a fast scanner that maintainers can run locally or in GitHub Actions.

## What It Checks

| Area | What it catches |
| --- | --- |
| AGENTS.md | Missing agent boundaries, secret rules, and verification commands |
| MCP | Local command launchers, inline secret-like values, missing permission notes |
| Prompts | Instruction override phrases and missing untrusted-input boundaries |
| Secrets | Token-like patterns and tracked `.env` files |
| Shell | Destructive commands and pipe-to-shell install patterns |
| Unicode | Invisible and bidirectional control characters |
| CI | Missing validation workflows and missing scanner/test commands |
| Release | Thin release proof, changelog, tags, or mirror notes |

## Quick Start

```bash
# Human-readable terminal report
npx github:aolingge/agent-hardening-kit --path .

# Markdown for pull requests
npx github:aolingge/agent-hardening-kit --path . --markdown > agent-hardening-report.md

# SARIF for GitHub Code Scanning
npx github:aolingge/agent-hardening-kit --path . --sarif > agent-hardening.sarif

# Self-contained HTML dashboard
npx github:aolingge/agent-hardening-kit --path . --html > agent-hardening-report.html

# Generate starter policy files and CI workflow
npx github:aolingge/agent-hardening-kit --path . --write-policy
```

Use `.agent-hardening-ignore` to exclude intentionally unsafe fixtures or generated reports from project-level scans.

Windows users can follow the PowerShell-specific commands in [docs/powershell.md](docs/powershell.md).

## CI Gate

```yaml
name: Agent Hardening
on: [pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 20
      - run: npx github:aolingge/agent-hardening-kit --path . --sarif > agent-hardening.sarif
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: agent-hardening.sarif
```

## Scoring

The scanner starts at 100 and subtracts weighted penalties for findings. It is intentionally practical: the goal is to make risky repos easier to fix, not to pretend static scanning can prove perfect security.

| Score | Meaning |
| --- | --- |
| 90-100 | Strong baseline |
| 80-89 | Good, with small fixes |
| 70-79 | Usable, needs hardening |
| 60-69 | Risky for agent workflows |
| 0-59 | Do not run autonomous agents here without review |

## Design Principles

- Zero runtime dependencies.
- Works on Windows, macOS, and Linux.
- Outputs JSON, Markdown, SARIF, HTML, and GitHub Actions annotations.
- Safe by default: policy generation does not overwrite existing files.
- Bilingual docs for English and Chinese open-source users.

## Roadmap

- More real-world MCP fixtures.
- GitLab CI and Gitee workflow examples.
- More Windows-first automation examples for PowerShell-heavy repositories.
- Rule suppression with justification comments.
- npm package publishing workflow.
- Community-maintained rule packs for specific agent tools.

## Contributing

New checks are welcome. Start with [CONTRIBUTING.md](CONTRIBUTING.md), add a fixture in `fixtures/`, then cover it with `node:test`.

## License

MIT
