# Threat Model

## Assets

- Source code
- Release credentials
- Package manager tokens
- Cloud keys
- Local files accessible through MCP tools
- Maintainer trust and public release reputation

## Entry Points

- Issues and pull requests
- Prompt files and eval fixtures
- MCP server configuration
- CI scripts
- Installation snippets
- Release automation
- Documentation copied by users

## Main Risks

- Prompt injection causes an agent to ignore repository rules.
- MCP tool permissions allow unexpected file, network, or shell access.
- Secrets are committed in examples or configuration.
- Hidden Unicode changes what an AI or reviewer sees.
- CI lacks evidence, so unsafe changes reach release.

## Expected Controls

- Clear AGENTS.md boundaries.
- MCP permission matrix.
- Prompt untrusted-input boundary.
- Secret examples that are clearly fake.
- Destructive command dry-run and confirmation.
- CI validation and SARIF reporting.
