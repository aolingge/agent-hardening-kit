# Checks

Agent Hardening Kit focuses on repository-level controls that make AI-assisted development safer and easier to review.

## Rule Domains

| Domain | Purpose |
| --- | --- |
| `agents` | Ensures humans and agents share the same operating contract. |
| `mcp` | Flags risky MCP launch patterns and missing permission documentation. |
| `prompts` | Finds prompt-injection language and missing untrusted-input boundaries. |
| `secrets` | Catches obvious credential mistakes before public release. |
| `shell` | Highlights destructive or supply-chain-sensitive command patterns. |
| `unicode` | Detects hidden characters that can smuggle instructions. |
| `ci` | Checks that pull requests have executable validation evidence. |
| `release` | Encourages changelogs, tags, and mirror proof. |

## Severity

- `error`: fix before running autonomous agents or publishing.
- `warning`: fix soon; risk depends on repository context.
- `notice`: improves maintainability and review quality.

## Practical Limitations

This is a static scanner. It cannot prove that prompts are robust, MCP tools are perfectly sandboxed, or secrets were never exposed. Use it as a fast baseline gate plus a review checklist.

## Ignore File

Create `.agent-hardening-ignore` at the repository root to skip intentionally unsafe fixtures or generated reports:

```text
fixtures/risky-repo/
agent-hardening-report.html
```
