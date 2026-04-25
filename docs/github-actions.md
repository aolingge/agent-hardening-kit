# GitHub Actions

Use SARIF output to surface findings in GitHub Code Scanning.

```yaml
name: Agent Hardening
on:
  pull_request:
  push:
    branches: [main]

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
      - run: npx agent-hardening-kit --path . --sarif > agent-hardening.sarif
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: agent-hardening.sarif
```

For strict gating, add `--min-score 80`.
