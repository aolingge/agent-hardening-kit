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
      - run: npx github:aolingge/agent-hardening-kit --path . --sarif > agent-hardening.sarif
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: agent-hardening.sarif
```

For strict gating, add `--min-score 80`.

If your contributors mainly use Windows, mirror the same workflow with `shell: pwsh` and `runs-on: windows-latest`:

```yaml
jobs:
  scan-windows:
    runs-on: windows-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 20
      - shell: pwsh
        run: |
          npx github:aolingge/agent-hardening-kit --path . --sarif |
            Set-Content agent-hardening.sarif
          if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
```

For more Windows-first examples, see [PowerShell and Windows Usage](powershell.md).
