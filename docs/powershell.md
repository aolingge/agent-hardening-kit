# PowerShell and Windows Usage

Agent Hardening Kit works on Windows PowerShell 5.1 and PowerShell 7+ because the CLI is just a Node.js entry point.

## Local Scans

Run the scanner against the current repository:

```powershell
npx github:aolingge/agent-hardening-kit --path .
```

Write Markdown for a pull request comment or audit note:

```powershell
npx github:aolingge/agent-hardening-kit --path . --markdown |
  Set-Content agent-hardening-report.md
```

Write SARIF for code-scanning upload:

```powershell
npx github:aolingge/agent-hardening-kit --path . --sarif |
  Set-Content agent-hardening.sarif
```

Write an HTML report you can open in the browser:

```powershell
npx github:aolingge/agent-hardening-kit --path . --html |
  Set-Content agent-hardening-report.html
```

Generate starter policy files without overwriting existing ones:

```powershell
npx github:aolingge/agent-hardening-kit --path . --write-policy
```

## Strict CI-Style Gate

Use `--min-score` when you want PowerShell to fail the step if the repository score is too low:

```powershell
npx github:aolingge/agent-hardening-kit --path . --json --min-score 80 |
  Set-Content agent-hardening-report.json
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
```

`$LASTEXITCODE` is the process exit code exposed by PowerShell. A non-zero value means the scan found enough problems to fail the gate.

## GitHub Actions on Windows

Use `shell: pwsh` when you want the same command style locally and in CI:

```yaml
name: Agent Hardening Windows
on:
  pull_request:

jobs:
  scan:
    runs-on: windows-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 20
      - name: Generate markdown report
        shell: pwsh
        run: |
          npx github:aolingge/agent-hardening-kit --path . --markdown |
            Set-Content agent-hardening-report.md
      - name: Fail if score is too low
        shell: pwsh
        run: |
          npx github:aolingge/agent-hardening-kit --path . --json --min-score 80 |
            Set-Content agent-hardening-report.json
          if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
```

## Tips

- Keep intentionally unsafe fixtures in `.agent-hardening-ignore` so Windows smoke tests do not fail on teaching samples.
- Prefer `Set-Content` in docs and scripts because it works consistently in Windows PowerShell and PowerShell 7.
- If your repository mixes Bash and PowerShell examples, label each block clearly so contributors know which shell to use.
