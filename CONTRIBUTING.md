# Contributing

Thanks for improving Agent Hardening Kit.

## Add A Rule

1. Add or update a rule in `src/cli.js`.
2. Add a safe fixture under `fixtures/`.
3. Add a test in `tests/cli.test.js`.
4. Run `npm test` and `npm run check`.

## Rule Quality Bar

- The rule should catch a real repository risk.
- The fix text should be specific enough for a beginner to act on.
- Fixtures must not contain real secrets, cookies, tokens, private URLs, or private logs.

## Commit Style

Use short imperative commits, for example:

```text
add mcp permission matrix check
```
