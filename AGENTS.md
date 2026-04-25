# Agent Instructions

This repository is a security-adjacent CLI. Keep changes small, testable, and easy to review.

## Boundaries

- Do not commit real secrets, tokens, cookies, private URLs, browser profiles, private logs, or credential material.
- Fixtures must use obviously fake placeholder values.
- Do not add network calls to the scanner runtime without a clear opt-in flag.
- Policy generation must not overwrite user files.

## Verification

- Run `npm test` after rule or output changes.
- Run `npm run check` before publishing.
- For SARIF changes, run `npm run smoke:sarif` and parse the generated file as JSON.

## Style

- Runtime code stays dependency-free.
- Error messages should explain the fix in beginner-friendly language.
- Public documentation is bilingual when the concept is user-facing.
