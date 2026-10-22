# Release verification

- Run `npm run check` on supported Node versions.
- Confirm `plugin.json` and both example fixtures parse as JSON.
- Exercise valid and unsafe fixtures in CLI and browser.
- Confirm response CSP and no outbound browser request.
- Inspect `dist/SHA256SUMS.json` and release archive checksum.
- Scan tracked files for credentials and private/employer identifiers.
- Verify signed commit/tag, exact-commit CI, Pages deployment, live content, and GitHub release independently.
- Treat OpenAI directory submission, approval, and publication as separate states; this static utility is not submitted in v0.1.0.
