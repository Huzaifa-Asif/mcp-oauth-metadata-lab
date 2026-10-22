# MCP OAuth Metadata Lab

An offline, zero-dependency browser and CLI preflight for saved MCP OAuth discovery metadata. It cross-checks protected-resource and authorization-server documents, PKCE, registration strategy, scopes, URL hygiene, challenges, and accidental secret-bearing input without contacting any endpoint.

## Why

OAuth discovery failures are often found only after a client starts a login. A wrong resource identifier, issuer drift, missing `S256`, or incomplete DCR metadata can make a correct-looking integration fail late. This tool makes those cross-document assumptions visible earlier.

## Run

Requires Node.js 20+.

```sh
npm test
npm run check
npm start
node cli.mjs examples/valid.json --markdown
```

Open `http://127.0.0.1:4173`. The browser app and CLI perform no network requests. CI may publish the static UI to GitHub Pages.

## Fixture

See [`examples/valid.json`](examples/valid.json). Provide an MCP URL, saved protected-resource metadata, saved authorization-server metadata, a `clientRegistration` strategy (`cimd`, `dcr`, or `predefined`), and optionally a captured `WWW-Authenticate` challenge. Never paste tokens, secrets, or private keys.

The portable Agent Plugin manifest is at `plugin.json`; its local workflow lives at `skills/audit-mcp-oauth-metadata/SKILL.md`. This package does not expose an MCP server and is not itself an OpenAI directory submission.

## What it checks

- HTTPS, userinfo, fragments, private hosts, and exact resource identity
- authorization-server listing and issuer consistency
- authorization-code and PKCE S256 support
- token endpoint authentication metadata and DCR requirements
- resource/server scope drift and bearer challenge shape
- obvious secret-like fields, bounded input, deterministic and redacted reports

## Limits

This is a saved-fixture lint tool, not a live client, OAuth implementation, SSRF scanner, complete RFC validator, accessibility certification, or evidence of OpenAI approval. It never fetches metadata, follows redirects, validates TLS/DNS, executes a login, or stores input. Review `docs/THREAT_MODEL.md` before using findings for a release decision.

## Project policy

MIT licensed. See [privacy](PRIVACY.md), [security](SECURITY.md), [support](SUPPORT.md), [contributing](CONTRIBUTING.md), and the [research note](docs/RESEARCH.md).
