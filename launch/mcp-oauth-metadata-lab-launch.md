# Catch OAuth Metadata Drift Before Login

OAuth failures in an MCP integration rarely announce themselves as “the issuer in these two documents differs.” More often, the user sees a login loop, a generic authorization error, or a client that never discovers the endpoint it needs. The defect sits across documents: an MCP resource URL, protected-resource metadata, authorization-server metadata, and sometimes a `WWW-Authenticate` challenge.

That is the problem MCP OAuth Metadata Lab is designed to make smaller.

## The late-feedback problem

A live OAuth test combines discovery, redirects, client registration, user consent, token exchange, network policy, and server behavior. When that whole path fails, a simple static mismatch competes with many plausible causes. Teams can spend time debugging the flow before proving that its advertised inputs agree.

MCP OAuth Metadata Lab performs a deliberately earlier check. Give it saved, synthetic metadata and it compares the fields locally. It looks for resource identity drift, unlisted issuers, missing authorization-code or PKCE S256 support, registration-strategy gaps, scope differences, malformed challenges, unsafe URL shapes, and accidentally pasted secret-like fields.

## Local by design

The browser app and CLI make no outbound request. They do not follow a discovery URL, execute an authorization flow, accept a token, or store the fixture. Reports describe finding codes and paths without repeating submitted values. That boundary is useful for a preflight tool: the validator should not become another OAuth client or an SSRF surface.

```sh
node cli.mjs examples/valid.json --markdown
```

The same repository includes an unsafe synthetic fixture, a portable Agent Plugin skill, a threat model, and deterministic tests. The release has no runtime or development dependencies.

## Where it fits

This tool does not replace MCP Inspector. Inspector is the stronger choice when the server is reachable and you need to exercise the actual connection and login. A generic OAuth playground is better when you need to inspect a live token exchange. Framework conformance tests go deeper inside their own server implementations.

Metadata Lab occupies the step before those tools: compare the public contract while the inputs are still easy to reason about and safe to keep synthetic.

## What a clean report does—and does not—mean

A clean report means the evaluated fields passed this bounded profile. It does not prove full RFC compliance, TLS or DNS safety, correct live behavior, secure authorization-server configuration, accessibility conformance, OpenAI review, or deployability. Discovery documents can be internally consistent and still lead to an insecure system.

The next step remains a live test in an isolated environment, followed by server-side security review and the platform-specific release process.

## Release details

MCP OAuth Metadata Lab is MIT-licensed and intended for local developer use. The v0.1.0 release ships a browser UI, CLI, examples, portable audit skill, documentation, and release verification checklist. The project’s sources and live demo links will be inserted here only after exact-commit CI and deployment are independently verified.

_Draft prepared 2026-10-23 MYT. Publication destination is intentionally unselected pending explicit authorization._
