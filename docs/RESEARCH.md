# Research and alternatives — 2026-10-23

## Need

Current OpenAI guidance requires OAuth authorization code with PKCE S256 and MCP-compatible metadata. MCP authorization uses protected-resource metadata to bind a resource to authorization servers. Real implementation reports show discovery failures around subpaths, issuer validation, metadata URL selection, and resource validation. This tool targets that narrow, testable gap before a live login.

## Primary sources

- [OpenAI authentication](https://developers.openai.com/plugins/build/auth) — authorization-code/PKCE, discovery, registration choices, and resource parameter.
- [MCP authorization specification (2026-07-28)](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization) — protected-resource discovery and OAuth metadata.
- [MCP security considerations](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/security-considerations) — confused-deputy, audience, and token handling risks.
- [RFC 9728](https://www.rfc-editor.org/info/rfc9728/) — OAuth protected resource metadata.

## Alternatives

- MCP Inspector exercises broader live connections and OAuth behavior. It is the right next step after static preflight, but requires a reachable server and has a different trust boundary.
- OAuth 2.0 Playground exercises live OAuth exchanges and handles credentials/tokens; it is not MCP resource-metadata specific.
- Server/framework conformance suites are deeper for their implementation, but do not offer a small standalone saved-fixture comparison.

## Novelty limit

OAuth metadata parsing and linting are established ideas. Originality here is limited to a small, local-first cross-document profile tailored to current MCP/OpenAI interoperability. It is not presented as a new protocol, complete validator, or replacement for existing inspectors.
