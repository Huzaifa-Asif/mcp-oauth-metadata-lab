const MAX_BYTES = 256_000;
const LEVEL = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
const SECRET = /^(access|refresh|id)[_-]?token$|^client[_-]?secret$|^api[_-]?key$|^authorization$/i;

function finding(severity, code, message, path = null) { return { severity, code, message, path }; }
function object(value, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error(`${label} must be a JSON object`);
  if (new TextEncoder().encode(JSON.stringify(value)).byteLength > MAX_BYTES) throw new Error(`${label} exceeds the 256 KB limit`);
}
function safeUrl(value, label, findings, path) {
  if (typeof value !== "string" || !value.trim()) { findings.push(finding("critical", `missing-${label}`, `${label} must be a non-empty URL.`, path)); return null; }
  let url;
  try { url = new URL(value); } catch { findings.push(finding("critical", `invalid-${label}`, `${label} is not a valid URL.`, path)); return null; }
  if (url.protocol !== "https:") findings.push(finding("high", `insecure-${label}`, `${label} must use HTTPS.`, path));
  if (url.username || url.password) findings.push(finding("critical", `userinfo-${label}`, `${label} must not contain URL user information.`, path));
  if (url.hash) findings.push(finding("medium", `fragment-${label}`, `${label} should not contain a fragment.`, path));
  if (/^(localhost|127\.|\[?::1\]?|0\.0\.0\.0|169\.254\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/i.test(url.hostname)) findings.push(finding("high", `private-${label}`, `${label} points to a local or private host; verify this is intentional.`, path));
  return url;
}
function strings(value, label, findings, path) {
  if (!Array.isArray(value) || value.some((x) => typeof x !== "string" || !x.trim())) { findings.push(finding("high", `invalid-${label}`, `${label} must be an array of non-empty strings.`, path)); return []; }
  return value;
}
function scanSecrets(value, path, findings) {
  if (!value || typeof value !== "object") return;
  for (const [key, child] of Object.entries(value)) {
    const childPath = `${path}.${key}`;
    if (SECRET.test(key) && child !== "[REDACTED]" && child !== null && child !== "") findings.push(finding("critical", "secret-bearing-input", "Remove credentials and tokens before analysis.", childPath));
    if (child && typeof child === "object") scanSecrets(child, childPath, findings);
  }
}

export function analyzeBundle(bundle) {
  object(bundle, "bundle");
  object(bundle.protectedResource, "protectedResource");
  object(bundle.authorizationServer, "authorizationServer");
  const findings = [];
  scanSecrets(bundle, "$", findings);
  const mcp = safeUrl(bundle.mcpUrl, "mcp-url", findings, "$.mcpUrl");
  const prm = bundle.protectedResource;
  const asm = bundle.authorizationServer;
  const resource = safeUrl(prm.resource, "resource", findings, "$.protectedResource.resource");
  if (mcp && resource && prm.resource !== bundle.mcpUrl) findings.push(finding("high", "resource-mismatch", "resource does not exactly match the MCP URL.", "$.protectedResource.resource"));
  const servers = strings(prm.authorization_servers, "authorization-servers", findings, "$.protectedResource.authorization_servers");
  const serverUrls = servers.map((value, index) => safeUrl(value, "authorization-server", findings, `$.protectedResource.authorization_servers[${index}]`)).filter(Boolean);
  const issuer = safeUrl(asm.issuer, "issuer", findings, "$.authorizationServer.issuer");
  safeUrl(asm.authorization_endpoint, "authorization-endpoint", findings, "$.authorizationServer.authorization_endpoint");
  safeUrl(asm.token_endpoint, "token-endpoint", findings, "$.authorizationServer.token_endpoint");
  if (issuer && serverUrls.length && !servers.includes(asm.issuer)) findings.push(finding("critical", "issuer-not-authorized", "Authorization server issuer is not listed exactly by the protected resource.", "$.authorizationServer.issuer"));
  const grants = asm.grant_types_supported === undefined ? ["authorization_code", "implicit"] : strings(asm.grant_types_supported, "grant-types", findings, "$.authorizationServer.grant_types_supported");
  if (!grants.includes("authorization_code")) findings.push(finding("critical", "authorization-code-missing", "ChatGPT requires the authorization code flow.", "$.authorizationServer.grant_types_supported"));
  const responses = strings(asm.response_types_supported, "response-types", findings, "$.authorizationServer.response_types_supported");
  if (!responses.includes("code")) findings.push(finding("critical", "code-response-missing", "Authorization code flow requires response type code.", "$.authorizationServer.response_types_supported"));
  const challenges = strings(asm.code_challenge_methods_supported ?? [], "pkce-methods", findings, "$.authorizationServer.code_challenge_methods_supported");
  if (!challenges.includes("S256")) findings.push(finding("critical", "pkce-s256-missing", "PKCE S256 support is required.", "$.authorizationServer.code_challenge_methods_supported"));
  const strategy = bundle.clientRegistration ?? "cimd";
  if (!new Set(["cimd", "dcr", "predefined"]).has(strategy)) findings.push(finding("high", "unknown-registration-strategy", "clientRegistration must be cimd, dcr, or predefined.", "$.clientRegistration"));
  const authMethods = strings(asm.token_endpoint_auth_methods_supported ?? [], "token-auth-methods", findings, "$.authorizationServer.token_endpoint_auth_methods_supported");
  const supportedAuth = strategy === "cimd" ? ["none", "private_key_jwt"] : ["none", "client_secret_basic", "client_secret_post"];
  if (!authMethods.some((x) => supportedAuth.includes(x))) findings.push(finding("high", "unsupported-token-auth", `No token endpoint authentication method supported for ${strategy} is advertised.`, "$.authorizationServer.token_endpoint_auth_methods_supported"));
  if (authMethods.includes("private_key_jwt")) {
    const algorithms = strings(asm.token_endpoint_auth_signing_alg_values_supported, "token-auth-signing-algorithms", findings, "$.authorizationServer.token_endpoint_auth_signing_alg_values_supported");
    if (!algorithms.length || algorithms.includes("none")) findings.push(finding("critical", "private-key-jwt-algorithm-missing", "private_key_jwt requires a non-empty signing algorithm list that excludes none.", "$.authorizationServer.token_endpoint_auth_signing_alg_values_supported"));
  }
  if (strategy === "cimd" && asm.client_id_metadata_document_supported !== true) findings.push(finding("critical", "cimd-not-advertised", "CIMD requires client_id_metadata_document_supported: true.", "$.authorizationServer.client_id_metadata_document_supported"));
  if (strategy === "dcr" && !asm.registration_endpoint) findings.push(finding("critical", "registration-endpoint-missing", "DCR requires a registration_endpoint.", "$.authorizationServer.registration_endpoint"));
  if (strategy === "dcr" && asm.registration_endpoint) safeUrl(asm.registration_endpoint, "registration-endpoint", findings, "$.authorizationServer.registration_endpoint");
  if (bundle.challenge !== undefined) {
    if (typeof bundle.challenge !== "string") findings.push(finding("high", "invalid-challenge", "challenge must be a string.", "$.challenge"));
    else {
      const metadataMatch = bundle.challenge.match(/resource_metadata="([^"]+)"/i);
      if (!/^Bearer\b/i.test(bundle.challenge)) findings.push(finding("high", "non-bearer-challenge", "The challenge should use the Bearer scheme.", "$.challenge"));
      if (!metadataMatch) findings.push(finding("high", "resource-metadata-missing", "The challenge should identify protected resource metadata.", "$.challenge"));
      else {
        const metadataUrl = safeUrl(metadataMatch[1], "resource-metadata-url", findings, "$.challenge");
        if (metadataUrl && resource && metadataUrl.origin !== resource.origin) findings.push(finding("high", "resource-metadata-origin-mismatch", "Challenge metadata URL is not on the protected resource origin.", "$.challenge"));
        if (metadataUrl && !metadataUrl.pathname.includes("/.well-known/oauth-protected-resource")) findings.push(finding("medium", "unexpected-resource-metadata-path", "Challenge metadata URL does not use the OAuth protected-resource well-known path.", "$.challenge"));
      }
    }
  }
  const resourceScopes = strings(prm.scopes_supported ?? [], "resource-scopes", findings, "$.protectedResource.scopes_supported");
  const serverScopes = strings(asm.scopes_supported ?? [], "server-scopes", findings, "$.authorizationServer.scopes_supported");
  for (const scope of resourceScopes) if (serverScopes.length && !serverScopes.includes(scope)) findings.push(finding("medium", "scope-not-advertised", `Resource scope ${scope} is not advertised by the authorization server.`, "$.protectedResource.scopes_supported"));
  if (resource && issuer && resource.origin === issuer.origin) findings.push(finding("info", "shared-origin", "Resource and authorization server share an origin; confirm the trust boundary is intentional."));
  findings.sort((a, b) => LEVEL[a.severity] - LEVEL[b.severity] || a.code.localeCompare(b.code));
  const summary = Object.fromEntries(Object.keys(LEVEL).map((level) => [level, findings.filter((x) => x.severity === level).length]));
  return { schemaVersion: 1, status: summary.critical || summary.high ? "needs-attention" : "reviewed", summary, findings, limitations: ["Offline analysis only; no endpoint is fetched and no OAuth flow is executed.", "Checks a bounded interoperability profile, not complete RFC or OpenAI conformance.", "A clean report is not security certification, app approval, or proof of deployability."] };
}

export function redact(value) {
  if (Array.isArray(value)) return value.map(redact);
  if (!value || typeof value !== "object") return value;
  return Object.fromEntries(Object.entries(value).map(([key, child]) => [key, SECRET.test(key) ? "[REDACTED]" : redact(child)]));
}

export function formatMarkdown(report) {
  const clean = (v) => String(v).replace(/[\u0000-\u001f\u007f-\u009f\u202a-\u202e\u2066-\u2069]/g, "?").replaceAll("`", "\\`");
  const lines = ["# MCP OAuth metadata report", "", `Status: **${report.status}**`, "", ...report.findings.map((x) => `- **${x.severity.toUpperCase()}** \`${clean(x.code)}\`: ${clean(x.message)}${x.path ? ` (\`${clean(x.path)}\`)` : ""}`), "", "## Limitations", "", ...report.limitations.map((x) => `- ${x}`), ""];
  return `${lines.join("\n")}\n`;
}
