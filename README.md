# `dev.mcpg.credential.oauth-id-jag`

OAuth 2.0 **Cross-App Access** credential-issuer plugin (the ID-JAG flow).
Turns the *caller's* subject token into an **upstream** access token so the
gateway can act on-behalf-of the end user against a federated MCP server,
running the two-hop Identity Assertion Authorization Grant flow per provider:

1. **Exchange** (RFC 8693) at the enterprise IdP's `idp_token_url`: the
   caller's subject token is exchanged for an **ID-JAG** — a short-lived ID
   Assertion Grant scoped (`audience`) to the upstream Resource Authorization
   Server. The response's `issued_token_type` **must** be
   `urn:ietf:params:oauth:token-type:id-jag`, or the issuer refuses.
2. **Redeem** (RFC 7523) at the upstream AS's `redeem_token_url`: the ID-JAG is
   presented as a `jwt-bearer` assertion and redeemed for the upstream access
   token. That token is the issued credential.

Callers reference an issued token via the standard URI:

```
cred://dev.mcpg.credential.oauth-id-jag/<provider>
```

## How the subject token reaches the plugin

`CredentialIssuer::issue(identity, target, _config)` reads the caller's raw
subject token from `identity.attributes["subject_token"]` (and an optional
`identity.attributes["subject_token_type"]`, otherwise the provider default).
Federation's `oauth_impersonation` auth mode populates these from the inbound
caller bearer. The subject token, the ID-JAG, and the upstream token are used
transiently and never logged. If `subject_token` is absent the plugin returns a
`Misconfigured` error rather than exchanging an empty token.

Cross-app access is an on-behalf-of grant, so `issue` requires a **Verified**
caller — a spoofable header-asserted identity can never drive it.

## No in-plugin cache

Issued tokens are **per-caller** — each subject token yields a distinct
exchange — so caching is left to the **host credential cache**, keyed per
`(identity_hash, plugin_id, target)`. A provider-keyed in-plugin cache would
serve one caller's token to another, so it is deliberately omitted; the host
cache deduplicates per caller using the reported `ttl_seconds`.

## Operator config

```yaml
plugins:
  - id: dev.mcpg.credential.oauth-id-jag
    class: credential_issuer
    config:
      providers:
        drive:
          idp_token_url: https://idp.example.com/oauth2/token   # hop 1 (IdP)
          client_id: mcpg-gateway
          client_secret: "${env.IDP_CLIENT_SECRET}"             # optional
          audience: https://drive-mcp.example.com               # upstream AS issuer
          resource: https://drive-mcp.example.com/mcp           # optional (RFC 8707)
          scopes: [read]
          redeem_token_url: https://drive-mcp.example.com/oauth2/token  # hop 2 (upstream AS)
          redeem_client_id: mcpg-drive                          # optional
          redeem_client_secret: "${env.DRIVE_CLIENT_SECRET}"    # optional (needs redeem_client_id)
```

Used by a federation:

```yaml
mcp:
  federations:
    - name: drive
      upstream:
        url: https://drive-mcp.example.com/mcp
        auth:
          mode: oauth_impersonation
          credential: cred://dev.mcpg.credential.oauth-id-jag/drive
```

At **dispatch** the caller's bearer is run through both hops and the resulting
upstream token is forwarded; at **import / listen** (no caller) the upstream is
listed anonymously, like `pass_through`.

## Fleet template (`target_template`)

For a fleet of servers behind one IdP (e.g. an auto-federated MCP
registry), a `target_template` derives a provider for any allowlisted
target instead of one `providers` entry per server — `{target}` expands
to the requested target name:

```yaml
plugins:
  - id: dev.mcpg.credential.oauth-id-jag
    config:
      target_template:
        allowed_targets: ["com.acme/*"]     # exact or trailing-* globs; required
        idp_token_url: https://idp.acme.example/oauth2/token
        client_id: mcpg-fleet
        client_secret: "${env.IDP_SECRET}"
        audience_template: "https://{target}.mcp.acme.internal"
        resource_template: "https://{target}.mcp.acme.internal/mcp"   # optional
        redeem_token_url_template: "https://{target}.mcp.acme.internal/oauth2/token"
```

An exact `providers` entry always wins over the template; targets outside
`allowed_targets` fail closed. Combined with the registry mapper's
`{server}` expansion (`credential:
"cred://dev.mcpg.credential.oauth-id-jag/{server}"`), one block serves
every registry server.

The engine's per-call issuer config may override `audience`, `resource`,
and `redeem_token_url` (http(s) only) for a single issuance — the hook
OAuth discovery uses to feed a discovered authorization server without
minting config.

## Security notes

- The upstream token is *user-scoped* — audit the IdP-side `audience`/`scope`
  and the caller-trust requirements before enabling cross-app access against an
  upstream.
- Neither the subject token, the ID-JAG, nor the upstream token is logged, and
  IdP/AS response bodies are never echoed into error reasons (only the RFC 6749
  `error` code + HTTP status surface).

## Building and testing

```sh
cargo build --release   # builds the plugin cdylib into target/release/
cargo test
```
