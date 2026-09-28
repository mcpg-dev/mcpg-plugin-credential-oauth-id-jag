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
   token. `resource` (RFC 8707, as MCP authorization requires) and `scope` go
   with it when configured. That token is the issued credential.

Callers reference an issued token via the standard URI:

```
cred://dev.mcpg.credential.oauth-id-jag/<provider>
```

## How the subject token reaches the plugin

`CredentialIssuer::issue(identity, target, _config)` reads the caller's raw
subject token from `identity.attributes["subject_token"]`. Its type is the
provider's `subject_token_type`, unless
`identity.attributes["subject_token_type"]` overrides it. Federation's
`oauth_impersonation` auth mode populates the token from the inbound caller
bearer. The subject token, the ID-JAG, and the upstream token are used
transiently and never logged. If `subject_token` is absent the plugin returns
a `Misconfigured` error rather than exchanging an empty token.

Cross-app access is an on-behalf-of grant, so `issue` requires a **Verified**
caller — a spoofable header-asserted identity can never drive it.

A caller whose bearer the gateway process minted is refused before any request
with `Misconfigured`: "a token minted by this gateway cannot be exchanged at the
enterprise IdP". That covers `auth_provider: ema` (the embedded authorization
server's access tokens), `auth_provider: inspector_supervisor` (the supervised
inspector's credential), and any caller with `attributes["token_issuer"]`,
which the embedded authorization server sets on its callers also when a
`principal_issuer` changes their `auth_provider`. Only the gateway can
validate these bearers.

The exception is `attributes["subject_token_source"] = "idp_vault"`: the
subject token is then the caller's enterprise IdP sign-in the gateway keeps
(a federation with `upstream.auth.subject_token: idp_refresh_token` or
`idp_id_token`), not the gateway's bearer, and any caller may present it. It
goes only to the token endpoint that issued it, by the client it was issued
to (ID-JAG §4.3.3): the call is refused with `Misconfigured` before any
request unless `attributes["subject_token_endpoint"]` equals `idp_token_url`,
`attributes["subject_token_client_id"]` equals `client_id`, and, when
`idp_issuer` is set, `attributes["subject_token_issuer"]` equals it. Only
the gateway's federation engine sets these attributes: it drops every
`subject_token*` attribute the caller carries, and no claim mapping can
produce one. So set `idp_token_url` and `client_id` to the login client of
`governance.access.authorization_server.trusted_idps[].login`.

### Subject token types

`subject_token_type` is required. It takes a short name or the RFC 8693 URN:
`id_token`, `refresh_token`, `saml2`, `access_token` or `jwt`
(`urn:ietf:params:oauth:token-type:<name>`). Any other value refuses to load.
The per-request attribute override is validated the same way.

The ID-JAG profile requires IdPs to accept identity assertions (`id_token`,
`saml2`) and permits `refresh_token`. Okta's Cross App Access accepts
`id_token` and `refresh_token` only, so an inbound OAuth *access token* is not
a subject token Okta will exchange. Use `access_token` only with an IdP that
documents support for it.

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
          idp_token_url: https://acme.okta.com/oauth2/v1/token   # hop 1 (IdP)
          client_id: 0oa-mcpg-agent
          client_auth: private_key_jwt
          private_key: "${secret.MCPG_AGENT_KEY}"                # PEM
          key_id: mcpg-2026
          subject_token_type: id_token                           # required
          audience: https://auth.drive.example.com               # upstream AS issuer
          resource: https://drive-mcp.example.com/mcp            # optional (RFC 8707)
          scopes: [read]
          redeem_token_url: https://auth.drive.example.com/oauth2/token  # hop 2
          redeem_client_id: mcpg-drive
          redeem_client_secret: "${secret.DRIVE_CLIENT_SECRET}"
          redeem_client_auth: client_secret_basic
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
listed anonymously, like `pass_through`, unless the federation sets
`upstream.auth.import`.

By default `oauth_impersonation` sends the caller's bearer as the subject token,
so `subject_token_type: id_token` against Okta works only when callers present
an Okta ID token issued to this `client_id` (`aud` = `0oa-mcpg-agent` here). A
typical MCP client presents an OAuth access token instead, which Okta refuses
with `invalid_grant`. With interactive sign-in on the gateway, set
`upstream.auth.subject_token: idp_refresh_token` instead: the gateway then
sends the user's Okta refresh token it keeps from their sign-in, with the
matching `subject_token_type`, and this provider's `client_id` and
`idp_token_url` must be the gateway's login client's.

## Client authentication

Each hop authenticates on its own. Hop 1 uses `client_auth`, `client_id`,
`client_secret`, `private_key`, `key_id`, `signing_alg` and
`assertion_audience`. Hop 2 uses the same settings with a `redeem_` prefix.

| `client_auth` | Sends | Requires |
|---|---|---|
| unset | `client_id`, and `client_secret` when set, in the form body | nothing extra (hop 2 may send nothing) |
| `client_secret_post` | `client_id` and `client_secret` in the form body | both |
| `client_secret_basic` | `Authorization: Basic`, id and secret form-encoded first (RFC 6749 §2.3.1) | both |
| `private_key_jwt` | `client_id`, `client_assertion_type` and a signed `client_assertion` (RFC 7523 §2.2) | `client_id`, `private_key`; no `client_secret` |

For `private_key_jwt`:

- `private_key` is a PKCS#8 PEM (PKCS#1 also works for RSA). Source it with
  `${secret.NAME}` or `${env.X}`; literal `\n` escapes are accepted.
- `signing_alg` is one of `RS256` (default), `RS384`, `RS512`, `PS256`,
  `PS384`, `PS512`, `ES256`, `ES384` or `EdDSA`. The key must match it; a
  mismatch refuses to load.
- `key_id` sets the JWT `kid` header.
- `assertion_audience` is `token_endpoint` (default, the URL the assertion is
  posted to, which Okta requires) or `issuer`. For hop 1, `issuer` needs
  `idp_issuer`. For hop 2, `issuer` uses `audience`, which the ID-JAG profile
  defines as the upstream AS issuer.
- Every assertion is freshly signed: `iss` = `sub` = the client id, a new
  `jti`, `iat` now and `exp` two minutes later.

## Egress policy

Both token endpoints must be `https` and must not target a private, loopback
or link-local address. Both are checked at load and again before every
issuance, and a hop-2 refusal stops the flow before hop 1 runs. Name
resolution for every connection drops private addresses, so a name that
rebinds to an internal address is refused too. Redirects are never followed:
an endpoint that answers 3xx fails with `Misconfigured` ("configure the final
URL").

- `allow_insecure_http: true` permits `http://` endpoints (local development).
- `allow_private_network: true` permits private destinations, such as an IdP
  inside the cluster.

An egress proxy from `HTTPS_PROXY`, `HTTP_PROXY` or `ALL_PROXY` works without
either opt-in, also on a private address: its host resolves unfiltered. Through
a proxy the proxy resolves the token endpoint, so the name-resolution guard
does not apply to it; the URL check still refuses private IP literals and
`localhost` names. Enforce destination policy at the proxy.

## Actor token

`actor_token` with `actor_token_type` (same type names as the subject token)
adds an RFC 8693 actor to hop 1. They are set together or not at all.

## Fleet template (`target_template`)

For a fleet of servers behind one IdP (e.g. an auto-federated MCP
registry), a `target_template` derives a provider for any allowlisted
target instead of one `providers` entry per server. In the `*_template`
fields `{target}` expands to the requested target name and `{target_slug}`
to a hostname-safe form of it: every character outside `[A-Za-z0-9-]`
becomes `-`, and leading or trailing `-` are dropped (`com.acme/crm` becomes
`com-acme-crm`).

```yaml
plugins:
  - id: dev.mcpg.credential.oauth-id-jag
    config:
      target_template:
        allowed_targets: ["com.acme/*"]     # exact or trailing-* globs; required
        idp_token_url: https://idp.acme.example/oauth2/token
        client_id: mcpg-fleet
        client_auth: client_secret_basic
        client_secret: "${secret.IDP_SECRET}"
        subject_token_type: id_token
        audience_template: "https://{target_slug}.mcp.acme.example"
        resource_template: "https://{target_slug}.mcp.acme.example/mcp"   # optional
        redeem_token_url_template: "https://{target_slug}.mcp.acme.example/oauth2/token"
```

A raw `{target}` in the host of `redeem_token_url_template` only admits
targets made of letters, digits, `.` and `-`; anything else is refused, and a
pattern whose probe target fails that rule refuses to load. Use
`{target_slug}` in hosts. An exact `providers` entry always wins over the
template; targets outside `allowed_targets` fail closed. Combined with the
registry mapper's `{server}` expansion (`credential:
"cred://dev.mcpg.credential.oauth-id-jag/{server}"`), one block serves every
registry server.

The engine's per-call issuer config may override `audience`, `resource`,
and `redeem_token_url` for a single issuance — the hook OAuth discovery uses
to feed the exact metadata of the upstream's authorization server. That
metadata is the upstream's document, so it cannot widen the provider:

- A per-call `audience` must equal the configured `audience` (or the expanded
  `audience_template`), except for one trailing `/`. Otherwise the issuance
  fails with `Misconfigured` before either hop, so an upstream cannot obtain a
  grant for a sibling authorization server on the same origin.
- A per-call `redeem_token_url` must share its origin with the configured one.

## Migration

- `subject_token_type` is required. It defaulted to `access_token` before; set
  `subject_token_type: access_token` to keep that behaviour, or the type your
  callers' bearers really are.
- Both endpoints must be `https` and must not target or resolve to a private
  address. Set `allow_insecure_http` or `allow_private_network` where a
  deployment relied on that.
- A raw `{target}` in the host of `redeem_token_url_template` refuses targets
  with characters other than letters, digits, `.` and `-`. Use `{target_slug}`.
- A per-call `audience` that differs from the configured one is refused.

## Security notes

- The upstream token is *user-scoped* — audit the IdP-side `audience`/`scope`
  and the caller-trust requirements before enabling cross-app access against an
  upstream.
- Neither the subject token, the ID-JAG, the upstream token, the client
  secret, nor the private key is logged, and IdP/AS response bodies are never
  echoed into error reasons (only the RFC 6749 `error` code + HTTP status
  surface).

## Building and testing

```sh
cargo build --release   # builds the plugin cdylib into target/release/
cargo test
```
