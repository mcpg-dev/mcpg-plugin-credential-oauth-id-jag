//! `dev.mcpg.credential.oauth-id-jag` — outbound OAuth 2.0 Cross-App Access
//! credential_issuer plugin (the ID-JAG two-hop flow).
//!
//! Turns the *caller's* subject token into an **upstream** access token so a
//! gateway can act on-behalf-of the end user against a federated MCP server.
//! Operators declare named providers; callers reference an issued token via
//! `cred://<plugin_id>/<provider>`.
//!
//! ## Two hops
//!
//! 1. **Exchange** (RFC 8693) at the enterprise IdP's `idp_token_url`: exchange
//!    the caller's subject token for an **ID-JAG** — an ID Assertion Grant
//!    scoped (`audience`) to the upstream Resource Authorization Server. The
//!    response's `issued_token_type` must be `…:token-type:id-jag`, or the
//!    issuer refuses (a misconfigured IdP is a security hole, not a fallback).
//! 2. **Redeem** (RFC 7523) at the upstream AS's `redeem_token_url`: present
//!    the ID-JAG as a `jwt-bearer` assertion and redeem it for the upstream
//!    access token. That token is the issued credential.
//!
//! ## Subject token
//!
//! The subject token is read from the resolved identity's
//! `attributes["subject_token"]` (and `subject_token_type`, falling back to the
//! provider default). Federation's `oauth_impersonation` mode populates these
//! from the inbound caller bearer. The subject token, the ID-JAG, and the
//! upstream token are used transiently and never logged.
//!
//! ## No in-plugin cache
//!
//! Issued tokens are per-caller — each subject token yields a distinct
//! exchange — so caching belongs in the host credential cache, keyed per
//! `(identity_hash, plugin_id, target)`. A provider-keyed in-plugin cache would
//! serve one caller's token to another, so it is deliberately omitted; every
//! `issue` performs a fresh two-hop flow and the host cache deduplicates per
//! caller.

mod config;

use std::collections::BTreeMap;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use mcpg_plugin_protocol::credential::{CredentialError, CredentialIssuer, IssuedCredential};
use mcpg_plugin_protocol::types::PluginIdentity;
use mcpg_plugin_protocol::{PluginClass, PluginManifest};
use mcpg_plugin_sdk::declare_plugin;
use mcpg_plugin_sdk::ffi::SyncCredentialIssuer;
use serde_json::Value;
use tokio::runtime::Runtime;

pub use config::{ConfigError, IdJagConfig, IdJagProviderConfig};

const PLUGIN_ID: &str = "dev.mcpg.credential.oauth-id-jag";

/// RFC 8693 §2.1 grant type for hop 1 (subject-token exchange).
const GRANT_TYPE_TOKEN_EXCHANGE: &str = "urn:ietf:params:oauth:grant-type:token-exchange";
/// RFC 7523 grant type for hop 2 (ID-JAG redemption at the upstream AS).
const GRANT_TYPE_JWT_BEARER: &str = "urn:ietf:params:oauth:grant-type:jwt-bearer";
/// The token type hop 1 requests and hop 1's response must carry.
const TOKEN_TYPE_ID_JAG: &str = "urn:ietf:params:oauth:token-type:id-jag";

/// Identity-attribute key carrying the caller's raw subject token to exchange.
/// Populated by federation `oauth_impersonation` (and any other caller); never
/// logged.
const SUBJECT_TOKEN_ATTR: &str = "subject_token";
/// Optional per-request override of the subject token's type.
const SUBJECT_TOKEN_TYPE_ATTR: &str = "subject_token_type";

/// Metric `hop` label values.
const HOP_EXCHANGE: &str = "exchange";
const HOP_REDEEM: &str = "redeem";

/// Hop-1 response: the ID-JAG the IdP mints from the caller's subject token.
#[derive(serde::Deserialize)]
struct ExchangeResponse {
    access_token: String,
    #[serde(default)]
    issued_token_type: Option<String>,
    #[serde(default)]
    expires_in: Option<u64>,
}

/// Hop-2 response: the upstream access token the AS issues for the ID-JAG.
#[derive(serde::Deserialize)]
struct RedeemResponse {
    access_token: String,
    #[serde(default = "default_token_type")]
    token_type: String,
    #[serde(default)]
    expires_in: Option<u64>,
    #[serde(default)]
    scope: Option<String>,
}

/// The ID-JAG carried between the two hops.
struct IdJag {
    assertion: String,
    expires_in: Option<u64>,
}

fn default_token_type() -> String {
    "Bearer".to_owned()
}

pub struct OAuthIdJagPlugin {
    inner: Arc<Inner>,
}

struct Inner {
    manifest: PluginManifest,
    config: IdJagConfig,
    http_client: reqwest::Client,
    /// Tokio runtime for the SyncCredentialIssuer FFI path; lazily built on
    /// first sync call (see the oauth-token-exchange issuer for rationale).
    sync_runtime: OnceLock<Runtime>,
}

impl OAuthIdJagPlugin {
    pub fn from_config_json(config_json: &str) -> Self {
        let cfg = IdJagConfig::parse(config_json).unwrap_or_else(|err| {
            tracing::error!(
                plugin_id = PLUGIN_ID,
                error = %err,
                "oauth-id-jag: config parse failed; refusing to register"
            );
            panic!(
                "oauth-id-jag config parse failed: {err}. A misconfigured \
                 credential issuer is a security hole; refusing to load."
            )
        });
        Self::from_validated_config(cfg)
    }

    fn from_validated_config(cfg: IdJagConfig) -> Self {
        let http_client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            // The client secret is posted to this endpoint; a redirect would
            // deliver it to a host the origin check never inspected.
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("oauth-id-jag: failed to build HTTP client");
        tracing::info!(
            plugin_id = PLUGIN_ID,
            provider_count = cfg.providers.len(),
            "oauth-id-jag: configured"
        );
        Self {
            inner: Arc::new(Inner {
                manifest: PluginManifest {
                    id: PLUGIN_ID.into(),
                    version: env!("CARGO_PKG_VERSION").into(),
                    name: "OAuth Cross-App Access (ID-JAG) Issuer".into(),
                    plugin_class: PluginClass::CredentialIssuer,
                    protocol_version: "1.0".into(),
                    license: None,
                    required_capabilities: Vec::new(),
                    tags: Vec::new(),
                    provides: Vec::new(),
                    provides_schemes: Vec::new(),
                    module_path_prefix: ::std::module_path!()
                        .split("::")
                        .next()
                        .unwrap_or("")
                        .to_owned(),
                    backend_profile: None,
                },
                config: cfg,
                http_client,
                sync_runtime: OnceLock::new(),
            }),
        }
    }
}

/// Whether two URLs share scheme + host + port.
///
/// Used to keep a discovery-supplied token endpoint on the origin the
/// operator configured — the credentials posted there are the operator's.
fn same_origin(a: &str, b: &str) -> bool {
    let origin = |u: &str| {
        url::Url::parse(u).ok().map(|p| {
            (
                p.scheme().to_owned(),
                p.host_str().map(str::to_ascii_lowercase),
                p.port_or_known_default(),
            )
        })
    };
    match (origin(a), origin(b)) {
        (Some(x), Some(y)) => x == y,
        _ => false,
    }
}

#[derive(Debug, Default, serde::Deserialize)]
/// Host-supplied per-call overrides (the `config` argument of
/// `CredentialIssuer::issue`). The gateway populates these from operator
/// config or from OAuth discovery — and discovery is a document the
/// *upstream* serves, so it is not operator-trusted. `redeem_token_url`
/// is therefore confined to the operator-configured origin rather than
/// merely scheme-checked.
struct CallOverrides {
    #[serde(default)]
    audience: Option<String>,
    #[serde(default)]
    redeem_token_url: Option<String>,
    #[serde(default)]
    resource: Option<String>,
}

impl CallOverrides {
    fn parse(config: &Value) -> Result<Self, CredentialError> {
        if config.is_null() {
            return Ok(Self::default());
        }
        serde_json::from_value(config.clone()).map_err(|e| CredentialError::Misconfigured {
            reason: format!("invalid per-call issuer config: {e}"),
        })
    }

    fn apply(
        self,
        provider_name: &str,
        mut provider: config::IdJagProviderConfig,
    ) -> Result<config::IdJagProviderConfig, CredentialError> {
        if let Some(audience) = self.audience.filter(|a| !a.is_empty()) {
            provider.audience = audience;
        }
        if let Some(url) = self.redeem_token_url.filter(|u| !u.is_empty()) {
            if !url.starts_with("http://") && !url.starts_with("https://") {
                return Err(CredentialError::Misconfigured {
                    reason: format!(
                        "per-call redeem_token_url for `{provider_name}` must be http(s)"
                    ),
                });
            }
            // This override reaches us from OAuth discovery, i.e. from a
            // document the *upstream* serves — and this endpoint is where the
            // client_id, client_secret and assertion get POSTed. A scheme
            // check alone let that upstream nominate any collector it liked.
            // The sibling oauth-token-exchange issuer carries no endpoint
            // override at all for exactly this reason; here the feature needs
            // one, so it is confined to the origin the operator configured.
            if !same_origin(&url, &provider.redeem_token_url) {
                return Err(CredentialError::Misconfigured {
                    reason: format!(
                        "per-call redeem_token_url for `{provider_name}` must share an origin \
                         with the configured endpoint; refusing to send client credentials to \
                         a discovery-nominated host"
                    ),
                });
            }
            provider.redeem_token_url = url;
        }
        if let Some(resource) = self.resource.filter(|r| !r.is_empty()) {
            provider.resource = Some(resource);
        }
        Ok(provider)
    }
}

async fn issue_inner(
    inner: &Inner,
    identity: &PluginIdentity,
    provider_name: &str,
    call_config: &Value,
) -> Result<IssuedCredential, CredentialError> {
    // Cross-app access is on-behalf-of impersonation: it mints an upstream
    // token from the *caller's* subject token. Honour it only for a
    // cryptographically Verified caller. Today the transport drops
    // `attributes` for non-Verified identities (so `subject_token` would be
    // absent), but that is an upstream coincidence — a custom identity plugin
    // emitting non-verified trust with populated attributes must not be able to
    // drive impersonation. Gate explicitly here.
    if !mcpg_plugin_protocol::catalog::trust_level_meets(
        identity.trust_level.as_str(),
        mcpg_plugin_protocol::catalog::TRUST_LEVEL_VERIFIED,
    ) {
        return Err(CredentialError::NotAuthorized {
            reason: format!(
                "cross-app access for `{provider_name}` requires a Verified caller; \
                 trust is `{}`",
                identity.trust_level
            ),
        });
    }

    // Exact provider entries win; the target template serves the rest
    // of an allowlisted fleet with `{target}` expanded per server.
    let resolved = match inner.config.providers.get(provider_name) {
        Some(provider) => provider.clone(),
        None => inner
            .config
            .target_template
            .as_ref()
            .and_then(|t| t.expand(provider_name))
            .ok_or_else(|| CredentialError::Misconfigured {
                reason: format!(
                    "unknown provider `{provider_name}` (no exact entry; \
                     target_template absent or target not in allowed_targets)"
                ),
            })?,
    };
    let resolved = CallOverrides::parse(call_config)?.apply(provider_name, resolved)?;
    let provider = &resolved;

    let subject_token = identity
        .attributes
        .get(SUBJECT_TOKEN_ATTR)
        .map(String::as_str)
        .filter(|t| !t.is_empty())
        .ok_or_else(|| CredentialError::Misconfigured {
            reason: format!(
                "cross-app access for `{provider_name}` requires the caller's subject token in \
                 identity.attributes[\"{SUBJECT_TOKEN_ATTR}\"]"
            ),
        })?;
    let subject_token_type = identity
        .attributes
        .get(SUBJECT_TOKEN_TYPE_ATTR)
        .map(String::as_str)
        .unwrap_or(provider.subject_token_type.as_str());

    let id_jag = exchange_for_id_jag(
        inner,
        provider_name,
        provider,
        subject_token,
        subject_token_type,
    )
    .await?;
    redeem_id_jag(inner, provider_name, provider, &id_jag).await
}

/// Hop 1: exchange the caller's subject token for an ID-JAG at the IdP.
async fn exchange_for_id_jag(
    inner: &Inner,
    provider_name: &str,
    provider: &IdJagProviderConfig,
    subject_token: &str,
    subject_token_type: &str,
) -> Result<IdJag, CredentialError> {
    let timeout = Duration::from_millis(provider.timeout_ms);
    let scope_joined = provider.scopes.join(" ");
    let mut form: Vec<(&str, &str)> = vec![
        ("grant_type", GRANT_TYPE_TOKEN_EXCHANGE),
        ("requested_token_type", TOKEN_TYPE_ID_JAG),
        ("audience", provider.audience.as_str()),
        ("subject_token", subject_token),
        ("subject_token_type", subject_token_type),
        ("client_id", provider.client_id.as_str()),
    ];
    if let Some(secret) = provider.client_secret.as_deref().filter(|s| !s.is_empty()) {
        form.push(("client_secret", secret));
    }
    if !provider.scopes.is_empty() {
        form.push(("scope", scope_joined.as_str()));
    }
    if let Some(res) = provider.resource.as_deref() {
        form.push(("resource", res));
    }

    let started = Instant::now();
    let response = inner
        .http_client
        .post(&provider.idp_token_url)
        .timeout(timeout)
        .form(&form)
        .send()
        .await
        .map_err(|e| CredentialError::Backend {
            reason: format!("ID-JAG exchange endpoint unreachable for `{provider_name}`: {e}"),
        })?;
    record_latency(provider_name, HOP_EXCHANGE, started);

    if !response.status().is_success() {
        record_error(provider_name, HOP_EXCHANGE);
        return Err(oauth_error_from_response(response, provider_name, HOP_EXCHANGE).await);
    }

    let parsed: ExchangeResponse = response
        .json()
        .await
        .map_err(|e| CredentialError::Backend {
            reason: format!("failed to parse ID-JAG exchange response for `{provider_name}`: {e}"),
        })?;

    // The exchange MUST yield an ID-JAG. Anything else means the IdP is not
    // configured for cross-app access; refuse rather than forward a token of
    // the wrong type on to the upstream AS. The issued type is never echoed —
    // only the expected URN — so no upstream detail leaks.
    if parsed.issued_token_type.as_deref() != Some(TOKEN_TYPE_ID_JAG) {
        record_error(provider_name, HOP_EXCHANGE);
        return Err(CredentialError::Misconfigured {
            reason: format!(
                "ID-JAG exchange for `{provider_name}` did not return an id-jag token \
                 (issued_token_type != {TOKEN_TYPE_ID_JAG})"
            ),
        });
    }

    Ok(IdJag {
        assertion: parsed.access_token,
        expires_in: parsed.expires_in,
    })
}

/// Hop 2: redeem the ID-JAG for the upstream access token at the upstream AS.
async fn redeem_id_jag(
    inner: &Inner,
    provider_name: &str,
    provider: &IdJagProviderConfig,
    id_jag: &IdJag,
) -> Result<IssuedCredential, CredentialError> {
    let timeout = Duration::from_millis(provider.timeout_ms);
    let mut form: Vec<(&str, &str)> = vec![
        ("grant_type", GRANT_TYPE_JWT_BEARER),
        ("assertion", id_jag.assertion.as_str()),
    ];
    if let Some(cid) = provider
        .redeem_client_id
        .as_deref()
        .filter(|s| !s.is_empty())
    {
        form.push(("client_id", cid));
    }
    if let Some(secret) = provider
        .redeem_client_secret
        .as_deref()
        .filter(|s| !s.is_empty())
    {
        form.push(("client_secret", secret));
    }

    let started = Instant::now();
    let response = inner
        .http_client
        .post(&provider.redeem_token_url)
        .timeout(timeout)
        .form(&form)
        .send()
        .await
        .map_err(|e| CredentialError::Backend {
            reason: format!("ID-JAG redeem endpoint unreachable for `{provider_name}`: {e}"),
        })?;
    record_latency(provider_name, HOP_REDEEM, started);

    if !response.status().is_success() {
        record_error(provider_name, HOP_REDEEM);
        return Err(oauth_error_from_response(response, provider_name, HOP_REDEEM).await);
    }

    let parsed: RedeemResponse = response
        .json()
        .await
        .map_err(|e| CredentialError::Backend {
            reason: format!("failed to parse ID-JAG redeem response for `{provider_name}`: {e}"),
        })?;
    metrics::counter!(
        "mcpg_oauth_id_jag_total",
        "provider" => provider_name.to_owned(),
    )
    .increment(1);

    // ttl from the upstream AS; the host credential cache enforces
    // min(ttl, max_cache_ttl). Default one hour when absent.
    let ttl_seconds = parsed.expires_in.unwrap_or(3600);
    let mut parts = BTreeMap::new();
    parts.insert("access_token".to_owned(), parsed.access_token.clone());
    parts.insert("token_type".to_owned(), parsed.token_type.clone());
    let mut metadata = BTreeMap::new();
    metadata.insert("oauth.token_type".to_owned(), parsed.token_type.clone());
    if let Some(scope) = parsed.scope.as_deref().filter(|s| !s.is_empty()) {
        metadata.insert("oauth.granted_scope".to_owned(), scope.to_owned());
    }
    if let Some(exp) = id_jag.expires_in {
        metadata.insert("oauth.idjag_expires_in".to_owned(), exp.to_string());
    }
    Ok(IssuedCredential {
        value: Some(parsed.access_token),
        parts,
        ttl_seconds,
        lease_id: None,
        issued_at: now_rfc3339(),
        metadata,
    })
}

/// Map a non-success token-endpoint response to a `CredentialError`.
///
/// SECURITY: never embed the raw response body in the error reason. It is
/// upstream-internal detail that propagates into logs / audit, and a
/// misbehaving endpoint could echo the caller's subject token, the ID-JAG, or
/// the upstream token into it. Surface only the standard RFC 6749 §5.2 `error`
/// code (a fixed, non-sensitive enum) when the body parses as an OAuth error
/// response; otherwise just status + provider. Drop `error_description` / raw
/// body entirely.
async fn oauth_error_from_response(
    response: reqwest::Response,
    provider_name: &str,
    hop: &'static str,
) -> CredentialError {
    let status = response.status();
    let body = response
        .text()
        .await
        .unwrap_or_else(|_| "<unreadable>".to_owned());
    let oauth_error = serde_json::from_str::<Value>(&body)
        .ok()
        .and_then(|v| v.get("error").and_then(Value::as_str).map(str::to_owned));
    let reason = match oauth_error.as_deref() {
        Some(code) => format!(
            "ID-JAG {hop} endpoint returned HTTP {status} for `{provider_name}` (error: {code})"
        ),
        None => format!("ID-JAG {hop} endpoint returned HTTP {status} for `{provider_name}`"),
    };
    match status.as_u16() {
        429 => CredentialError::Throttled { reason },
        // 4xx is a config / subject-token problem — not retryable.
        400..=499 => CredentialError::Misconfigured { reason },
        // 5xx is upstream-side; surface as a transient backend outage.
        _ => CredentialError::Backend { reason },
    }
}

fn record_latency(provider_name: &str, hop: &'static str, started: Instant) {
    metrics::histogram!(
        "mcpg_oauth_id_jag_latency_ms",
        "provider" => provider_name.to_owned(),
        "hop" => hop,
    )
    .record(started.elapsed().as_millis() as f64);
}

fn record_error(provider_name: &str, hop: &'static str) {
    metrics::counter!(
        "mcpg_oauth_id_jag_error_total",
        "provider" => provider_name.to_owned(),
        "hop" => hop,
    )
    .increment(1);
}

fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

#[async_trait]
impl CredentialIssuer for OAuthIdJagPlugin {
    fn manifest(&self) -> &PluginManifest {
        &self.inner.manifest
    }

    async fn issue(
        &self,
        identity: &PluginIdentity,
        target: &str,
        config: &Value,
    ) -> Result<IssuedCredential, CredentialError> {
        issue_inner(&self.inner, identity, target, config).await
    }

    // Both the ID-JAG and the upstream token carry their own issuer expiry;
    // there is no per-token lease to revoke. No-op revoke.
}

impl SyncCredentialIssuer for OAuthIdJagPlugin {
    fn manifest(&self) -> &PluginManifest {
        &self.inner.manifest
    }

    fn issue(
        &self,
        identity: &PluginIdentity,
        target: &str,
        config: &Value,
    ) -> Result<IssuedCredential, CredentialError> {
        let runtime = self.inner.sync_runtime.get_or_init(|| {
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
                .expect("oauth-id-jag: failed to build tokio runtime")
        });
        let inner = Arc::clone(&self.inner);
        let identity = identity.clone();
        let target = target.to_owned();
        let config = config.clone();
        runtime.block_on(async move { issue_inner(&inner, &identity, &target, &config).await })
    }
}

declare_plugin! {
    plugin_id: PLUGIN_ID,
    plugin_version: env!("CARGO_PKG_VERSION"),
    descriptor_yaml: include_str!("../plugin.yaml"),
    capabilities: &[mcpg_plugin_protocol::capability::Capability::NetworkOutbound],
    entities: [
        credential_issuer as entity {
            inner_name: "",
            plugin_type: OAuthIdJagPlugin,
            factory: |cfg: &str, _host: ::mcpg_plugin_sdk::HostHandle| -> OAuthIdJagPlugin {
                OAuthIdJagPlugin::from_config_json(cfg)
            },
        }
    ],
}

#[cfg(test)]
mod tests {
    /// The endpoint override arrives from a document the upstream serves,
    /// and the client_id/client_secret are posted to it. Confining it to the
    /// operator's own origin is what stops a discovery document nominating a
    /// collector.
    #[test]
    fn redeem_token_url_override_is_confined_to_the_operator_origin() {
        let configured = "https://idp.corp.example/oauth/token";
        assert!(same_origin(
            "https://idp.corp.example/oauth/v2/token",
            configured
        ));
        for hostile in [
            "https://collector.attacker.test/token",
            "http://idp.corp.example/oauth/token",
            "https://idp.corp.example:8443/oauth/token",
            "https://evil.idp.corp.example/oauth/token",
        ] {
            assert!(
                !same_origin(hostile, configured),
                "{hostile} must be refused"
            );
        }
    }

    use super::*;
    use serde_json::json;
    use wiremock::matchers::{body_string_contains, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// Identity carrying a subject token in `attributes` — what federation
    /// `oauth_impersonation` builds from the inbound caller bearer.
    fn identity_with_subject(token: &str) -> PluginIdentity {
        let mut attributes = BTreeMap::new();
        if !token.is_empty() {
            attributes.insert(SUBJECT_TOKEN_ATTR.to_owned(), token.to_owned());
        }
        PluginIdentity {
            kind: "verified".into(),
            trust_level: "verified".into(),
            subject_id: Some("alice".into()),
            auth_provider: None,
            issuer: None,
            roles: vec![],
            groups: vec![],
            scopes: vec![],
            attributes,
        }
    }

    /// Build a plugin whose single `drive` provider points both hops at `base`
    /// (`/idp/token` for exchange, `/as/token` for redeem).
    fn build_with_base(base: &str) -> OAuthIdJagPlugin {
        let cfg = json!({
            "providers": {
                "drive": {
                    "idp_token_url": format!("{base}/idp/token"),
                    "client_id": "mcpg",
                    "client_secret": "idp-secret",
                    "audience": "https://drive-mcp.example.com",
                    "resource": "https://drive-mcp.example.com/mcp",
                    "scopes": ["read"],
                    "redeem_token_url": format!("{base}/as/token"),
                    "redeem_client_id": "mcpg-drive"
                }
            }
        });
        OAuthIdJagPlugin::from_config_json(&cfg.to_string())
    }

    #[test]
    fn from_config_json_succeeds() {
        let plugin = build_with_base("https://example.com");
        assert_eq!(plugin.inner.manifest.id, PLUGIN_ID);
        assert_eq!(plugin.inner.config.providers.len(), 1);
    }

    #[test]
    #[should_panic(expected = "oauth-id-jag config parse failed")]
    fn malformed_config_panics_at_construction() {
        OAuthIdJagPlugin::from_config_json("{ not json");
    }

    #[tokio::test]
    async fn two_hop_flow_issues_upstream_token() {
        let server = MockServer::start().await;
        // Hop 1 — exchange: assert every RFC 8693 form field EXACTLY (url-encoded).
        Mock::given(method("POST"))
            .and(path("/idp/token"))
            .and(body_string_contains(
                "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange",
            ))
            .and(body_string_contains(
                "requested_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aid-jag",
            ))
            .and(body_string_contains(
                "audience=https%3A%2F%2Fdrive-mcp.example.com",
            ))
            .and(body_string_contains(
                "resource=https%3A%2F%2Fdrive-mcp.example.com%2Fmcp",
            ))
            .and(body_string_contains("scope=read"))
            .and(body_string_contains("subject_token=caller-bearer-xyz"))
            .and(body_string_contains(
                "subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token",
            ))
            .and(body_string_contains("client_id=mcpg"))
            .and(body_string_contains("client_secret=idp-secret"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "access_token": "the-id-jag-assertion",
                "issued_token_type": "urn:ietf:params:oauth:token-type:id-jag",
                "token_type": "N_A",
                "expires_in": 900
            })))
            .expect(1)
            .mount(&server)
            .await;
        // Hop 2 — redeem: jwt-bearer + the assertion must equal hop-1's token.
        Mock::given(method("POST"))
            .and(path("/as/token"))
            .and(body_string_contains(
                "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer",
            ))
            .and(body_string_contains("assertion=the-id-jag-assertion"))
            .and(body_string_contains("client_id=mcpg-drive"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "access_token": "upstream-access-tok",
                "token_type": "Bearer",
                "expires_in": 600,
                "scope": "read"
            })))
            .expect(1)
            .mount(&server)
            .await;

        let plugin = build_with_base(&server.uri());
        let cred = CredentialIssuer::issue(
            &plugin,
            &identity_with_subject("caller-bearer-xyz"),
            "drive",
            &json!({}),
        )
        .await
        .unwrap();

        assert_eq!(cred.value.as_deref(), Some("upstream-access-tok"));
        assert_eq!(cred.ttl_seconds, 600);
        assert_eq!(cred.part("access_token"), Some("upstream-access-tok"));
        assert_eq!(cred.part("token_type"), Some("Bearer"));
        assert_eq!(
            cred.metadata.get("oauth.token_type").map(String::as_str),
            Some("Bearer")
        );
        assert_eq!(
            cred.metadata.get("oauth.granted_scope").map(String::as_str),
            Some("read")
        );
        assert_eq!(
            cred.metadata
                .get("oauth.idjag_expires_in")
                .map(String::as_str),
            Some("900")
        );
    }

    #[tokio::test]
    async fn wrong_issued_token_type_is_refused_without_body_echo() {
        let server = MockServer::start().await;
        // Hop 1 returns a plain access_token type, not an ID-JAG.
        Mock::given(method("POST"))
            .and(path("/idp/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "access_token": "SHOULD_NOT_LEAK_idjag_value",
                "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
                "expires_in": 900
            })))
            .mount(&server)
            .await;
        // No hop-2 mock: the flow must stop at the type check.
        let plugin = build_with_base(&server.uri());
        let err = CredentialIssuer::issue(
            &plugin,
            &identity_with_subject("caller-bearer-xyz"),
            "drive",
            &json!({}),
        )
        .await
        .unwrap_err();
        match err {
            CredentialError::Misconfigured { reason } => {
                assert!(
                    reason.contains("issued_token_type"),
                    "type-mismatch reason expected: {reason}"
                );
                // SECURITY: the hop-1 response body / token value must not leak.
                assert!(
                    !reason.contains("SHOULD_NOT_LEAK_idjag_value"),
                    "hop-1 token leaked into the reason: {reason}"
                );
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[tokio::test]
    async fn redeem_4xx_surfaces_only_oauth_error_code() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/idp/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "access_token": "the-id-jag-assertion",
                "issued_token_type": "urn:ietf:params:oauth:token-type:id-jag",
                "expires_in": 900
            })))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/as/token"))
            .respond_with(ResponseTemplate::new(400).set_body_json(json!({
                "error": "invalid_grant",
                "error_description": "assertion the-id-jag-assertion rejected LEAKED_SECRET_abc123"
            })))
            .mount(&server)
            .await;
        let plugin = build_with_base(&server.uri());
        let err = CredentialIssuer::issue(
            &plugin,
            &identity_with_subject("caller-bearer-xyz"),
            "drive",
            &json!({}),
        )
        .await
        .unwrap_err();
        match err {
            CredentialError::Misconfigured { reason } => {
                assert!(reason.contains("400"), "status preserved: {reason}");
                assert!(
                    reason.contains("invalid_grant"),
                    "OAuth error code surfaced: {reason}"
                );
                // SECURITY: neither the error_description body nor the ID-JAG
                // assertion may leak into the reason.
                assert!(
                    !reason.contains("LEAKED_SECRET_abc123"),
                    "AS error body leaked into the reason: {reason}"
                );
                assert!(
                    !reason.contains("the-id-jag-assertion"),
                    "ID-JAG assertion leaked into the reason: {reason}"
                );
                assert!(
                    !reason.contains("idp-secret") && !reason.contains("caller-bearer-xyz"),
                    "a secret leaked into the reason: {reason}"
                );
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[tokio::test]
    async fn non_verified_identity_is_not_authorized() {
        // On-behalf-of cross-app access requires a Verified caller. A
        // non-verified identity with a populated subject token must be refused
        // before any HTTP.
        let plugin = build_with_base("https://example.com");
        let mut identity = identity_with_subject("caller-bearer-xyz");
        identity.trust_level = "header_asserted".into();
        identity.kind = "header_asserted".into();
        let err = CredentialIssuer::issue(&plugin, &identity, "drive", &json!({}))
            .await
            .unwrap_err();
        match err {
            CredentialError::NotAuthorized { reason } => {
                assert!(reason.contains("Verified"), "got: {reason}");
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[tokio::test]
    async fn missing_subject_token_is_misconfigured() {
        // No live endpoint needed — the check happens before any HTTP.
        let plugin = build_with_base("https://example.com");
        let err = CredentialIssuer::issue(&plugin, &identity_with_subject(""), "drive", &json!({}))
            .await
            .unwrap_err();
        match err {
            CredentialError::Misconfigured { reason } => {
                assert!(reason.contains("subject_token"), "got: {reason}");
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[tokio::test]
    async fn unknown_provider_is_misconfigured() {
        let plugin = build_with_base("https://example.com");
        let err = CredentialIssuer::issue(
            &plugin,
            &identity_with_subject("tok"),
            "missing",
            &json!({}),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, CredentialError::Misconfigured { .. }));
    }

    #[tokio::test]
    async fn subject_token_type_override_from_identity() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/idp/token"))
            .and(body_string_contains(
                "subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Ajwt",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "access_token": "the-id-jag-assertion",
                "issued_token_type": "urn:ietf:params:oauth:token-type:id-jag",
                "expires_in": 900
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/as/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "access_token": "upstream-access-tok",
                "expires_in": 300
            })))
            .mount(&server)
            .await;
        let plugin = build_with_base(&server.uri());
        let mut identity = identity_with_subject("caller-bearer");
        identity.attributes.insert(
            SUBJECT_TOKEN_TYPE_ATTR.to_owned(),
            "urn:ietf:params:oauth:token-type:jwt".to_owned(),
        );
        let cred = CredentialIssuer::issue(&plugin, &identity, "drive", &json!({}))
            .await
            .unwrap();
        assert_eq!(cred.value.as_deref(), Some("upstream-access-tok"));
        // Default token_type when the AS omits it.
        assert_eq!(cred.part("token_type"), Some("Bearer"));
    }

    /// Build a plugin with NO exact providers — only a target template whose
    /// audience and redeem URL both expand `{target}`.
    fn build_template_with_base(base: &str) -> OAuthIdJagPlugin {
        let cfg = json!({
            "target_template": {
                "allowed_targets": ["srv-*"],
                "idp_token_url": format!("{base}/idp/token"),
                "client_id": "mcpg-fleet",
                "client_secret": "idp-secret",
                "audience_template": "https://{target}.mcp.example.com",
                "scopes": ["read"],
                "redeem_token_url_template": format!("{base}/as/{{target}}/token")
            }
        });
        OAuthIdJagPlugin::from_config_json(&cfg.to_string())
    }

    #[tokio::test]
    async fn template_expands_target_through_two_hop_flow() {
        let server = MockServer::start().await;
        // Hop 1 must carry the audience expanded from the template.
        Mock::given(method("POST"))
            .and(path("/idp/token"))
            .and(body_string_contains(
                "audience=https%3A%2F%2Fsrv-crm.mcp.example.com",
            ))
            .and(body_string_contains("client_id=mcpg-fleet"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "access_token": "the-id-jag-assertion",
                "issued_token_type": "urn:ietf:params:oauth:token-type:id-jag",
                "expires_in": 900
            })))
            .expect(1)
            .mount(&server)
            .await;
        // Hop 2 lands on the per-target redeem path expanded from the template.
        Mock::given(method("POST"))
            .and(path("/as/srv-crm/token"))
            .and(body_string_contains("assertion=the-id-jag-assertion"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "access_token": "upstream-access-tok",
                "token_type": "Bearer",
                "expires_in": 600
            })))
            .expect(1)
            .mount(&server)
            .await;

        let plugin = build_template_with_base(&server.uri());
        let cred = CredentialIssuer::issue(
            &plugin,
            &identity_with_subject("caller-bearer-xyz"),
            "srv-crm",
            &json!({}),
        )
        .await
        .unwrap();
        assert_eq!(cred.value.as_deref(), Some("upstream-access-tok"));
        assert_eq!(cred.ttl_seconds, 600);
    }

    #[tokio::test]
    async fn template_target_outside_allowlist_is_misconfigured() {
        // Must fail closed before any HTTP: the target is not allowlisted.
        let plugin = build_template_with_base("https://example.com");
        let err = CredentialIssuer::issue(
            &plugin,
            &identity_with_subject("tok"),
            "other-app",
            &json!({}),
        )
        .await
        .unwrap_err();
        match err {
            CredentialError::Misconfigured { reason } => {
                assert!(reason.contains("other-app"), "got: {reason}");
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[tokio::test]
    async fn call_config_overrides_take_precedence() {
        let server = MockServer::start().await;
        // Hop 1 must carry the OVERRIDDEN audience/resource, not the provider's.
        Mock::given(method("POST"))
            .and(path("/idp/token"))
            .and(body_string_contains(
                "audience=https%3A%2F%2Fdiscovered.example.com",
            ))
            .and(body_string_contains(
                "resource=https%3A%2F%2Fdiscovered.example.com%2Fmcp",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "access_token": "the-id-jag-assertion",
                "issued_token_type": "urn:ietf:params:oauth:token-type:id-jag",
                "expires_in": 900
            })))
            .expect(1)
            .mount(&server)
            .await;
        // Hop 2 lands on the OVERRIDDEN redeem path.
        Mock::given(method("POST"))
            .and(path("/discovered/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "access_token": "upstream-access-tok",
                "expires_in": 300
            })))
            .expect(1)
            .mount(&server)
            .await;

        let plugin = build_with_base(&server.uri());
        let call_config = json!({
            "audience": "https://discovered.example.com",
            "resource": "https://discovered.example.com/mcp",
            "redeem_token_url": format!("{}/discovered/token", server.uri()),
        });
        let cred = CredentialIssuer::issue(
            &plugin,
            &identity_with_subject("caller-bearer-xyz"),
            "drive",
            &call_config,
        )
        .await
        .unwrap();
        assert_eq!(cred.value.as_deref(), Some("upstream-access-tok"));
    }

    #[tokio::test]
    async fn non_http_redeem_override_is_refused() {
        let plugin = build_with_base("https://example.com");
        let err = CredentialIssuer::issue(
            &plugin,
            &identity_with_subject("tok"),
            "drive",
            &json!({ "redeem_token_url": "file:///etc/passwd" }),
        )
        .await
        .unwrap_err();
        match err {
            CredentialError::Misconfigured { reason } => {
                assert!(reason.contains("http"), "got: {reason}");
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[tokio::test]
    async fn malformed_call_config_is_misconfigured() {
        let plugin = build_with_base("https://example.com");
        let err = CredentialIssuer::issue(
            &plugin,
            &identity_with_subject("tok"),
            "drive",
            &json!({ "audience": 5 }),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, CredentialError::Misconfigured { .. }));
    }
}
