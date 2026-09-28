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
//!    the ID-JAG as a `jwt-bearer` assertion, with `resource` and `scope`
//!    when configured, and redeem it for the upstream access token. That
//!    token is the issued credential.
//!
//! Each hop authenticates with `client_secret_post`, `client_secret_basic` or
//! `private_key_jwt`, configured separately. Both endpoints must be https and
//! must not resolve to private addresses unless the provider opts in.
//!
//! ## Subject token
//!
//! The subject token is read from the resolved identity's
//! `attributes["subject_token"]`; its type is the provider's
//! `subject_token_type` unless `attributes["subject_token_type"]` overrides
//! it. Federation's `oauth_impersonation` mode populates the token from the
//! inbound caller bearer. A bearer the gateway process minted (`auth_provider`
//! `ema` or `inspector_supervisor`, or any `attributes["token_issuer"]`) is
//! refused: no enterprise IdP can validate it.
//!
//! The exception is a subject token from the caller's enterprise IdP sign-in
//! the gateway keeps (`attributes["subject_token_source"] = "idp_vault"`),
//! whatever bearer the caller presented. It is exchanged only at the token
//! endpoint that issued it, by the client it was issued to (ID-JAG §4.3.3):
//! `attributes["subject_token_endpoint"]` must equal `idp_token_url`,
//! `attributes["subject_token_client_id"]` must equal `client_id`, and, when
//! `idp_issuer` is set, `attributes["subject_token_issuer"]` must equal it.
//! Otherwise the call is refused before any request.
//!
//! The subject token, the ID-JAG, and the upstream token are used
//! transiently and never logged.
//!
//! ## No in-plugin cache
//!
//! Issued tokens are per-caller — each subject token yields a distinct
//! exchange — so caching belongs in the host credential cache, keyed per
//! `(identity_hash, plugin_id, target)`. A provider-keyed in-plugin cache would
//! serve one caller's token to another, so it is deliberately omitted; every
//! `issue` performs a fresh two-hop flow and the host cache deduplicates per
//! caller.

mod client_auth;
mod config;
mod egress;

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

use client_auth::ClientAuth;
pub use client_auth::{AssertionAudience, ClientAuthMethod, SigningAlg};
pub use config::{
    ConfigError, ExpandError, IdJagConfig, IdJagProviderConfig, IdJagTargetTemplate,
    normalize_token_type, target_slug,
};

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

/// `auth_provider` values of callers whose bearer the gateway process
/// minted: the embedded authorization server and the supervised inspector.
const GATEWAY_MINTED_AUTH_PROVIDERS: [&str; 2] = ["ema", "inspector_supervisor"];
/// Attribute the embedded authorization server sets on every caller of a
/// token it minted. A `principal_issuer` alias rewrites `auth_provider`
/// but leaves this in place.
const TOKEN_ISSUER_ATTR: &str = "token_issuer";
/// Attribute naming where the subject token came from.
const SUBJECT_TOKEN_SOURCE_ATTR: &str = "subject_token_source";
/// The caller's enterprise IdP sign-in the gateway stored: an IdP token,
/// exchangeable even when the caller presented a gateway-minted bearer.
const SUBJECT_TOKEN_SOURCE_IDP_VAULT: &str = "idp_vault";
/// The token endpoint, client and issuer a stored sign-in was issued by.
const SUBJECT_TOKEN_ENDPOINT_ATTR: &str = "subject_token_endpoint";
const SUBJECT_TOKEN_CLIENT_ID_ATTR: &str = "subject_token_client_id";
const SUBJECT_TOKEN_ISSUER_ATTR: &str = "subject_token_issuer";

fn is_gateway_minted(identity: &PluginIdentity) -> bool {
    let minted_provider = identity.auth_provider.as_deref().is_some_and(|p| {
        GATEWAY_MINTED_AUTH_PROVIDERS
            .iter()
            .any(|minted| p.eq_ignore_ascii_case(minted))
    });
    minted_provider || identity.attributes.contains_key(TOKEN_ISSUER_ATTR)
}

fn from_idp_vault(identity: &PluginIdentity) -> bool {
    identity
        .attributes
        .get(SUBJECT_TOKEN_SOURCE_ATTR)
        .is_some_and(|source| source == SUBJECT_TOKEN_SOURCE_IDP_VAULT)
}

/// Refuse a stored-sign-in subject token that `provider` would send to
/// another token endpoint than the one that issued it, or present with
/// another client (ID-JAG §4.3.3).
fn check_idp_vault_binding(
    provider_name: &str,
    provider: &IdJagProviderConfig,
    identity: &PluginIdentity,
) -> Result<(), CredentialError> {
    let attribute = |name: &str| identity.attributes.get(name).map(String::as_str);
    let bound = attribute(SUBJECT_TOKEN_ENDPOINT_ATTR) == Some(provider.idp_token_url.as_str())
        && attribute(SUBJECT_TOKEN_CLIENT_ID_ATTR) == Some(provider.client_id.as_str())
        && provider
            .idp_issuer
            .as_deref()
            .is_none_or(|issuer| attribute(SUBJECT_TOKEN_ISSUER_ATTR) == Some(issuer));
    if bound {
        return Ok(());
    }
    Err(CredentialError::Misconfigured {
        reason: format!(
            "cross-app access for `{provider_name}`: the stored enterprise sign-in may only be \
             exchanged at the IdP that issued it, by the client it was issued to; idp_token_url \
             and client_id must be the gateway's login client's, and idp_issuer, when set, its \
             IdP"
        ),
    })
}

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

/// Client authentication for both hops of one provider.
struct HopAuth {
    idp: ClientAuth,
    redeem: ClientAuth,
}

impl HopAuth {
    fn compile(provider: &IdJagProviderConfig) -> Result<Self, String> {
        Ok(Self {
            idp: provider.idp_client_auth()?,
            redeem: provider.redeem_client_auth()?,
        })
    }
}

struct Inner {
    manifest: PluginManifest,
    config: IdJagConfig,
    provider_auth: BTreeMap<String, Arc<HopAuth>>,
    template_auth: Option<Arc<HopAuth>>,
    /// Refuses private, loopback and link-local destinations.
    guarded_client: reqwest::Client,
    /// For providers with `allow_private_network: true`.
    open_client: reqwest::Client,
    /// Tokio runtime for the SyncCredentialIssuer FFI path; lazily built on
    /// first sync call (see the oauth-token-exchange issuer for rationale).
    sync_runtime: OnceLock<Runtime>,
}

impl Inner {
    fn client(&self, provider: &IdJagProviderConfig) -> &reqwest::Client {
        if provider.allow_private_network {
            &self.open_client
        } else {
            &self.guarded_client
        }
    }
}

fn refuse_to_load(err: &dyn std::fmt::Display) -> ! {
    tracing::error!(
        plugin_id = PLUGIN_ID,
        error = %err,
        "oauth-id-jag: config parse failed; refusing to register"
    );
    panic!(
        "oauth-id-jag config parse failed: {err}. A misconfigured \
         credential issuer is a security hole; refusing to load."
    )
}

impl OAuthIdJagPlugin {
    pub fn from_config_json(config_json: &str) -> Self {
        let cfg = IdJagConfig::parse(config_json).unwrap_or_else(|err| refuse_to_load(&err));
        Self::from_validated_config(cfg).unwrap_or_else(|err| refuse_to_load(&err))
    }

    fn from_validated_config(cfg: IdJagConfig) -> Result<Self, String> {
        let mut provider_auth = BTreeMap::new();
        for (name, provider) in &cfg.providers {
            let auth = HopAuth::compile(provider).map_err(|e| format!("provider `{name}` {e}"))?;
            provider_auth.insert(name.clone(), Arc::new(auth));
        }
        let template_auth = match &cfg.target_template {
            Some(template) => {
                let probe = template.probe().map_err(|e| e.to_string())?;
                let auth = HopAuth::compile(&probe).map_err(|e| format!("target_template {e}"))?;
                Some(Arc::new(auth))
            }
            None => None,
        };
        tracing::info!(
            plugin_id = PLUGIN_ID,
            provider_count = cfg.providers.len(),
            "oauth-id-jag: configured"
        );
        Ok(Self {
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
                provider_auth,
                template_auth,
                guarded_client: egress::build_client(true),
                open_client: egress::build_client(false),
                sync_runtime: OnceLock::new(),
            }),
        })
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

/// Whether a per-call audience names the configured one. Only a single
/// trailing `/` may differ: the authorization server compares `aud` byte for
/// byte against its issuer, and discovery supplies that exact spelling.
fn same_audience(per_call: &str, configured: &str) -> bool {
    fn trim(s: &str) -> &str {
        s.strip_suffix('/').unwrap_or(s)
    }
    trim(per_call) == trim(configured)
}

#[derive(Debug, Default, serde::Deserialize)]
/// Host-supplied per-call overrides (the `config` argument of
/// `CredentialIssuer::issue`). The gateway populates these from operator
/// config or from OAuth discovery — and discovery is a document the
/// *upstream* serves, so it is not operator-trusted. `audience` must name
/// the configured audience, and `redeem_token_url` must stay on the
/// configured origin.
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
        // The audience picks the AS the ID-JAG (and an issuer-audience client
        // assertion) is good for; origin confinement cannot tell sibling ASes apart.
        if let Some(audience) = self.audience.filter(|a| !a.is_empty()) {
            if !same_audience(&audience, &provider.audience) {
                return Err(CredentialError::Misconfigured {
                    reason: format!(
                        "per-call audience for `{provider_name}` does not match the configured \
                         audience; refusing to request an ID-JAG for a discovery-nominated \
                         authorization server"
                    ),
                });
            }
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
            // client credentials and the assertion get POSTed. A scheme check
            // alone would let that upstream nominate any collector it liked,
            // so it is confined to the origin the operator configured.
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

fn unknown_provider(provider_name: &str) -> CredentialError {
    CredentialError::Misconfigured {
        reason: format!(
            "unknown provider `{provider_name}` (no exact entry; \
             target_template absent or target not in allowed_targets)"
        ),
    }
}

/// The provider for `provider_name` and its compiled client authentication.
/// Exact provider entries win; the target template serves the rest of an
/// allowlisted fleet.
fn resolve_provider(
    inner: &Inner,
    provider_name: &str,
) -> Result<(IdJagProviderConfig, Arc<HopAuth>), CredentialError> {
    if let Some(provider) = inner.config.providers.get(provider_name) {
        let auth = inner
            .provider_auth
            .get(provider_name)
            .cloned()
            .ok_or_else(|| unknown_provider(provider_name))?;
        return Ok((provider.clone(), auth));
    }
    let (Some(template), Some(auth)) = (&inner.config.target_template, &inner.template_auth) else {
        return Err(unknown_provider(provider_name));
    };
    match template.expand(provider_name) {
        Ok(provider) => Ok((provider, Arc::clone(auth))),
        Err(ExpandError::NotAllowed(_)) => Err(unknown_provider(provider_name)),
        Err(e) => Err(CredentialError::Misconfigured {
            reason: e.to_string(),
        }),
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

    // A bearer the gateway minted is valid only at this gateway, so posting
    // one to the IdP can never succeed and hands a live gateway credential
    // to a third party. A stored IdP sign-in is an IdP token whoever the
    // caller is, and is checked against the provider below instead.
    let from_vault = from_idp_vault(identity);
    if !from_vault && is_gateway_minted(identity) {
        return Err(CredentialError::Misconfigured {
            reason: format!(
                "cross-app access for `{provider_name}`: a token minted by this gateway \
                 cannot be exchanged at the enterprise IdP"
            ),
        });
    }

    let (resolved, auth) = resolve_provider(inner, provider_name)?;
    let provider = CallOverrides::parse(call_config)?.apply(provider_name, resolved)?;
    if from_vault {
        check_idp_vault_binding(provider_name, &provider, identity)?;
    }

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
    let subject_token_type = match identity.attributes.get(SUBJECT_TOKEN_TYPE_ATTR) {
        Some(raw) => normalize_token_type(raw).ok_or_else(|| CredentialError::Misconfigured {
            reason: format!(
                "cross-app access for `{provider_name}`: identity.attributes\
                 [\"{SUBJECT_TOKEN_TYPE_ATTR}\"] is not a supported token type"
            ),
        })?,
        None => provider.subject_token_type.clone(),
    };
    check_endpoints(provider_name, &provider)?;

    let id_jag = exchange_for_id_jag(
        inner,
        provider_name,
        &provider,
        &auth.idp,
        subject_token,
        &subject_token_type,
    )
    .await?;
    redeem_id_jag(inner, provider_name, &provider, &auth.redeem, &id_jag).await
}

/// Check both token endpoints before either hop runs, so a refused redeem
/// endpoint never costs the caller's subject token a trip to the IdP.
fn check_endpoints(
    provider_name: &str,
    provider: &IdJagProviderConfig,
) -> Result<(), CredentialError> {
    for (hop, url) in [
        (HOP_EXCHANGE, &provider.idp_token_url),
        (HOP_REDEEM, &provider.redeem_token_url),
    ] {
        egress::check_endpoint(url, provider.egress()).map_err(|reason| {
            CredentialError::Misconfigured {
                reason: format!("ID-JAG {hop} endpoint for `{provider_name}` {reason}"),
            }
        })?;
    }
    Ok(())
}

/// One token endpoint and how to authenticate to it.
struct Hop<'a> {
    label: &'static str,
    token_url: &'a str,
    auth: &'a ClientAuth,
    /// The authorization server's issuer identifier, when known.
    issuer: Option<&'a str>,
}

/// POST `form` to a hop's token endpoint with the hop's client
/// authentication.
async fn post_token_request(
    inner: &Inner,
    provider_name: &str,
    provider: &IdJagProviderConfig,
    hop: Hop<'_>,
    mut form: Vec<(&'static str, String)>,
) -> Result<reqwest::Response, CredentialError> {
    let Hop {
        label: hop,
        token_url,
        auth,
        issuer,
    } = hop;
    let request = inner
        .client(provider)
        .post(token_url)
        .timeout(Duration::from_millis(provider.timeout_ms));
    let request = auth
        .authenticate(request, &mut form, token_url, issuer)
        .map_err(|reason| CredentialError::Misconfigured {
            reason: format!("ID-JAG {hop} client authentication for `{provider_name}`: {reason}"),
        })?;

    let started = Instant::now();
    let response = request.form(&form).send().await.map_err(|e| {
        record_error(provider_name, hop);
        if egress::is_private_address_refusal(&e) {
            CredentialError::Misconfigured {
                reason: format!(
                    "ID-JAG {hop} endpoint for `{provider_name}` resolves only to private, \
                     loopback or link-local addresses (set allow_private_network: true to permit)"
                ),
            }
        } else {
            CredentialError::Backend {
                reason: format!("ID-JAG {hop} endpoint unreachable for `{provider_name}`: {e}"),
            }
        }
    })?;
    record_latency(provider_name, hop, started);

    if !response.status().is_success() {
        record_error(provider_name, hop);
        return Err(oauth_error_from_response(response, provider_name, hop).await);
    }
    Ok(response)
}

/// Hop 1: exchange the caller's subject token for an ID-JAG at the IdP.
async fn exchange_for_id_jag(
    inner: &Inner,
    provider_name: &str,
    provider: &IdJagProviderConfig,
    auth: &ClientAuth,
    subject_token: &str,
    subject_token_type: &str,
) -> Result<IdJag, CredentialError> {
    let mut form: Vec<(&'static str, String)> = vec![
        ("grant_type", GRANT_TYPE_TOKEN_EXCHANGE.to_owned()),
        ("requested_token_type", TOKEN_TYPE_ID_JAG.to_owned()),
        ("audience", provider.audience.clone()),
        ("subject_token", subject_token.to_owned()),
        ("subject_token_type", subject_token_type.to_owned()),
    ];
    if !provider.scopes.is_empty() {
        form.push(("scope", provider.scopes.join(" ")));
    }
    if let Some(res) = provider.resource.as_deref() {
        form.push(("resource", res.to_owned()));
    }
    if let (Some(token), Some(token_type)) = (
        provider.actor_token.as_deref().filter(|t| !t.is_empty()),
        provider.actor_token_type.as_deref(),
    ) {
        form.push(("actor_token", token.to_owned()));
        form.push(("actor_token_type", token_type.to_owned()));
    }

    let hop = Hop {
        label: HOP_EXCHANGE,
        token_url: &provider.idp_token_url,
        auth,
        issuer: provider.idp_issuer.as_deref(),
    };
    let response = post_token_request(inner, provider_name, provider, hop, form).await?;

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
    auth: &ClientAuth,
    id_jag: &IdJag,
) -> Result<IssuedCredential, CredentialError> {
    let mut form: Vec<(&'static str, String)> = vec![
        ("grant_type", GRANT_TYPE_JWT_BEARER.to_owned()),
        ("assertion", id_jag.assertion.clone()),
    ];
    // MCP authorization requires `resource` (RFC 8707) on every token
    // request, whether or not the IdP carried it into the ID-JAG.
    if let Some(res) = provider.resource.as_deref() {
        form.push(("resource", res.to_owned()));
    }
    if !provider.scopes.is_empty() {
        form.push(("scope", provider.scopes.join(" ")));
    }
    // `audience` is, by the ID-JAG profile, the upstream AS issuer.
    let hop = Hop {
        label: HOP_REDEEM,
        token_url: &provider.redeem_token_url,
        auth,
        issuer: Some(provider.audience.as_str()),
    };
    let response = post_token_request(inner, provider_name, provider, hop, form).await?;

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
        300..=399 => CredentialError::Misconfigured {
            reason: format!(
                "ID-JAG {hop} endpoint for `{provider_name}` redirected (HTTP {status}); \
                 redirects are not followed, configure the final URL"
            ),
        },
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
    use super::*;
    use jsonwebtoken::{Algorithm, DecodingKey, Validation};
    use serde_json::json;
    use wiremock::matchers::{any, body_string_contains, header, method, path};
    use wiremock::{Mock, MockServer, Request, ResponseTemplate};

    const RSA_PRIV: &str = include_str!("../tests/fixtures/rsa_priv.pem");
    const RSA_PUB: &str = include_str!("../tests/fixtures/rsa_pub.pem");
    const EC_PRIV: &str = include_str!("../tests/fixtures/ec_priv.pem");
    const EC_PUB: &str = include_str!("../tests/fixtures/ec_pub.pem");
    const ED_PRIV: &str = include_str!("../tests/fixtures/ed25519_priv.pem");
    const ED_PUB: &str = include_str!("../tests/fixtures/ed25519_pub.pem");

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
            auth_provider: Some("oidc".into()),
            issuer: None,
            roles: vec![],
            groups: vec![],
            scopes: vec![],
            attributes,
        }
    }

    /// The `drive` provider with both hops pointed at `base` (`/idp/token`
    /// for exchange, `/as/token` for redeem). A wiremock server listens on
    /// loopback over plain http, so both egress opt-ins are set.
    fn drive_config(base: &str) -> Value {
        json!({
            "providers": {
                "drive": {
                    "idp_token_url": format!("{base}/idp/token"),
                    "client_id": "mcpg",
                    "client_secret": "idp-secret",
                    "subject_token_type": "access_token",
                    "audience": "https://drive-mcp.example.com",
                    "resource": "https://drive-mcp.example.com/mcp",
                    "scopes": ["read"],
                    "redeem_token_url": format!("{base}/as/token"),
                    "redeem_client_id": "mcpg-drive",
                    "allow_insecure_http": true,
                    "allow_private_network": true
                }
            }
        })
    }

    fn build_with_base(base: &str) -> OAuthIdJagPlugin {
        OAuthIdJagPlugin::from_config_json(&drive_config(base).to_string())
    }

    fn id_jag_response() -> ResponseTemplate {
        ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "the-id-jag-assertion",
            "issued_token_type": "urn:ietf:params:oauth:token-type:id-jag",
            "token_type": "N_A",
            "expires_in": 300
        }))
    }

    fn upstream_token_response() -> ResponseTemplate {
        ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "upstream-access-tok",
            "token_type": "Bearer",
            "expires_in": 600
        }))
    }

    /// Decoded form body of the one request the server saw on `at`.
    async fn form_sent_to(server: &MockServer, at: &str) -> BTreeMap<String, String> {
        let requests: Vec<Request> = server.received_requests().await.unwrap();
        let request = requests
            .iter()
            .find(|r| r.url.path() == at)
            .unwrap_or_else(|| panic!("no request to {at}"));
        url::form_urlencoded::parse(&request.body)
            .into_owned()
            .collect()
    }

    fn assert_client_assertion(
        form: &BTreeMap<String, String>,
        alg: Algorithm,
        key: &DecodingKey,
        client_id: &str,
        aud: &str,
    ) {
        assert_eq!(
            form.get("client_assertion_type").map(String::as_str),
            Some("urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
        );
        assert!(!form.contains_key("client_secret"));
        let mut validation = Validation::new(alg);
        validation.set_audience(&[aud]);
        validation.set_issuer(&[client_id]);
        let claims = jsonwebtoken::decode::<Value>(&form["client_assertion"], key, &validation)
            .expect("client assertion verifies")
            .claims;
        assert_eq!(claims["sub"], client_id);
        let lifetime = claims["exp"].as_u64().unwrap() - claims["iat"].as_u64().unwrap();
        assert!(lifetime <= 300, "lifetime {lifetime}s exceeds five minutes");
        assert!(claims["jti"].as_str().is_some_and(|j| !j.is_empty()));
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

    #[test]
    #[should_panic(expected = "oauth-id-jag config parse failed")]
    fn http_endpoint_without_opt_in_refuses_to_load() {
        let mut cfg = drive_config("http://idp.example.com");
        cfg["providers"]["drive"]["allow_insecure_http"] = json!(false);
        OAuthIdJagPlugin::from_config_json(&cfg.to_string());
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
        // The default client authentication keeps credentials in the body.
        let idp_form = form_sent_to(&server, "/idp/token").await;
        assert!(!idp_form.contains_key("client_assertion"));
        assert!(!idp_form.contains_key("actor_token"));
        // Hop 2 names the MCP resource and the scopes too.
        let as_form = form_sent_to(&server, "/as/token").await;
        assert_eq!(
            as_form.get("resource").map(String::as_str),
            Some("https://drive-mcp.example.com/mcp")
        );
        assert_eq!(as_form.get("scope").map(String::as_str), Some("read"));
        assert!(!as_form.contains_key("audience"));
        assert!(!as_form.contains_key("subject_token"));
    }

    #[tokio::test]
    async fn hop_two_omits_resource_and_scope_when_none_are_configured() {
        let server = MockServer::start().await;
        Mock::given(path("/idp/token"))
            .respond_with(id_jag_response())
            .mount(&server)
            .await;
        Mock::given(path("/as/token"))
            .respond_with(upstream_token_response())
            .expect(1)
            .mount(&server)
            .await;
        let mut cfg = drive_config(&server.uri());
        let drive = cfg["providers"]["drive"].as_object_mut().unwrap();
        drive.remove("resource");
        drive.remove("scopes");
        let plugin = OAuthIdJagPlugin::from_config_json(&cfg.to_string());
        CredentialIssuer::issue(&plugin, &identity_with_subject("tok"), "drive", &json!({}))
            .await
            .unwrap();
        let form = form_sent_to(&server, "/as/token").await;
        assert!(!form.contains_key("resource"), "{form:?}");
        assert!(!form.contains_key("scope"), "{form:?}");
    }

    #[tokio::test]
    async fn client_secret_basic_on_both_hops_uses_the_header_only() {
        let server = MockServer::start().await;
        // base64("mcpg:idp-secret") and base64("mcpg-drive:as-secret")
        Mock::given(method("POST"))
            .and(path("/idp/token"))
            .and(header("authorization", "Basic bWNwZzppZHAtc2VjcmV0"))
            .respond_with(id_jag_response())
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/as/token"))
            .and(header(
                "authorization",
                "Basic bWNwZy1kcml2ZTphcy1zZWNyZXQ=",
            ))
            .respond_with(upstream_token_response())
            .expect(1)
            .mount(&server)
            .await;
        let mut cfg = drive_config(&server.uri());
        cfg["providers"]["drive"]["client_auth"] = json!("client_secret_basic");
        cfg["providers"]["drive"]["redeem_client_secret"] = json!("as-secret");
        cfg["providers"]["drive"]["redeem_client_auth"] = json!("client_secret_basic");
        let plugin = OAuthIdJagPlugin::from_config_json(&cfg.to_string());
        CredentialIssuer::issue(&plugin, &identity_with_subject("tok"), "drive", &json!({}))
            .await
            .unwrap();
        for at in ["/idp/token", "/as/token"] {
            let form = form_sent_to(&server, at).await;
            assert!(!form.contains_key("client_id"), "{at}: {form:?}");
            assert!(!form.contains_key("client_secret"), "{at}: {form:?}");
        }
    }

    #[tokio::test]
    async fn explicit_client_secret_post_on_redeem_sends_the_secret_in_the_body() {
        let server = MockServer::start().await;
        Mock::given(path("/idp/token"))
            .respond_with(id_jag_response())
            .mount(&server)
            .await;
        Mock::given(path("/as/token"))
            .and(body_string_contains("client_id=mcpg-drive"))
            .and(body_string_contains("client_secret=as-secret"))
            .respond_with(upstream_token_response())
            .expect(1)
            .mount(&server)
            .await;
        let mut cfg = drive_config(&server.uri());
        cfg["providers"]["drive"]["redeem_client_secret"] = json!("as-secret");
        cfg["providers"]["drive"]["redeem_client_auth"] = json!("client_secret_post");
        let plugin = OAuthIdJagPlugin::from_config_json(&cfg.to_string());
        CredentialIssuer::issue(&plugin, &identity_with_subject("tok"), "drive", &json!({}))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn private_key_jwt_on_hop_one_targets_the_token_endpoint() {
        let server = MockServer::start().await;
        Mock::given(path("/idp/token"))
            .respond_with(id_jag_response())
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(path("/as/token"))
            .respond_with(upstream_token_response())
            .expect(1)
            .mount(&server)
            .await;
        let mut cfg = drive_config(&server.uri());
        let drive = cfg["providers"]["drive"].as_object_mut().unwrap();
        drive.remove("client_secret");
        drive.insert("client_auth".into(), json!("private_key_jwt"));
        drive.insert("private_key".into(), json!(RSA_PRIV));
        drive.insert("key_id".into(), json!("mcpg-2026"));
        drive.insert("signing_alg".into(), json!("RS256"));
        let plugin = OAuthIdJagPlugin::from_config_json(&cfg.to_string());
        CredentialIssuer::issue(&plugin, &identity_with_subject("tok"), "drive", &json!({}))
            .await
            .unwrap();

        let form = form_sent_to(&server, "/idp/token").await;
        assert_eq!(form.get("client_id").map(String::as_str), Some("mcpg"));
        assert_client_assertion(
            &form,
            Algorithm::RS256,
            &DecodingKey::from_rsa_pem(RSA_PUB.as_bytes()).unwrap(),
            "mcpg",
            &format!("{}/idp/token", server.uri()),
        );
        let header = jsonwebtoken::decode_header(&form["client_assertion"]).unwrap();
        assert_eq!(header.kid.as_deref(), Some("mcpg-2026"));
    }

    #[tokio::test]
    async fn private_key_jwt_on_hop_one_can_target_the_idp_issuer() {
        let server = MockServer::start().await;
        Mock::given(path("/idp/token"))
            .respond_with(id_jag_response())
            .mount(&server)
            .await;
        Mock::given(path("/as/token"))
            .respond_with(upstream_token_response())
            .mount(&server)
            .await;
        let mut cfg = drive_config(&server.uri());
        let drive = cfg["providers"]["drive"].as_object_mut().unwrap();
        drive.remove("client_secret");
        drive.insert("client_auth".into(), json!("private_key_jwt"));
        drive.insert("private_key".into(), json!(EC_PRIV));
        drive.insert("signing_alg".into(), json!("ES256"));
        drive.insert("assertion_audience".into(), json!("issuer"));
        drive.insert("idp_issuer".into(), json!("https://acme.okta.example"));
        let plugin = OAuthIdJagPlugin::from_config_json(&cfg.to_string());
        CredentialIssuer::issue(&plugin, &identity_with_subject("tok"), "drive", &json!({}))
            .await
            .unwrap();
        assert_client_assertion(
            &form_sent_to(&server, "/idp/token").await,
            Algorithm::ES256,
            &DecodingKey::from_ec_pem(EC_PUB.as_bytes()).unwrap(),
            "mcpg",
            "https://acme.okta.example",
        );
    }

    #[tokio::test]
    async fn private_key_jwt_on_redeem_uses_the_upstream_issuer() {
        let server = MockServer::start().await;
        Mock::given(path("/idp/token"))
            .respond_with(id_jag_response())
            .mount(&server)
            .await;
        Mock::given(path("/as/token"))
            .and(body_string_contains("assertion=the-id-jag-assertion"))
            .respond_with(upstream_token_response())
            .expect(1)
            .mount(&server)
            .await;
        let mut cfg = drive_config(&server.uri());
        let drive = cfg["providers"]["drive"].as_object_mut().unwrap();
        drive.insert("redeem_client_auth".into(), json!("private_key_jwt"));
        drive.insert("redeem_private_key".into(), json!(ED_PRIV));
        drive.insert("redeem_signing_alg".into(), json!("EdDSA"));
        drive.insert("redeem_assertion_audience".into(), json!("issuer"));
        let plugin = OAuthIdJagPlugin::from_config_json(&cfg.to_string());
        CredentialIssuer::issue(&plugin, &identity_with_subject("tok"), "drive", &json!({}))
            .await
            .unwrap();
        let form = form_sent_to(&server, "/as/token").await;
        assert_eq!(
            form.get("client_id").map(String::as_str),
            Some("mcpg-drive")
        );
        assert_client_assertion(
            &form,
            Algorithm::EdDSA,
            &DecodingKey::from_ed_pem(ED_PUB.as_bytes()).unwrap(),
            "mcpg-drive",
            "https://drive-mcp.example.com",
        );
    }

    #[tokio::test]
    async fn actor_token_is_sent_on_hop_one_only() {
        let server = MockServer::start().await;
        Mock::given(path("/idp/token"))
            .and(body_string_contains("actor_token=gateway-actor"))
            .and(body_string_contains(
                "actor_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Ajwt",
            ))
            .respond_with(id_jag_response())
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(path("/as/token"))
            .respond_with(upstream_token_response())
            .expect(1)
            .mount(&server)
            .await;
        let mut cfg = drive_config(&server.uri());
        cfg["providers"]["drive"]["actor_token"] = json!("gateway-actor");
        cfg["providers"]["drive"]["actor_token_type"] = json!("jwt");
        let plugin = OAuthIdJagPlugin::from_config_json(&cfg.to_string());
        CredentialIssuer::issue(&plugin, &identity_with_subject("tok"), "drive", &json!({}))
            .await
            .unwrap();
        assert!(
            !form_sent_to(&server, "/as/token")
                .await
                .contains_key("actor_token")
        );
    }

    #[tokio::test]
    async fn gateway_minted_caller_is_refused_without_any_request() {
        let server = MockServer::start().await;
        Mock::given(any())
            .respond_with(ResponseTemplate::new(500))
            .expect(0)
            .mount(&server)
            .await;
        let plugin = build_with_base(&server.uri());
        for provider in ["ema", "inspector_supervisor", "EMA"] {
            let mut identity = identity_with_subject("gateway-minted-token");
            identity.auth_provider = Some(provider.into());
            let err = CredentialIssuer::issue(&plugin, &identity, "drive", &json!({}))
                .await
                .unwrap_err();
            match err {
                CredentialError::Misconfigured { reason } => {
                    assert!(
                        reason.contains(
                            "a token minted by this gateway cannot be exchanged at the \
                             enterprise IdP"
                        ),
                        "{provider}: {reason}"
                    );
                    assert!(!reason.contains("gateway-minted-token"), "{reason}");
                }
                other => panic!("{provider}: unexpected error: {other:?}"),
            }
        }
    }

    /// An EMA caller whose IdP sets `principal_issuer` reports the SSO
    /// provider's `auth_provider`; the `token_issuer` attribute still marks
    /// its bearer as gateway-minted.
    #[tokio::test]
    async fn token_issuer_attribute_is_refused_without_any_request() {
        let server = MockServer::start().await;
        Mock::given(any())
            .respond_with(ResponseTemplate::new(500))
            .expect(0)
            .mount(&server)
            .await;
        let plugin = build_with_base(&server.uri());
        let sources = [None, Some("caller_bearer"), Some("IDP_VAULT"), Some("")];
        for source in sources {
            let mut identity = identity_with_subject("gateway-minted-token");
            identity.auth_provider = Some("oidc_oauth:https://acme.okta.com/oauth2/default".into());
            identity.attributes.insert(
                TOKEN_ISSUER_ATTR.to_owned(),
                "https://mcp.acme.example".to_owned(),
            );
            if let Some(source) = source {
                identity
                    .attributes
                    .insert(SUBJECT_TOKEN_SOURCE_ATTR.to_owned(), source.to_owned());
            }
            let err = CredentialIssuer::issue(&plugin, &identity, "drive", &json!({}))
                .await
                .unwrap_err();
            match err {
                CredentialError::Misconfigured { reason } => {
                    assert!(
                        reason.contains("a token minted by this gateway cannot be exchanged"),
                        "{source:?}: {reason}"
                    );
                    assert!(!reason.contains("gateway-minted-token"), "{reason}");
                }
                other => panic!("{source:?}: unexpected error: {other:?}"),
            }
        }
    }

    /// A caller the gateway minted a token for, whose subject token is the
    /// refresh token of their stored IdP sign-in at `base`'s IdP, issued
    /// to the provider's `client_id`.
    fn idp_vault_identity(base: &str, auth_provider: &str) -> PluginIdentity {
        let mut identity = identity_with_subject("idp-refresh-token");
        identity.auth_provider = Some(auth_provider.into());
        for (name, value) in [
            (TOKEN_ISSUER_ATTR, "https://mcp.acme.example".to_owned()),
            (
                SUBJECT_TOKEN_SOURCE_ATTR,
                SUBJECT_TOKEN_SOURCE_IDP_VAULT.to_owned(),
            ),
            (
                SUBJECT_TOKEN_TYPE_ATTR,
                "urn:ietf:params:oauth:token-type:refresh_token".to_owned(),
            ),
            (SUBJECT_TOKEN_ENDPOINT_ATTR, format!("{base}/idp/token")),
            (SUBJECT_TOKEN_CLIENT_ID_ATTR, "mcpg".to_owned()),
            (SUBJECT_TOKEN_ISSUER_ATTR, base.to_owned()),
            (
                "subject_token_binding",
                "vault:p:mcpg:refresh_token".to_owned(),
            ),
        ] {
            identity.attributes.insert(name.to_owned(), value);
        }
        identity
    }

    /// A subject token from the stored IdP sign-in is an IdP token, so it
    /// is exchanged for a caller whose bearer the gateway minted, at the
    /// token endpoint and with the client that issued it.
    #[tokio::test]
    async fn idp_vault_subject_token_is_exchanged_for_a_gateway_minted_caller() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/idp/token"))
            .and(body_string_contains("subject_token=idp-refresh-token"))
            .and(body_string_contains(
                "subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Arefresh_token",
            ))
            .respond_with(id_jag_response())
            .expect(3)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/as/token"))
            .respond_with(upstream_token_response())
            .expect(3)
            .mount(&server)
            .await;
        let plugin = build_with_base(&server.uri());
        for auth_provider in [
            "ema",
            "inspector_supervisor",
            "oidc_oauth:https://sso.example",
        ] {
            let identity = idp_vault_identity(&server.uri(), auth_provider);
            let cred = CredentialIssuer::issue(&plugin, &identity, "drive", &json!({}))
                .await
                .unwrap_or_else(|e| panic!("{auth_provider}: {e:?}"));
            assert_eq!(cred.value.as_deref(), Some("upstream-access-tok"));
        }
    }

    /// The stored sign-in goes to no other token endpoint than the one that
    /// issued it, with no other client, and from no other IdP than the
    /// provider's `idp_issuer`; a vault token without those attributes is
    /// refused too. Nothing is sent.
    #[tokio::test]
    async fn idp_vault_subject_token_bound_elsewhere_is_refused_without_any_request() {
        let server = MockServer::start().await;
        Mock::given(any())
            .respond_with(ResponseTemplate::new(500))
            .expect(0)
            .mount(&server)
            .await;
        let base = server.uri();
        let mut config = drive_config(&base);
        config["providers"]["drive"]["idp_issuer"] = json!(base);
        let plugin = OAuthIdJagPlugin::from_config_json(&config.to_string());
        let cases: [(&str, Option<String>); 7] = [
            (
                SUBJECT_TOKEN_ENDPOINT_ATTR,
                Some(format!("{base}/other/token")),
            ),
            (
                SUBJECT_TOKEN_ENDPOINT_ATTR,
                Some(format!("{base}/idp/token/")),
            ),
            (SUBJECT_TOKEN_ENDPOINT_ATTR, None),
            (
                SUBJECT_TOKEN_CLIENT_ID_ATTR,
                Some("another-client".to_owned()),
            ),
            (SUBJECT_TOKEN_CLIENT_ID_ATTR, None),
            (
                SUBJECT_TOKEN_ISSUER_ATTR,
                Some("https://other-idp.example".to_owned()),
            ),
            (SUBJECT_TOKEN_ISSUER_ATTR, None),
        ];
        for (attribute, value) in cases {
            let mut identity = idp_vault_identity(&base, "ema");
            match value {
                Some(ref value) => {
                    identity
                        .attributes
                        .insert(attribute.to_owned(), value.clone());
                }
                None => {
                    identity.attributes.remove(attribute);
                }
            }
            match CredentialIssuer::issue(&plugin, &identity, "drive", &json!({})).await {
                Err(CredentialError::Misconfigured { reason }) => {
                    assert!(
                        reason.contains("may only be exchanged at the IdP that issued it"),
                        "{attribute}={value:?}: {reason}"
                    );
                    assert!(!reason.contains("idp-refresh-token"), "{reason}");
                }
                other => panic!("{attribute}={value:?}: unexpected {other:?}"),
            }
        }
    }

    /// Without `idp_issuer` on the provider, the endpoint and client decide.
    #[tokio::test]
    async fn idp_vault_issuer_is_checked_only_when_the_provider_names_one() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/idp/token"))
            .respond_with(id_jag_response())
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/as/token"))
            .respond_with(upstream_token_response())
            .expect(1)
            .mount(&server)
            .await;
        let plugin = build_with_base(&server.uri());
        let mut identity = idp_vault_identity(&server.uri(), "ema");
        identity.attributes.insert(
            SUBJECT_TOKEN_ISSUER_ATTR.to_owned(),
            "https://any-idp.example".to_owned(),
        );
        CredentialIssuer::issue(&plugin, &identity, "drive", &json!({}))
            .await
            .expect("exchanged");
    }

    #[tokio::test]
    async fn unsupported_subject_token_type_attribute_is_refused_before_http() {
        let server = MockServer::start().await;
        Mock::given(any())
            .respond_with(ResponseTemplate::new(500))
            .expect(0)
            .mount(&server)
            .await;
        let plugin = build_with_base(&server.uri());
        let mut identity = identity_with_subject("tok");
        identity.attributes.insert(
            SUBJECT_TOKEN_TYPE_ATTR.to_owned(),
            "urn:example:custom".into(),
        );
        let err = CredentialIssuer::issue(&plugin, &identity, "drive", &json!({}))
            .await
            .unwrap_err();
        assert!(
            matches!(&err, CredentialError::Misconfigured { reason } if reason.contains("subject_token_type")),
            "{err:?}"
        );
    }

    #[tokio::test]
    async fn private_template_expansion_is_refused_before_either_hop() {
        // `10.*` probes as the hostname `10.probe`, so the template loads;
        // the target `10.0.0.1` then expands to a private IP literal, and
        // the egress check refuses it before the IdP sees the subject token.
        let cfg = json!({
            "target_template": {
                "allowed_targets": ["10.*"],
                "idp_token_url": "https://idp.example.com/token",
                "client_id": "mcpg-fleet",
                "subject_token_type": "id_token",
                "audience_template": "https://{target}",
                "redeem_token_url_template": "https://{target}/token"
            }
        });
        let plugin = OAuthIdJagPlugin::from_config_json(&cfg.to_string());
        let err = CredentialIssuer::issue(
            &plugin,
            &identity_with_subject("tok"),
            "10.0.0.1",
            &json!({}),
        )
        .await
        .unwrap_err();
        match err {
            CredentialError::Misconfigured { reason } => {
                assert!(reason.contains("redeem"), "{reason}");
                assert!(reason.contains("allow_private_network"), "{reason}");
            }
            other => panic!("unexpected error: {other:?}"),
        }
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
            .respond_with(id_jag_response())
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
    async fn redirect_from_the_idp_is_not_followed() {
        let server = MockServer::start().await;
        Mock::given(path("/idp/token"))
            .respond_with(ResponseTemplate::new(307).insert_header("location", "/collector"))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(path("/collector"))
            .respond_with(id_jag_response())
            .expect(0)
            .mount(&server)
            .await;
        let plugin = build_with_base(&server.uri());
        let err =
            CredentialIssuer::issue(&plugin, &identity_with_subject("tok"), "drive", &json!({}))
                .await
                .unwrap_err();
        match err {
            CredentialError::Misconfigured { reason } => {
                assert!(reason.contains("exchange"), "{reason}");
                assert!(reason.contains("redirects are not followed"), "{reason}");
                assert!(!reason.contains("/collector"), "{reason}");
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[tokio::test]
    async fn redirect_from_the_redeem_endpoint_is_misconfigured() {
        let server = MockServer::start().await;
        Mock::given(path("/idp/token"))
            .respond_with(id_jag_response())
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(path("/as/token"))
            .respond_with(ResponseTemplate::new(301).insert_header("location", "/as/v2/token"))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(path("/as/v2/token"))
            .respond_with(upstream_token_response())
            .expect(0)
            .mount(&server)
            .await;
        let plugin = build_with_base(&server.uri());
        let err =
            CredentialIssuer::issue(&plugin, &identity_with_subject("tok"), "drive", &json!({}))
                .await
                .unwrap_err();
        assert!(
            matches!(&err, CredentialError::Misconfigured { reason }
                if reason.contains("redeem") && reason.contains("configure the final URL")),
            "{err:?}"
        );
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
            .respond_with(id_jag_response())
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
        identity
            .attributes
            .insert(SUBJECT_TOKEN_TYPE_ATTR.to_owned(), "jwt".to_owned());
        let cred = CredentialIssuer::issue(&plugin, &identity, "drive", &json!({}))
            .await
            .unwrap();
        assert_eq!(cred.value.as_deref(), Some("upstream-access-tok"));
        // Default token_type when the AS omits it.
        assert_eq!(cred.part("token_type"), Some("Bearer"));
    }

    /// Build a plugin with NO exact providers — only a target template whose
    /// audience and redeem URL both expand the target.
    fn build_template_with_base(base: &str) -> OAuthIdJagPlugin {
        let cfg = json!({
            "target_template": {
                "allowed_targets": ["srv-*", "com.acme/*"],
                "idp_token_url": format!("{base}/idp/token"),
                "client_id": "mcpg-fleet",
                "client_secret": "idp-secret",
                "subject_token_type": "id_token",
                "audience_template": "https://{target_slug}.mcp.example.com",
                "scopes": ["read"],
                "redeem_token_url_template": format!("{base}/as/{{target_slug}}/token"),
                "allow_insecure_http": true,
                "allow_private_network": true
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
                "audience=https%3A%2F%2Fcom-acme-crm.mcp.example.com",
            ))
            .and(body_string_contains("client_id=mcpg-fleet"))
            .respond_with(id_jag_response())
            .expect(1)
            .mount(&server)
            .await;
        // Hop 2 lands on the per-target redeem path expanded from the template.
        Mock::given(method("POST"))
            .and(path("/as/com-acme-crm/token"))
            .and(body_string_contains("assertion=the-id-jag-assertion"))
            .respond_with(upstream_token_response())
            .expect(1)
            .mount(&server)
            .await;

        let plugin = build_template_with_base(&server.uri());
        let cred = CredentialIssuer::issue(
            &plugin,
            &identity_with_subject("caller-bearer-xyz"),
            "com.acme/crm",
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
        Mock::given(method("POST"))
            .and(path("/idp/token"))
            .respond_with(id_jag_response())
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
        // Discovery states the configured issuer with a trailing slash.
        let call_config = json!({
            "audience": "https://drive-mcp.example.com/",
            "resource": "https://discovered.example.com/mcp",
            "redeem_token_url": format!("{}/discovered/token", server.uri()),
            "issuer": "https://drive-mcp.example.com/",
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
        // Hop 1 carries the per-call spelling of the audience and the
        // per-call resource.
        let form = form_sent_to(&server, "/idp/token").await;
        assert_eq!(
            form.get("audience").map(String::as_str),
            Some("https://drive-mcp.example.com/")
        );
        assert_eq!(
            form.get("resource").map(String::as_str),
            Some("https://discovered.example.com/mcp")
        );
    }

    /// Discovery metadata is the upstream's document. An audience it names
    /// that is not the operator's must stop the flow before the IdP sees the
    /// subject token, including when the endpoint shares the operator's
    /// origin, as sibling authorization servers on one tenant do.
    #[tokio::test]
    async fn per_call_audience_for_another_authorization_server_is_refused_before_either_hop() {
        let server = MockServer::start().await;
        Mock::given(any())
            .respond_with(ResponseTemplate::new(500))
            .expect(0)
            .mount(&server)
            .await;
        let base = server.uri();
        let mut cfg = drive_config(&base);
        let drive = cfg["providers"]["drive"].as_object_mut().unwrap();
        drive.insert("audience".into(), json!(format!("{base}/oauth2/crm")));
        let token_url = format!("{base}/oauth2/crm/v1/token");
        drive.insert("redeem_token_url".into(), json!(token_url));
        drive.insert("redeem_client_auth".into(), json!("private_key_jwt"));
        drive.insert("redeem_private_key".into(), json!(ED_PRIV));
        drive.insert("redeem_signing_alg".into(), json!("EdDSA"));
        drive.insert("redeem_assertion_audience".into(), json!("issuer"));
        let plugin = OAuthIdJagPlugin::from_config_json(&cfg.to_string());
        for (audience, redeem_token_url) in [
            (
                format!("{base}/oauth2/billing"),
                format!("{base}/oauth2/billing/v1/token"),
            ),
            (
                "https://as.attacker.example".to_owned(),
                format!("{base}/oauth2/crm/v1/token"),
            ),
            (
                format!("{base}/oauth2/crm/extra"),
                format!("{base}/oauth2/crm/v1/token"),
            ),
        ] {
            let call_config = json!({
                "audience": audience,
                "redeem_token_url": redeem_token_url,
            });
            let err = CredentialIssuer::issue(
                &plugin,
                &identity_with_subject("caller-bearer-xyz"),
                "drive",
                &call_config,
            )
            .await
            .unwrap_err();
            match err {
                CredentialError::Misconfigured { reason } => {
                    assert!(
                        reason.contains("does not match the configured audience"),
                        "{audience}: {reason}"
                    );
                    assert!(!reason.contains("caller-bearer-xyz"), "{reason}");
                }
                other => panic!("{audience}: unexpected error: {other:?}"),
            }
        }
    }

    #[test]
    fn same_audience_tolerates_only_a_trailing_slash() {
        assert!(same_audience("https://as.example", "https://as.example"));
        assert!(same_audience("https://as.example/", "https://as.example"));
        assert!(same_audience("https://as.example", "https://as.example/"));
        for other in [
            "https://as.example//",
            "https://AS.example",
            "http://as.example",
            "https://as.example/tenant",
            "https://as.example.evil",
        ] {
            assert!(!same_audience(other, "https://as.example"), "{other}");
        }
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
