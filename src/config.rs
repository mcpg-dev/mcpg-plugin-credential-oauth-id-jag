//! Operator-supplied configuration schema for
//! `dev.mcpg.credential.oauth-id-jag`.
//!
//! ```yaml
//! plugins:
//!   - id: dev.mcpg.credential.oauth-id-jag
//!     config:
//!       providers:
//!         drive:
//!           idp_token_url: https://acme.okta.com/oauth2/v1/token    # hop 1
//!           client_id: mcpg-gateway
//!           client_auth: private_key_jwt          # or client_secret_basic / client_secret_post
//!           private_key: ${secret.IDP_SIGNING_KEY}
//!           key_id: mcpg-2026
//!           subject_token_type: id_token                           # required
//!           audience: https://auth.drive.example.com               # upstream AS issuer
//!           resource: https://drive-mcp.example.com/mcp            # optional (RFC 8707)
//!           scopes: [read]
//!           redeem_token_url: https://auth.drive.example.com/oauth2/token  # hop 2
//!           redeem_client_id: mcpg-drive
//!           redeem_client_secret: ${secret.DRIVE_CLIENT_SECRET}
//!           redeem_client_auth: client_secret_basic
//! ```
//!
//! The config structs deliberately do NOT set `deny_unknown_fields`: the
//! gateway injects a private `__mcpg_secret_refs` hint into the plugin spec for
//! secret-rotation scoping, and schema validation must tolerate it.

use std::collections::BTreeMap;

use serde::{Deserialize, Deserializer, Serialize};
use thiserror::Error;

use crate::client_auth::{
    AssertionAudience, ClientAuth, ClientAuthMethod, ClientAuthSettings, SigningAlg,
};
use crate::egress::{EgressPolicy, check_endpoint};

/// URN prefix of the RFC 8693 §3 token type identifiers.
const TOKEN_TYPE_URN_PREFIX: &str = "urn:ietf:params:oauth:token-type:";

/// Subject and actor token types the plugin sends, by short name.
const SUPPORTED_TOKEN_TYPES: [&str; 5] =
    ["id_token", "refresh_token", "saml2", "access_token", "jwt"];

/// Map a token type to its RFC 8693 URN. Accepts the short name
/// (`id_token`) or the URN; returns `None` for anything else.
pub fn normalize_token_type(value: &str) -> Option<String> {
    let value = value.trim();
    let short = value.strip_prefix(TOKEN_TYPE_URN_PREFIX).unwrap_or(value);
    SUPPORTED_TOKEN_TYPES
        .contains(&short)
        .then(|| format!("{TOKEN_TYPE_URN_PREFIX}{short}"))
}

fn unsupported_token_type<E: serde::de::Error>() -> E {
    E::custom(
        "unsupported token type; expected id_token, refresh_token, saml2, access_token or jwt \
         (short name or urn:ietf:params:oauth:token-type:<name>)",
    )
}

fn de_token_type<'de, D: Deserializer<'de>>(d: D) -> Result<String, D::Error> {
    let raw = String::deserialize(d)?;
    normalize_token_type(&raw).ok_or_else(unsupported_token_type)
}

fn de_opt_token_type<'de, D: Deserializer<'de>>(d: D) -> Result<Option<String>, D::Error> {
    Option::<String>::deserialize(d)?
        .map(|raw| normalize_token_type(&raw).ok_or_else(unsupported_token_type))
        .transpose()
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct IdJagConfig {
    /// Named ID-JAG providers. The map key is the provider name; callers
    /// reference an issued upstream token via the URI
    /// `cred://dev.mcpg.credential.oauth-id-jag/<name>`.
    #[serde(default)]
    pub providers: BTreeMap<String, IdJagProviderConfig>,

    /// Template fallback for targets with no exact `providers` entry:
    /// one block serves a whole fleet by expanding `{target}` or
    /// `{target_slug}` into the audience / redeem endpoint (registry
    /// auto-federation references `cred://…/<server-name>` per server).
    /// Exact entries always win.
    #[serde(default)]
    pub target_template: Option<IdJagTargetTemplate>,
}

/// Template provider expanded per requested target. In the `*_template`
/// fields `{target}` is replaced with the target string and `{target_slug}`
/// with [`target_slug`] of it; everything else is shared fleet config.
/// `allowed_targets` bounds what the template may mint for — an unbounded
/// template would let any dispatchable target name select an audience.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct IdJagTargetTemplate {
    /// Targets this template serves: exact match or a single
    /// trailing-`*` prefix glob. Required non-empty.
    pub allowed_targets: Vec<String>,

    /// Enterprise IdP token endpoint for hop 1 (shared by the fleet).
    pub idp_token_url: String,

    /// IdP issuer identifier, used as the client assertion audience when
    /// `assertion_audience: issuer`.
    #[serde(default)]
    pub idp_issuer: Option<String>,

    /// OAuth client id MCPG presents to the IdP.
    pub client_id: String,

    /// Optional IdP client secret (`${env.VAR}` / `${secret.NAME}` sourced).
    #[serde(default)]
    pub client_secret: Option<String>,

    /// Hop-1 client authentication. Unset: `client_id`, and `client_secret`
    /// when present, in the form body.
    #[serde(default)]
    pub client_auth: Option<ClientAuthMethod>,

    /// PEM private key for `client_auth: private_key_jwt`.
    #[serde(default)]
    pub private_key: Option<String>,

    /// `kid` header of the hop-1 client assertion.
    #[serde(default)]
    pub key_id: Option<String>,

    /// Hop-1 client assertion algorithm. Default RS256.
    #[serde(default)]
    pub signing_alg: Option<SigningAlg>,

    /// Hop-1 client assertion `aud`. Default the token endpoint URL.
    #[serde(default)]
    pub assertion_audience: Option<AssertionAudience>,

    /// Hop-1 `audience` with `{target}` / `{target_slug}` expansion — the
    /// upstream Resource Authorization Server's issuer per target.
    pub audience_template: String,

    /// Optional RFC 8707 `resource` with `{target}` / `{target_slug}` expansion.
    #[serde(default)]
    pub resource_template: Option<String>,

    /// Scopes to request (space-joined).
    #[serde(default)]
    pub scopes: Vec<String>,

    /// `subject_token_type` for hop 1. Required.
    #[serde(deserialize_with = "de_token_type")]
    pub subject_token_type: String,

    /// Optional RFC 8693 `actor_token` for hop 1.
    #[serde(default)]
    pub actor_token: Option<String>,

    /// `actor_token_type`; required with `actor_token`.
    #[serde(default, deserialize_with = "de_opt_token_type")]
    pub actor_token_type: Option<String>,

    /// Hop-2 upstream AS token endpoint with `{target}` / `{target_slug}`
    /// expansion. A raw `{target}` in the host only admits hostname-safe
    /// targets.
    pub redeem_token_url_template: String,

    /// Optional client id MCPG presents on hop 2.
    #[serde(default)]
    pub redeem_client_id: Option<String>,

    /// Optional hop-2 client secret. Requires `redeem_client_id`.
    #[serde(default)]
    pub redeem_client_secret: Option<String>,

    /// Hop-2 client authentication. Unset: `redeem_client_id` and
    /// `redeem_client_secret`, each when present, in the form body.
    #[serde(default)]
    pub redeem_client_auth: Option<ClientAuthMethod>,

    /// PEM private key for `redeem_client_auth: private_key_jwt`.
    #[serde(default)]
    pub redeem_private_key: Option<String>,

    /// `kid` header of the hop-2 client assertion.
    #[serde(default)]
    pub redeem_key_id: Option<String>,

    /// Hop-2 client assertion algorithm. Default RS256.
    #[serde(default)]
    pub redeem_signing_alg: Option<SigningAlg>,

    /// Hop-2 client assertion `aud`: the redeem endpoint URL (default) or
    /// the upstream AS issuer, which is `audience`.
    #[serde(default)]
    pub redeem_assertion_audience: Option<AssertionAudience>,

    /// Permit plain-http token endpoints. Local development only.
    #[serde(default)]
    pub allow_insecure_http: bool,

    /// Permit token endpoints on private, loopback or link-local addresses.
    #[serde(default)]
    pub allow_private_network: bool,

    /// Per-request timeout applied to each hop. Default 5 000.
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
}

/// Why a template does not expand for a target.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ExpandError {
    #[error("target `{0}` is not in target_template.allowed_targets")]
    NotAllowed(String),
    #[error(
        "target `{0}` has characters that are not valid in a hostname, and \
         redeem_token_url_template puts {{target}} in the host; use {{target_slug}}"
    )]
    UnsafeHost(String),
    #[error("target `{0}` has no hostname characters for {{target_slug}}")]
    EmptySlug(String),
}

/// `target` reduced to hostname-safe characters: every character outside
/// `[A-Za-z0-9-]` (`/` and `.` included) becomes `-`, and leading or
/// trailing `-` are dropped. `com.acme/crm` becomes `com-acme-crm`.
pub fn target_slug(target: &str) -> String {
    let mapped: String = target
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' {
                c
            } else {
                '-'
            }
        })
        .collect();
    mapped.trim_matches('-').to_owned()
}

fn substitute(template: &str, target: &str, slug: &str) -> String {
    template
        .replace("{target_slug}", slug)
        .replace("{target}", target)
}

/// Whether a raw `{target}` sits in the authority of a URL template, where
/// a `/`, `@` or `:` in the target would move the request to another host.
fn target_in_authority(template: &str) -> bool {
    let rest = template.split_once("://").map_or(template, |(_, r)| r);
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    rest[..end].contains("{target}")
}

fn is_hostname_safe(target: &str) -> bool {
    !target.is_empty()
        && target
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.')
}

/// A representative target for an `allowed_targets` pattern.
fn probe_target(pattern: &str) -> String {
    match pattern.strip_suffix('*') {
        Some(prefix) => format!("{prefix}probe"),
        None => pattern.to_owned(),
    }
}

impl IdJagTargetTemplate {
    /// Expand the template for `target`.
    pub fn expand(&self, target: &str) -> Result<IdJagProviderConfig, ExpandError> {
        if !self.allowed_targets.iter().any(|p| glob_match(p, target)) {
            return Err(ExpandError::NotAllowed(target.to_owned()));
        }
        let slug = target_slug(target);
        let uses_slug = [
            Some(&self.audience_template),
            self.resource_template.as_ref(),
            Some(&self.redeem_token_url_template),
        ]
        .into_iter()
        .flatten()
        .any(|t| t.contains("{target_slug}"));
        if uses_slug && slug.is_empty() {
            return Err(ExpandError::EmptySlug(target.to_owned()));
        }
        if target_in_authority(&self.redeem_token_url_template) && !is_hostname_safe(target) {
            return Err(ExpandError::UnsafeHost(target.to_owned()));
        }
        let sub = |s: &str| substitute(s, target, &slug);
        Ok(IdJagProviderConfig {
            idp_token_url: self.idp_token_url.clone(),
            idp_issuer: self.idp_issuer.clone(),
            client_id: self.client_id.clone(),
            client_secret: self.client_secret.clone(),
            client_auth: self.client_auth,
            private_key: self.private_key.clone(),
            key_id: self.key_id.clone(),
            signing_alg: self.signing_alg,
            assertion_audience: self.assertion_audience,
            audience: sub(&self.audience_template),
            resource: self.resource_template.as_deref().map(sub),
            scopes: self.scopes.clone(),
            subject_token_type: self.subject_token_type.clone(),
            actor_token: self.actor_token.clone(),
            actor_token_type: self.actor_token_type.clone(),
            redeem_token_url: sub(&self.redeem_token_url_template),
            redeem_client_id: self.redeem_client_id.clone(),
            redeem_client_secret: self.redeem_client_secret.clone(),
            redeem_client_auth: self.redeem_client_auth,
            redeem_private_key: self.redeem_private_key.clone(),
            redeem_key_id: self.redeem_key_id.clone(),
            redeem_signing_alg: self.redeem_signing_alg,
            redeem_assertion_audience: self.redeem_assertion_audience,
            allow_insecure_http: self.allow_insecure_http,
            allow_private_network: self.allow_private_network,
            timeout_ms: self.timeout_ms,
        })
    }

    /// The expansion for a representative target of the first
    /// `allowed_targets` pattern. Client authentication does not depend on
    /// the target, so this is what it is compiled from.
    pub(crate) fn probe(&self) -> Result<IdJagProviderConfig, ExpandError> {
        let pattern = self.allowed_targets.first().map_or("", String::as_str);
        self.expand(&probe_target(pattern))
    }
}

/// Minimal glob: exact match, `*` (all), or a single trailing-`*`
/// prefix glob — the same semantics the gateway's filters use.
fn glob_match(pattern: &str, name: &str) -> bool {
    match pattern.strip_suffix('*') {
        Some(prefix) => name.starts_with(prefix),
        None => pattern == name,
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct IdJagProviderConfig {
    /// Enterprise IdP token endpoint for hop 1 (RFC 8693 token-exchange).
    pub idp_token_url: String,

    /// IdP issuer identifier, used as the client assertion audience when
    /// `assertion_audience: issuer`.
    #[serde(default)]
    pub idp_issuer: Option<String>,

    /// OAuth client id MCPG presents to the IdP (the gateway's confidential
    /// client at the enterprise IdP).
    pub client_id: String,

    /// Optional client secret for the IdP client. Source from a secret backend
    /// via `${env.VAR}` / `${secret.NAME}` so the literal never appears in
    /// YAML or logs.
    #[serde(default)]
    pub client_secret: Option<String>,

    /// Hop-1 client authentication. Unset: `client_id`, and `client_secret`
    /// when present, in the form body.
    #[serde(default)]
    pub client_auth: Option<ClientAuthMethod>,

    /// PEM private key for `client_auth: private_key_jwt`.
    #[serde(default)]
    pub private_key: Option<String>,

    /// `kid` header of the hop-1 client assertion.
    #[serde(default)]
    pub key_id: Option<String>,

    /// Hop-1 client assertion algorithm. Default RS256.
    #[serde(default)]
    pub signing_alg: Option<SigningAlg>,

    /// Hop-1 client assertion `aud`. Default the token endpoint URL.
    #[serde(default)]
    pub assertion_audience: Option<AssertionAudience>,

    /// `audience` for hop 1 — the upstream Resource Authorization Server's
    /// issuer the ID-JAG is minted for. Required and non-empty.
    pub audience: String,

    /// Optional `resource` (RFC 8707) — the upstream MCP server the token is
    /// for.
    #[serde(default)]
    pub resource: Option<String>,

    /// Scopes to request (space-joined, RFC 6749 §3.3).
    #[serde(default)]
    pub scopes: Vec<String>,

    /// `subject_token_type` for hop 1 (RFC 8693 §2.1), as a short name or
    /// URN. Required. The caller may override it per request via
    /// `identity.attributes["subject_token_type"]`.
    #[serde(deserialize_with = "de_token_type")]
    pub subject_token_type: String,

    /// Optional RFC 8693 `actor_token` for hop 1.
    #[serde(default)]
    pub actor_token: Option<String>,

    /// `actor_token_type`; required with `actor_token`.
    #[serde(default, deserialize_with = "de_opt_token_type")]
    pub actor_token_type: Option<String>,

    /// Upstream AS token endpoint for hop 2 (RFC 7523 `jwt-bearer` redemption).
    pub redeem_token_url: String,

    /// Optional client id MCPG presents to the upstream AS on hop 2.
    #[serde(default)]
    pub redeem_client_id: Option<String>,

    /// Optional client secret for the upstream-AS client. Requires
    /// `redeem_client_id`.
    #[serde(default)]
    pub redeem_client_secret: Option<String>,

    /// Hop-2 client authentication. Unset: `redeem_client_id` and
    /// `redeem_client_secret`, each when present, in the form body.
    #[serde(default)]
    pub redeem_client_auth: Option<ClientAuthMethod>,

    /// PEM private key for `redeem_client_auth: private_key_jwt`.
    #[serde(default)]
    pub redeem_private_key: Option<String>,

    /// `kid` header of the hop-2 client assertion.
    #[serde(default)]
    pub redeem_key_id: Option<String>,

    /// Hop-2 client assertion algorithm. Default RS256.
    #[serde(default)]
    pub redeem_signing_alg: Option<SigningAlg>,

    /// Hop-2 client assertion `aud`: the redeem endpoint URL (default) or
    /// the upstream AS issuer, which is `audience`.
    #[serde(default)]
    pub redeem_assertion_audience: Option<AssertionAudience>,

    /// Permit plain-http token endpoints. Local development only.
    #[serde(default)]
    pub allow_insecure_http: bool,

    /// Permit token endpoints on private, loopback or link-local addresses.
    #[serde(default)]
    pub allow_private_network: bool,

    /// Per-request timeout applied to each hop. Default 5 000.
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
}

impl IdJagProviderConfig {
    pub(crate) fn egress(&self) -> EgressPolicy {
        EgressPolicy {
            allow_insecure_http: self.allow_insecure_http,
            allow_private_network: self.allow_private_network,
        }
    }

    /// Client authentication for hop 1, at the IdP.
    pub(crate) fn idp_client_auth(&self) -> Result<ClientAuth, String> {
        ClientAuth::compile(&ClientAuthSettings {
            prefix: "",
            method: self.client_auth,
            client_id: Some(self.client_id.as_str()),
            client_secret: self.client_secret.as_deref(),
            private_key: self.private_key.as_deref(),
            key_id: self.key_id.as_deref(),
            signing_alg: self.signing_alg,
            assertion_audience: self.assertion_audience,
            issuer_available: self
                .idp_issuer
                .as_deref()
                .is_some_and(|i| !i.trim().is_empty()),
            issuer_setting: "idp_issuer",
        })
    }

    /// Client authentication for hop 2, at the upstream AS.
    pub(crate) fn redeem_client_auth(&self) -> Result<ClientAuth, String> {
        ClientAuth::compile(&ClientAuthSettings {
            prefix: "redeem_",
            method: self.redeem_client_auth,
            client_id: self.redeem_client_id.as_deref(),
            client_secret: self.redeem_client_secret.as_deref(),
            private_key: self.redeem_private_key.as_deref(),
            key_id: self.redeem_key_id.as_deref(),
            signing_alg: self.redeem_signing_alg,
            assertion_audience: self.redeem_assertion_audience,
            issuer_available: true,
            issuer_setting: "audience",
        })
    }
}

fn default_timeout_ms() -> u64 {
    5_000
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("invalid credential.oauth-id-jag config JSON: {0}")]
    InvalidJson(#[from] serde_json::Error),
    #[error("credential.oauth-id-jag: configure `providers` and/or a `target_template`")]
    EmptyProviders,
    #[error("credential.oauth-id-jag: target_template.allowed_targets must be non-empty")]
    EmptyAllowedTargets,
    #[error("credential.oauth-id-jag: target_template: {0}")]
    Template(#[from] ExpandError),
    #[error("credential.oauth-id-jag: provider `{name}` idp_token_url is empty")]
    EmptyIdpTokenUrl { name: String },
    #[error("credential.oauth-id-jag: provider `{name}` {field} {reason}")]
    InvalidEndpoint {
        name: String,
        field: &'static str,
        reason: String,
    },
    #[error("credential.oauth-id-jag: provider `{name}` client_id is empty")]
    EmptyClientId { name: String },
    #[error("credential.oauth-id-jag: provider `{name}` audience is empty")]
    EmptyAudience { name: String },
    #[error("credential.oauth-id-jag: provider `{name}` redeem_token_url is empty")]
    EmptyRedeemTokenUrl { name: String },
    #[error(
        "credential.oauth-id-jag: provider `{name}` redeem_client_secret requires redeem_client_id"
    )]
    RedeemSecretWithoutClientId { name: String },
    #[error("credential.oauth-id-jag: provider `{name}` {reason}")]
    ClientAuth { name: String, reason: String },
    #[error(
        "credential.oauth-id-jag: provider `{name}` actor_token and actor_token_type go together"
    )]
    ActorTokenPairing { name: String },
    #[error(
        "credential.oauth-id-jag: provider `{name}` timeout_ms={timeout}; must be 100..=60_000"
    )]
    InvalidTimeoutMs { name: String, timeout: u64 },
}

impl IdJagConfig {
    pub fn parse(s: &str) -> Result<Self, ConfigError> {
        let cfg: Self = serde_json::from_str(s)?;
        cfg.validate()?;
        Ok(cfg)
    }

    fn validate(&self) -> Result<(), ConfigError> {
        if self.providers.is_empty() && self.target_template.is_none() {
            return Err(ConfigError::EmptyProviders);
        }
        if let Some(template) = &self.target_template {
            if template.allowed_targets.is_empty() {
                return Err(ConfigError::EmptyAllowedTargets);
            }
            // Every pattern's representative target must expand, and the
            // expansion is exactly a provider, so the provider rules apply.
            for pattern in &template.allowed_targets {
                let probe = template.expand(&probe_target(pattern))?;
                Self::validate_provider("target_template", &probe)?;
            }
            Self::validate_client_auth("target_template", &template.probe()?)?;
        }
        for (name, provider) in &self.providers {
            Self::validate_provider(name, provider)?;
            Self::validate_client_auth(name, provider)?;
        }
        Ok(())
    }

    fn validate_provider(name: &str, provider: &IdJagProviderConfig) -> Result<(), ConfigError> {
        let endpoint = |field: &'static str, url: &str| {
            check_endpoint(url, provider.egress()).map_err(|reason| ConfigError::InvalidEndpoint {
                name: name.to_owned(),
                field,
                reason,
            })
        };
        if provider.idp_token_url.trim().is_empty() {
            return Err(ConfigError::EmptyIdpTokenUrl {
                name: name.to_owned(),
            });
        }
        endpoint("idp_token_url", &provider.idp_token_url)?;
        if provider.client_id.trim().is_empty() {
            return Err(ConfigError::EmptyClientId {
                name: name.to_owned(),
            });
        }
        if provider.audience.trim().is_empty() {
            return Err(ConfigError::EmptyAudience {
                name: name.to_owned(),
            });
        }
        if provider.redeem_token_url.trim().is_empty() {
            return Err(ConfigError::EmptyRedeemTokenUrl {
                name: name.to_owned(),
            });
        }
        endpoint("redeem_token_url", &provider.redeem_token_url)?;
        // A redeem client secret is meaningless without the id it authenticates.
        let has_redeem_secret = provider
            .redeem_client_secret
            .as_deref()
            .is_some_and(|s| !s.is_empty());
        let missing_redeem_id = provider
            .redeem_client_id
            .as_deref()
            .is_none_or(|s| s.trim().is_empty());
        if has_redeem_secret && missing_redeem_id {
            return Err(ConfigError::RedeemSecretWithoutClientId {
                name: name.to_owned(),
            });
        }
        let has_actor_token = provider
            .actor_token
            .as_deref()
            .is_some_and(|t| !t.trim().is_empty());
        if has_actor_token != provider.actor_token_type.is_some() {
            return Err(ConfigError::ActorTokenPairing {
                name: name.to_owned(),
            });
        }
        if provider.timeout_ms < 100 || provider.timeout_ms > 60_000 {
            return Err(ConfigError::InvalidTimeoutMs {
                name: name.to_owned(),
                timeout: provider.timeout_ms,
            });
        }
        Ok(())
    }

    fn validate_client_auth(name: &str, provider: &IdJagProviderConfig) -> Result<(), ConfigError> {
        let err = |reason| ConfigError::ClientAuth {
            name: name.to_owned(),
            reason,
        };
        provider.idp_client_auth().map_err(err)?;
        provider.redeem_client_auth().map_err(err)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const RSA_PRIV: &str = include_str!("../tests/fixtures/rsa_priv.pem");

    fn minimal() -> serde_json::Value {
        json!({
            "providers": {
                "drive": {
                    "idp_token_url": "https://idp.example.com/oauth2/token",
                    "client_id": "mcpg",
                    "subject_token_type": "id_token",
                    "audience": "https://drive-mcp.example.com",
                    "redeem_token_url": "https://drive-mcp.example.com/oauth2/token"
                }
            }
        })
    }

    fn parse_err(v: &serde_json::Value) -> ConfigError {
        IdJagConfig::parse(&v.to_string()).unwrap_err()
    }

    #[test]
    fn parses_minimal_with_defaults() {
        let cfg = IdJagConfig::parse(&minimal().to_string()).unwrap();
        let p = cfg.providers.get("drive").unwrap();
        assert_eq!(
            p.subject_token_type,
            "urn:ietf:params:oauth:token-type:id_token"
        );
        assert_eq!(p.timeout_ms, 5_000);
        assert!(p.client_secret.is_none());
        assert!(p.client_auth.is_none());
        assert!(p.redeem_client_auth.is_none());
        assert!(p.resource.is_none());
        assert!(p.scopes.is_empty());
        assert!(!p.allow_insecure_http);
        assert!(!p.allow_private_network);
    }

    #[test]
    fn tolerates_unknown_fields() {
        // The gateway injects a private `__mcpg_secret_refs` key into the spec;
        // schema validation must not reject it.
        let mut v = minimal();
        v["__mcpg_secret_refs"] = json!(["cred://x/y"]);
        assert!(IdJagConfig::parse(&v.to_string()).is_ok());
    }

    #[test]
    fn rejects_empty_providers() {
        let v = json!({ "providers": {} });
        assert!(matches!(parse_err(&v), ConfigError::EmptyProviders));
    }

    #[test]
    fn subject_token_type_is_required() {
        let mut v = minimal();
        v["providers"]["drive"]
            .as_object_mut()
            .unwrap()
            .remove("subject_token_type");
        let err = parse_err(&v).to_string();
        assert!(err.contains("subject_token_type"), "{err}");
    }

    #[test]
    fn subject_token_type_accepts_short_names_and_urns() {
        for (given, urn) in [
            ("id_token", "urn:ietf:params:oauth:token-type:id_token"),
            (
                "refresh_token",
                "urn:ietf:params:oauth:token-type:refresh_token",
            ),
            ("saml2", "urn:ietf:params:oauth:token-type:saml2"),
            (
                "access_token",
                "urn:ietf:params:oauth:token-type:access_token",
            ),
            (
                "urn:ietf:params:oauth:token-type:jwt",
                "urn:ietf:params:oauth:token-type:jwt",
            ),
        ] {
            let mut v = minimal();
            v["providers"]["drive"]["subject_token_type"] = json!(given);
            let cfg = IdJagConfig::parse(&v.to_string()).unwrap();
            assert_eq!(cfg.providers["drive"].subject_token_type, urn);
        }
    }

    #[test]
    fn subject_token_type_rejects_unknown_values() {
        for bad in [
            "id-jag",
            "urn:ietf:params:oauth:token-type:id-jag",
            "bearer",
            "",
        ] {
            let mut v = minimal();
            v["providers"]["drive"]["subject_token_type"] = json!(bad);
            assert!(
                matches!(parse_err(&v), ConfigError::InvalidJson(_)),
                "{bad:?} must be rejected"
            );
        }
    }

    #[test]
    fn http_endpoints_need_allow_insecure_http() {
        let mut v = minimal();
        v["providers"]["drive"]["idp_token_url"] = json!("http://idp.example.com/token");
        match parse_err(&v) {
            ConfigError::InvalidEndpoint { field, reason, .. } => {
                assert_eq!(field, "idp_token_url");
                assert!(reason.contains("allow_insecure_http"), "{reason}");
            }
            other => panic!("unexpected: {other}"),
        }
        v["providers"]["drive"]["allow_insecure_http"] = json!(true);
        assert!(IdJagConfig::parse(&v.to_string()).is_ok());
    }

    #[test]
    fn private_endpoints_need_allow_private_network() {
        let mut v = minimal();
        v["providers"]["drive"]["redeem_token_url"] = json!("https://10.0.0.7/token");
        match parse_err(&v) {
            ConfigError::InvalidEndpoint { field, reason, .. } => {
                assert_eq!(field, "redeem_token_url");
                assert!(reason.contains("allow_private_network"), "{reason}");
            }
            other => panic!("unexpected: {other}"),
        }
        v["providers"]["drive"]["allow_private_network"] = json!(true);
        assert!(IdJagConfig::parse(&v.to_string()).is_ok());
    }

    #[test]
    fn rejects_unknown_url_schemes() {
        for (field, url) in [
            ("idp_token_url", "file:///etc/oauth"),
            ("redeem_token_url", "ftp://as.example.com/token"),
        ] {
            let mut v = minimal();
            v["providers"]["drive"][field] = json!(url);
            v["providers"]["drive"]["allow_insecure_http"] = json!(true);
            assert!(
                matches!(parse_err(&v), ConfigError::InvalidEndpoint { .. }),
                "{field}={url}"
            );
        }
    }

    fn template_only() -> serde_json::Value {
        json!({
            "target_template": {
                "allowed_targets": ["com.acme/*"],
                "idp_token_url": "https://idp.acme.example/oauth2/token",
                "client_id": "mcpg-fleet",
                "subject_token_type": "id_token",
                "audience_template": "https://{target_slug}.mcp.acme.example",
                "resource_template": "https://mcp.acme.example/{target}",
                "redeem_token_url_template": "https://{target_slug}.mcp.acme.example/oauth2/token"
            }
        })
    }

    #[test]
    fn target_slug_maps_non_hostname_characters() {
        assert_eq!(target_slug("com.acme/crm"), "com-acme-crm");
        assert_eq!(
            target_slug("io.github.foo/bar_baz"),
            "io-github-foo-bar-baz"
        );
        assert_eq!(target_slug("/srv.1/"), "srv-1");
        assert_eq!(target_slug("xn--bcher-kva"), "xn--bcher-kva");
        assert_eq!(target_slug("./"), "");
    }

    #[test]
    fn template_only_config_validates_and_expands() {
        let cfg = IdJagConfig::parse(&template_only().to_string()).unwrap();
        let template = cfg.target_template.as_ref().unwrap();
        let expanded = template.expand("com.acme/crm").expect("allowlisted target");
        assert_eq!(expanded.audience, "https://com-acme-crm.mcp.acme.example");
        assert_eq!(
            expanded.resource.as_deref(),
            Some("https://mcp.acme.example/com.acme/crm")
        );
        assert_eq!(
            expanded.redeem_token_url,
            "https://com-acme-crm.mcp.acme.example/oauth2/token"
        );
        assert_eq!(expanded.client_id, "mcpg-fleet");
        assert_eq!(expanded.timeout_ms, 5_000);

        // Outside the allowlist: no expansion.
        assert_eq!(
            template.expand("io.github.evil/exfil"),
            Err(ExpandError::NotAllowed("io.github.evil/exfil".into()))
        );
    }

    #[test]
    fn raw_target_in_the_redeem_host_admits_only_hostname_safe_targets() {
        let mut v = template_only();
        v["target_template"]["allowed_targets"] = json!(["srv-*"]);
        v["target_template"]["redeem_token_url_template"] =
            json!("https://{target}.mcp.acme.example/oauth2/token");
        let cfg = IdJagConfig::parse(&v.to_string()).unwrap();
        let template = cfg.target_template.as_ref().unwrap();
        assert_eq!(
            template.expand("srv-crm").unwrap().redeem_token_url,
            "https://srv-crm.mcp.acme.example/oauth2/token"
        );
        for hostile in ["srv-x.evil.test/", "srv-a@evil.test", "srv-x:1#"] {
            assert_eq!(
                template.expand(hostile),
                Err(ExpandError::UnsafeHost(hostile.into())),
                "{hostile}"
            );
        }
    }

    #[test]
    fn raw_target_in_the_redeem_host_with_a_slash_pattern_fails_at_load() {
        let mut v = template_only();
        v["target_template"]["redeem_token_url_template"] =
            json!("https://{target}.mcp.acme.example/oauth2/token");
        assert!(matches!(
            parse_err(&v),
            ConfigError::Template(ExpandError::UnsafeHost(_))
        ));
    }

    #[test]
    fn raw_target_in_the_redeem_path_keeps_the_host_fixed() {
        let mut v = template_only();
        v["target_template"]["redeem_token_url_template"] =
            json!("https://as.acme.example/{target}/token");
        let cfg = IdJagConfig::parse(&v.to_string()).unwrap();
        let expanded = cfg
            .target_template
            .as_ref()
            .unwrap()
            .expand("com.acme/crm")
            .unwrap();
        assert_eq!(
            expanded.redeem_token_url,
            "https://as.acme.example/com.acme/crm/token"
        );
    }

    #[test]
    fn wildcard_allowlist_validates() {
        let mut v = template_only();
        v["target_template"]["allowed_targets"] = json!(["*"]);
        assert!(IdJagConfig::parse(&v.to_string()).is_ok());
    }

    #[test]
    fn template_requires_allowed_targets() {
        let mut v = template_only();
        v["target_template"]["allowed_targets"] = json!([]);
        assert!(matches!(parse_err(&v), ConfigError::EmptyAllowedTargets));
    }

    #[test]
    fn template_url_schemes_validated() {
        let mut v = template_only();
        v["target_template"]["redeem_token_url_template"] = json!("ftp://{target_slug}/token");
        assert!(matches!(parse_err(&v), ConfigError::InvalidEndpoint { .. }));
    }

    #[test]
    fn exact_provider_and_template_coexist() {
        let mut v = template_only();
        v["providers"] = minimal()["providers"].clone();
        let cfg = IdJagConfig::parse(&v.to_string()).unwrap();
        assert_eq!(cfg.providers.len(), 1);
        assert!(cfg.target_template.is_some());
    }

    #[test]
    fn rejects_missing_audience() {
        let mut v = minimal();
        v["providers"]["drive"]["audience"] = json!("");
        assert!(matches!(parse_err(&v), ConfigError::EmptyAudience { .. }));
    }

    #[test]
    fn rejects_missing_redeem_token_url() {
        let mut v = minimal();
        v["providers"]["drive"]["redeem_token_url"] = json!("");
        assert!(matches!(
            parse_err(&v),
            ConfigError::EmptyRedeemTokenUrl { .. }
        ));
    }

    #[test]
    fn rejects_empty_client_id() {
        let mut v = minimal();
        v["providers"]["drive"]["client_id"] = json!("");
        assert!(matches!(parse_err(&v), ConfigError::EmptyClientId { .. }));
    }

    #[test]
    fn rejects_redeem_secret_without_client_id() {
        let mut v = minimal();
        v["providers"]["drive"]["redeem_client_secret"] = json!("shhh");
        assert!(matches!(
            parse_err(&v),
            ConfigError::RedeemSecretWithoutClientId { .. }
        ));
    }

    #[test]
    fn rejects_oversize_timeout() {
        let mut v = minimal();
        v["providers"]["drive"]["timeout_ms"] = json!(120_000);
        assert!(matches!(
            parse_err(&v),
            ConfigError::InvalidTimeoutMs { .. }
        ));
    }

    #[test]
    fn actor_token_needs_its_type_and_vice_versa() {
        let mut v = minimal();
        v["providers"]["drive"]["actor_token"] = json!("gateway-actor");
        assert!(matches!(
            parse_err(&v),
            ConfigError::ActorTokenPairing { .. }
        ));
        v["providers"]["drive"]["actor_token_type"] = json!("jwt");
        let cfg = IdJagConfig::parse(&v.to_string()).unwrap();
        assert_eq!(
            cfg.providers["drive"].actor_token_type.as_deref(),
            Some("urn:ietf:params:oauth:token-type:jwt")
        );
        v["providers"]["drive"]
            .as_object_mut()
            .unwrap()
            .remove("actor_token");
        assert!(matches!(
            parse_err(&v),
            ConfigError::ActorTokenPairing { .. }
        ));
    }

    #[test]
    fn client_auth_per_hop_is_validated() {
        let mut v = minimal();
        v["providers"]["drive"]["client_auth"] = json!("client_secret_basic");
        match parse_err(&v) {
            ConfigError::ClientAuth { reason, .. } => {
                assert!(reason.contains("client_secret"), "{reason}");
            }
            other => panic!("unexpected: {other}"),
        }
        v["providers"]["drive"]["client_secret"] = json!("idp-secret");
        v["providers"]["drive"]["redeem_client_auth"] = json!("private_key_jwt");
        match parse_err(&v) {
            ConfigError::ClientAuth { reason, .. } => {
                assert!(reason.contains("redeem_client_id"), "{reason}");
            }
            other => panic!("unexpected: {other}"),
        }
        v["providers"]["drive"]["redeem_client_id"] = json!("mcpg-drive");
        v["providers"]["drive"]["redeem_private_key"] = json!(RSA_PRIV);
        v["providers"]["drive"]["redeem_assertion_audience"] = json!("issuer");
        assert!(IdJagConfig::parse(&v.to_string()).is_ok());
    }

    #[test]
    fn issuer_audience_on_hop_one_needs_idp_issuer() {
        let mut v = minimal();
        v["providers"]["drive"]["client_auth"] = json!("private_key_jwt");
        v["providers"]["drive"]["private_key"] = json!(RSA_PRIV);
        v["providers"]["drive"]["assertion_audience"] = json!("issuer");
        match parse_err(&v) {
            ConfigError::ClientAuth { reason, .. } => {
                assert!(reason.contains("idp_issuer"), "{reason}");
            }
            other => panic!("unexpected: {other}"),
        }
        v["providers"]["drive"]["idp_issuer"] = json!("https://idp.example.com");
        assert!(IdJagConfig::parse(&v.to_string()).is_ok());
    }

    #[test]
    fn unknown_client_auth_and_alg_are_rejected() {
        let mut v = minimal();
        v["providers"]["drive"]["client_auth"] = json!("tls_client_auth");
        assert!(matches!(parse_err(&v), ConfigError::InvalidJson(_)));
        let mut v = minimal();
        v["providers"]["drive"]["client_auth"] = json!("private_key_jwt");
        v["providers"]["drive"]["private_key"] = json!(RSA_PRIV);
        v["providers"]["drive"]["signing_alg"] = json!("HS256");
        assert!(matches!(parse_err(&v), ConfigError::InvalidJson(_)));
    }

    #[test]
    fn config_errors_never_echo_secrets() {
        let mut v = minimal();
        v["providers"]["drive"]["client_auth"] = json!("private_key_jwt");
        v["providers"]["drive"]["private_key"] = json!(RSA_PRIV);
        v["providers"]["drive"]["client_secret"] = json!("idp-secret-VALUE");
        let err = parse_err(&v).to_string();
        assert!(
            !err.contains("idp-secret-VALUE") && !err.contains("BEGIN"),
            "{err}"
        );
    }
}
