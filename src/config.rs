//! Operator-supplied configuration schema for
//! `dev.mcpg.credential.oauth-id-jag`.
//!
//! ```yaml
//! plugins:
//!   - id: dev.mcpg.credential.oauth-id-jag
//!     config:
//!       providers:
//!         drive:
//!           idp_token_url: https://idp.example.com/oauth2/token    # hop 1
//!           client_id: mcpg-gateway
//!           client_secret: ${env.IDP_CLIENT_SECRET}                # optional
//!           audience: https://drive-mcp.example.com                # upstream AS issuer
//!           resource: https://drive-mcp.example.com/mcp            # optional (RFC 8707)
//!           scopes: [read]
//!           redeem_token_url: https://drive-mcp.example.com/oauth2/token  # hop 2
//!           redeem_client_id: mcpg-drive                           # optional
//! ```
//!
//! The config structs deliberately do NOT set `deny_unknown_fields`: the
//! gateway injects a private `__mcpg_secret_refs` hint into the plugin spec for
//! secret-rotation scoping, and schema validation must tolerate it.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct IdJagConfig {
    /// Named ID-JAG providers. The map key is the provider name; callers
    /// reference an issued upstream token via the URI
    /// `cred://dev.mcpg.credential.oauth-id-jag/<name>`.
    #[serde(default)]
    pub providers: BTreeMap<String, IdJagProviderConfig>,

    /// Template fallback for targets with no exact `providers` entry:
    /// one block serves a whole fleet by expanding `{target}` into the
    /// audience / redeem endpoint (registry auto-federation references
    /// `cred://…/<server-name>` per server). Exact entries always win.
    #[serde(default)]
    pub target_template: Option<IdJagTargetTemplate>,
}

/// Template provider expanded per requested target. `{target}` in the
/// `*_template` fields is replaced with the target string; everything
/// else is shared fleet config. `allowed_targets` bounds what the
/// template may mint for — an unbounded template would let any
/// dispatchable target name select an audience.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct IdJagTargetTemplate {
    /// Targets this template serves: exact match or a single
    /// trailing-`*` prefix glob. Required non-empty.
    pub allowed_targets: Vec<String>,

    /// Enterprise IdP token endpoint for hop 1 (shared by the fleet).
    pub idp_token_url: String,

    /// OAuth client id MCPG presents to the IdP.
    pub client_id: String,

    /// Optional IdP client secret (`${env.VAR}` / `cred://…` sourced).
    #[serde(default)]
    pub client_secret: Option<String>,

    /// Hop-1 `audience` with `{target}` expansion — the upstream
    /// Resource Authorization Server's issuer per target.
    pub audience_template: String,

    /// Optional RFC 8707 `resource` with `{target}` expansion.
    #[serde(default)]
    pub resource_template: Option<String>,

    /// Scopes to request (space-joined).
    #[serde(default)]
    pub scopes: Vec<String>,

    /// `subject_token_type` for hop 1.
    #[serde(default = "default_subject_token_type")]
    pub subject_token_type: String,

    /// Hop-2 upstream AS token endpoint with `{target}` expansion.
    pub redeem_token_url_template: String,

    /// Optional client id MCPG presents on hop 2.
    #[serde(default)]
    pub redeem_client_id: Option<String>,

    /// Optional hop-2 client secret. Requires `redeem_client_id`.
    #[serde(default)]
    pub redeem_client_secret: Option<String>,

    /// Per-request timeout applied to each hop. Default 5 000.
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
}

impl IdJagTargetTemplate {
    /// Expand the template for `target`, or `None` when the target is
    /// outside `allowed_targets`.
    pub fn expand(&self, target: &str) -> Option<IdJagProviderConfig> {
        if !self.allowed_targets.iter().any(|p| glob_match(p, target)) {
            return None;
        }
        let sub = |s: &str| s.replace("{target}", target);
        Some(IdJagProviderConfig {
            idp_token_url: self.idp_token_url.clone(),
            client_id: self.client_id.clone(),
            client_secret: self.client_secret.clone(),
            audience: sub(&self.audience_template),
            resource: self.resource_template.as_deref().map(sub),
            scopes: self.scopes.clone(),
            subject_token_type: self.subject_token_type.clone(),
            redeem_token_url: sub(&self.redeem_token_url_template),
            redeem_client_id: self.redeem_client_id.clone(),
            redeem_client_secret: self.redeem_client_secret.clone(),
            timeout_ms: self.timeout_ms,
        })
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

    /// OAuth client id MCPG presents to the IdP (the gateway's confidential
    /// client at the enterprise IdP).
    pub client_id: String,

    /// Optional client secret for the IdP client. Source from a secret backend
    /// via `${env.VAR}` / `cred://...` so the literal never appears in YAML or
    /// logs.
    #[serde(default)]
    pub client_secret: Option<String>,

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

    /// `subject_token_type` for hop 1 (RFC 8693 §2.1). The caller may override
    /// per-request via `identity.attributes["subject_token_type"]`.
    #[serde(default = "default_subject_token_type")]
    pub subject_token_type: String,

    /// Upstream AS token endpoint for hop 2 (RFC 7523 `jwt-bearer` redemption).
    pub redeem_token_url: String,

    /// Optional client id MCPG presents to the upstream AS on hop 2.
    #[serde(default)]
    pub redeem_client_id: Option<String>,

    /// Optional client secret for the upstream-AS client. Requires
    /// `redeem_client_id`.
    #[serde(default)]
    pub redeem_client_secret: Option<String>,

    /// Per-request timeout applied to each hop. Default 5 000.
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
}

fn default_subject_token_type() -> String {
    "urn:ietf:params:oauth:token-type:access_token".to_owned()
}

fn default_timeout_ms() -> u64 {
    5_000
}

fn is_http_url(url: &str) -> bool {
    url.starts_with("http://") || url.starts_with("https://")
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("invalid credential.oauth-id-jag config JSON: {0}")]
    InvalidJson(#[from] serde_json::Error),
    #[error("credential.oauth-id-jag: configure `providers` and/or a `target_template`")]
    EmptyProviders,
    #[error("credential.oauth-id-jag: target_template.allowed_targets must be non-empty")]
    EmptyAllowedTargets,
    #[error("credential.oauth-id-jag: provider `{name}` idp_token_url is empty")]
    EmptyIdpTokenUrl { name: String },
    #[error(
        "credential.oauth-id-jag: provider `{name}` idp_token_url must start with http:// or https://"
    )]
    InvalidIdpTokenUrlScheme { name: String },
    #[error("credential.oauth-id-jag: provider `{name}` client_id is empty")]
    EmptyClientId { name: String },
    #[error("credential.oauth-id-jag: provider `{name}` audience is empty")]
    EmptyAudience { name: String },
    #[error("credential.oauth-id-jag: provider `{name}` redeem_token_url is empty")]
    EmptyRedeemTokenUrl { name: String },
    #[error(
        "credential.oauth-id-jag: provider `{name}` redeem_token_url must start with http:// or https://"
    )]
    InvalidRedeemTokenUrlScheme { name: String },
    #[error(
        "credential.oauth-id-jag: provider `{name}` redeem_client_secret requires redeem_client_id"
    )]
    RedeemSecretWithoutClientId { name: String },
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
            // Validate the template through a representative expansion —
            // the expanded shape is exactly a provider, so the provider
            // rules apply verbatim (a `{target}` in a URL template still
            // satisfies the scheme-prefix checks).
            let probe = template
                .expand(template.allowed_targets[0].trim_end_matches('*'))
                .expect("first allowed target expands");
            Self::validate_provider("target_template", &probe)?;
        }
        for (name, provider) in &self.providers {
            Self::validate_provider(name, provider)?;
        }
        Ok(())
    }

    fn validate_provider(name: &str, provider: &IdJagProviderConfig) -> Result<(), ConfigError> {
        {
            if provider.idp_token_url.trim().is_empty() {
                return Err(ConfigError::EmptyIdpTokenUrl {
                    name: name.to_owned(),
                });
            }
            if !is_http_url(&provider.idp_token_url) {
                return Err(ConfigError::InvalidIdpTokenUrlScheme {
                    name: name.to_owned(),
                });
            }
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
            if !is_http_url(&provider.redeem_token_url) {
                return Err(ConfigError::InvalidRedeemTokenUrlScheme {
                    name: name.to_owned(),
                });
            }
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
            if provider.timeout_ms < 100 || provider.timeout_ms > 60_000 {
                return Err(ConfigError::InvalidTimeoutMs {
                    name: name.to_owned(),
                    timeout: provider.timeout_ms,
                });
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn minimal() -> serde_json::Value {
        json!({
            "providers": {
                "drive": {
                    "idp_token_url": "https://idp.example.com/oauth2/token",
                    "client_id": "mcpg",
                    "audience": "https://drive-mcp.example.com",
                    "redeem_token_url": "https://drive-mcp.example.com/oauth2/token"
                }
            }
        })
    }

    #[test]
    fn parses_minimal_with_defaults() {
        let cfg = IdJagConfig::parse(&minimal().to_string()).unwrap();
        let p = cfg.providers.get("drive").unwrap();
        assert_eq!(
            p.subject_token_type,
            "urn:ietf:params:oauth:token-type:access_token"
        );
        assert_eq!(p.timeout_ms, 5_000);
        assert!(p.client_secret.is_none());
        assert!(p.resource.is_none());
        assert!(p.scopes.is_empty());
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
        assert!(matches!(
            IdJagConfig::parse(&v.to_string()).unwrap_err(),
            ConfigError::EmptyProviders
        ));
    }

    fn template_only() -> serde_json::Value {
        json!({
            "target_template": {
                "allowed_targets": ["com.acme/*"],
                "idp_token_url": "https://idp.acme.example/oauth2/token",
                "client_id": "mcpg-fleet",
                "audience_template": "https://{target}.mcp.acme.internal",
                "redeem_token_url_template": "https://{target}.mcp.acme.internal/oauth2/token"
            }
        })
    }

    #[test]
    fn template_only_config_validates_and_expands() {
        let cfg = IdJagConfig::parse(&template_only().to_string()).unwrap();
        let template = cfg.target_template.as_ref().unwrap();
        let expanded = template.expand("com.acme/crm").expect("allowlisted target");
        assert_eq!(expanded.audience, "https://com.acme/crm.mcp.acme.internal");
        assert_eq!(
            expanded.redeem_token_url,
            "https://com.acme/crm.mcp.acme.internal/oauth2/token"
        );
        assert_eq!(expanded.client_id, "mcpg-fleet");
        assert_eq!(expanded.timeout_ms, 5_000);

        // Outside the allowlist: no expansion.
        assert!(template.expand("io.github.evil/exfil").is_none());
    }

    #[test]
    fn template_requires_allowed_targets() {
        let mut v = template_only();
        v["target_template"]["allowed_targets"] = json!([]);
        assert!(matches!(
            IdJagConfig::parse(&v.to_string()).unwrap_err(),
            ConfigError::EmptyAllowedTargets
        ));
    }

    #[test]
    fn template_url_schemes_validated() {
        let mut v = template_only();
        v["target_template"]["redeem_token_url_template"] = json!("ftp://{target}/token");
        assert!(matches!(
            IdJagConfig::parse(&v.to_string()).unwrap_err(),
            ConfigError::InvalidRedeemTokenUrlScheme { .. }
        ));
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
        assert!(matches!(
            IdJagConfig::parse(&v.to_string()).unwrap_err(),
            ConfigError::EmptyAudience { .. }
        ));
    }

    #[test]
    fn rejects_missing_redeem_token_url() {
        let mut v = minimal();
        v["providers"]["drive"]["redeem_token_url"] = json!("");
        assert!(matches!(
            IdJagConfig::parse(&v.to_string()).unwrap_err(),
            ConfigError::EmptyRedeemTokenUrl { .. }
        ));
    }

    #[test]
    fn rejects_unknown_idp_url_scheme() {
        let mut v = minimal();
        v["providers"]["drive"]["idp_token_url"] = json!("file:///etc/oauth");
        assert!(matches!(
            IdJagConfig::parse(&v.to_string()).unwrap_err(),
            ConfigError::InvalidIdpTokenUrlScheme { .. }
        ));
    }

    #[test]
    fn rejects_unknown_redeem_url_scheme() {
        let mut v = minimal();
        v["providers"]["drive"]["redeem_token_url"] = json!("ftp://as.example.com/token");
        assert!(matches!(
            IdJagConfig::parse(&v.to_string()).unwrap_err(),
            ConfigError::InvalidRedeemTokenUrlScheme { .. }
        ));
    }

    #[test]
    fn rejects_empty_client_id() {
        let mut v = minimal();
        v["providers"]["drive"]["client_id"] = json!("");
        assert!(matches!(
            IdJagConfig::parse(&v.to_string()).unwrap_err(),
            ConfigError::EmptyClientId { .. }
        ));
    }

    #[test]
    fn rejects_redeem_secret_without_client_id() {
        let mut v = minimal();
        v["providers"]["drive"]["redeem_client_secret"] = json!("shhh");
        assert!(matches!(
            IdJagConfig::parse(&v.to_string()).unwrap_err(),
            ConfigError::RedeemSecretWithoutClientId { .. }
        ));
    }

    #[test]
    fn rejects_oversize_timeout() {
        let mut v = minimal();
        v["providers"]["drive"]["timeout_ms"] = json!(120_000);
        assert!(matches!(
            IdJagConfig::parse(&v.to_string()).unwrap_err(),
            ConfigError::InvalidTimeoutMs { .. }
        ));
    }
}
