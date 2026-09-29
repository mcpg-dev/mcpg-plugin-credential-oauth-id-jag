//! Client authentication at an OAuth token endpoint: `client_secret_post`,
//! `client_secret_basic` (RFC 6749 §2.3.1) and `private_key_jwt` (a signed
//! RFC 7523 §2.2 client assertion).

use std::borrow::Cow;
use std::time::{SystemTime, UNIX_EPOCH};

use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde::{Deserialize, Serialize};

/// `client_assertion_type` of a JWT client assertion (RFC 7523 §2.2).
pub(crate) const CLIENT_ASSERTION_TYPE_JWT: &str =
    "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

/// Lifetime of a signed client assertion. It is a bearer credential, so it
/// stays well under the five-minute ceiling.
pub(crate) const ASSERTION_LIFETIME_SECS: u64 = 120;

/// How the plugin authenticates to one token endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClientAuthMethod {
    /// `client_id` and `client_secret` in the form body.
    ClientSecretPost,
    /// `client_id` and `client_secret` in an HTTP Basic header.
    ClientSecretBasic,
    /// A client assertion JWT signed with the client's private key.
    PrivateKeyJwt,
}

impl ClientAuthMethod {
    fn as_str(self) -> &'static str {
        match self {
            Self::ClientSecretPost => "client_secret_post",
            Self::ClientSecretBasic => "client_secret_basic",
            Self::PrivateKeyJwt => "private_key_jwt",
        }
    }
}

/// The `aud` of a `private_key_jwt` client assertion.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AssertionAudience {
    /// The token endpoint URL the assertion is posted to (what Okta expects).
    #[default]
    TokenEndpoint,
    /// The authorization server's issuer identifier (RFC 7523bis).
    Issuer,
}

/// JWS algorithm of a `private_key_jwt` client assertion.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SigningAlg {
    #[serde(rename = "RS256")]
    Rs256,
    #[serde(rename = "RS384")]
    Rs384,
    #[serde(rename = "RS512")]
    Rs512,
    #[serde(rename = "PS256")]
    Ps256,
    #[serde(rename = "PS384")]
    Ps384,
    #[serde(rename = "PS512")]
    Ps512,
    #[serde(rename = "ES256")]
    Es256,
    #[serde(rename = "ES384")]
    Es384,
    #[serde(rename = "EdDSA")]
    EdDsa,
}

impl SigningAlg {
    /// The algorithm each key type implies, one per type: RSA, P-256, P-384
    /// and Ed25519. A key signs with at most one of them.
    const KEY_TYPE_DEFAULTS: [Self; 4] = [Self::Rs256, Self::Es256, Self::Es384, Self::EdDsa];

    fn as_str(self) -> &'static str {
        match self {
            Self::Rs256 => "RS256",
            Self::Rs384 => "RS384",
            Self::Rs512 => "RS512",
            Self::Ps256 => "PS256",
            Self::Ps384 => "PS384",
            Self::Ps512 => "PS512",
            Self::Es256 => "ES256",
            Self::Es384 => "ES384",
            Self::EdDsa => "EdDSA",
        }
    }

    fn algorithm(self) -> Algorithm {
        match self {
            Self::Rs256 => Algorithm::RS256,
            Self::Rs384 => Algorithm::RS384,
            Self::Rs512 => Algorithm::RS512,
            Self::Ps256 => Algorithm::PS256,
            Self::Ps384 => Algorithm::PS384,
            Self::Ps512 => Algorithm::PS512,
            Self::Es256 => Algorithm::ES256,
            Self::Es384 => Algorithm::ES384,
            Self::EdDsa => Algorithm::EdDSA,
        }
    }

    fn load_key(self, pem: &[u8]) -> jsonwebtoken::errors::Result<EncodingKey> {
        match self {
            Self::Rs256 | Self::Rs384 | Self::Rs512 | Self::Ps256 | Self::Ps384 | Self::Ps512 => {
                EncodingKey::from_rsa_pem(pem)
            }
            Self::Es256 | Self::Es384 => EncodingKey::from_ec_pem(pem),
            Self::EdDsa => EncodingKey::from_ed_pem(pem),
        }
    }

    /// The private key this algorithm signs with.
    fn key_type(self) -> &'static str {
        match self {
            Self::Rs256 | Self::Rs384 | Self::Rs512 | Self::Ps256 | Self::Ps384 | Self::Ps512 => {
                "an RSA key in PKCS#8 or PKCS#1 PEM"
            }
            Self::Es256 => "a P-256 key in PKCS#8 PEM",
            Self::Es384 => "a P-384 key in PKCS#8 PEM",
            Self::EdDsa => "an Ed25519 key in PKCS#8 PEM",
        }
    }
}

/// One token endpoint's client-authentication settings, as configured.
pub(crate) struct ClientAuthSettings<'a> {
    /// Prefix of the setting names in error reasons (`""` or `"redeem_"`).
    pub prefix: &'static str,
    pub method: Option<ClientAuthMethod>,
    pub client_id: Option<&'a str>,
    pub client_secret: Option<&'a str>,
    pub private_key: Option<&'a str>,
    pub key_id: Option<&'a str>,
    /// Unset: the algorithm the key type implies.
    pub signing_alg: Option<SigningAlg>,
    pub assertion_audience: Option<AssertionAudience>,
    /// Whether an issuer identifier exists for `assertion_audience: issuer`.
    pub issuer_available: bool,
    /// The setting that supplies that issuer identifier.
    pub issuer_setting: &'static str,
}

/// Client authentication for one token endpoint, with any signing key
/// already parsed.
pub(crate) enum ClientAuth {
    /// Form-body credentials. With no explicit `client_auth` the id and the
    /// secret are each sent only when configured.
    Post {
        client_id: Option<String>,
        client_secret: Option<String>,
    },
    Basic {
        client_id: String,
        client_secret: String,
    },
    PrivateKeyJwt(Box<AssertionSigner>),
}

pub(crate) struct AssertionSigner {
    client_id: String,
    alg: Algorithm,
    key: EncodingKey,
    key_id: Option<String>,
    audience: AssertionAudience,
}

#[derive(Serialize)]
struct AssertionClaims<'a> {
    iss: &'a str,
    sub: &'a str,
    aud: &'a str,
    jti: String,
    iat: u64,
    exp: u64,
}

fn present(value: Option<&str>) -> Option<&str> {
    value.filter(|v| !v.trim().is_empty())
}

/// A PEM passed through an environment variable often carries literal `\n`
/// escapes in place of line breaks.
fn normalize_pem(pem: &str) -> Cow<'_, str> {
    let pem = pem.trim();
    if !pem.contains('\n') && pem.contains("\\n") {
        Cow::Owned(pem.replace("\\n", "\n"))
    } else {
        Cow::Borrowed(pem)
    }
}

/// `application/x-www-form-urlencoded` encoding, which RFC 6749 §2.3.1
/// applies to the id and the secret before they enter a Basic header.
fn form_encode(value: &str) -> String {
    url::form_urlencoded::byte_serialize(value.as_bytes()).collect()
}

impl ClientAuth {
    /// Validate `settings` and parse the signing key. Reasons name settings,
    /// never their values.
    pub(crate) fn compile(settings: &ClientAuthSettings<'_>) -> Result<Self, String> {
        let p = settings.prefix;
        let client_id = present(settings.client_id);
        let client_secret = present(settings.client_secret);
        let key_settings = settings.private_key.is_some()
            || settings.key_id.is_some()
            || settings.signing_alg.is_some()
            || settings.assertion_audience.is_some();
        if settings.method != Some(ClientAuthMethod::PrivateKeyJwt) && key_settings {
            return Err(format!(
                "{p}private_key, {p}key_id, {p}signing_alg and {p}assertion_audience apply only \
                 to {p}client_auth: private_key_jwt"
            ));
        }
        match settings.method {
            None => Ok(Self::Post {
                client_id: client_id.map(str::to_owned),
                client_secret: client_secret.map(str::to_owned),
            }),
            Some(
                method @ (ClientAuthMethod::ClientSecretPost | ClientAuthMethod::ClientSecretBasic),
            ) => {
                let (Some(id), Some(secret)) = (client_id, client_secret) else {
                    return Err(format!(
                        "{p}client_auth: {} requires {p}client_id and {p}client_secret",
                        method.as_str()
                    ));
                };
                Ok(if method == ClientAuthMethod::ClientSecretPost {
                    Self::Post {
                        client_id: Some(id.to_owned()),
                        client_secret: Some(secret.to_owned()),
                    }
                } else {
                    Self::Basic {
                        client_id: id.to_owned(),
                        client_secret: secret.to_owned(),
                    }
                })
            }
            Some(ClientAuthMethod::PrivateKeyJwt) => {
                let Some(id) = client_id else {
                    return Err(format!(
                        "{p}client_auth: private_key_jwt requires {p}client_id"
                    ));
                };
                if client_secret.is_some() {
                    return Err(format!(
                        "{p}client_secret must not be set with {p}client_auth: private_key_jwt"
                    ));
                }
                let Some(pem) = present(settings.private_key) else {
                    return Err(format!(
                        "{p}client_auth: private_key_jwt requires {p}private_key"
                    ));
                };
                let audience = settings.assertion_audience.unwrap_or_default();
                if audience == AssertionAudience::Issuer && !settings.issuer_available {
                    return Err(format!(
                        "{p}assertion_audience: issuer requires {}",
                        settings.issuer_setting
                    ));
                }
                let pem = normalize_pem(pem);
                // A key counts for an algorithm only once it has signed: an EC
                // key loads for ES256 and ES384 alike but signs on one curve.
                // `Err(None)`: the key does not load. A load error can quote
                // bytes of the PEM, so only a signing error is kept.
                let signer_for = |alg: SigningAlg| -> Result<AssertionSigner, Option<String>> {
                    let signer = AssertionSigner {
                        client_id: id.to_owned(),
                        alg: alg.algorithm(),
                        key: alg.load_key(pem.as_bytes()).map_err(|_| None)?,
                        key_id: present(settings.key_id).map(str::to_owned),
                        audience,
                    };
                    signer
                        .encode("urn:mcpg:key-check", 0)
                        .map_err(|e| Some(e.to_string()))?;
                    Ok(signer)
                };
                let signer = match settings.signing_alg {
                    Some(alg) => signer_for(alg).map_err(|cause| {
                        let reason = format!(
                            "{p}private_key cannot sign {}: expected {}",
                            alg.as_str(),
                            alg.key_type()
                        );
                        match cause {
                            Some(cause) => format!("{reason} ({cause})"),
                            None => reason,
                        }
                    })?,
                    None => SigningAlg::KEY_TYPE_DEFAULTS
                        .into_iter()
                        .find_map(|alg| signer_for(alg).ok())
                        .ok_or_else(|| {
                            format!(
                                "{p}private_key is not a usable PEM private key: expected an RSA \
                                 (RS256), P-256 (ES256), P-384 (ES384) or Ed25519 (EdDSA) key in \
                                 PKCS#8 PEM, or an RSA key in PKCS#1 PEM"
                            )
                        })?,
                };
                Ok(Self::PrivateKeyJwt(Box::new(signer)))
            }
        }
    }

    /// Attach this client's credentials to a token request. `issuer` is the
    /// authorization server's issuer identifier, when one is known.
    pub(crate) fn authenticate(
        &self,
        request: reqwest::RequestBuilder,
        form: &mut Vec<(&'static str, String)>,
        token_url: &str,
        issuer: Option<&str>,
    ) -> Result<reqwest::RequestBuilder, String> {
        match self {
            Self::Post {
                client_id,
                client_secret,
            } => {
                if let Some(id) = client_id {
                    form.push(("client_id", id.clone()));
                }
                if let Some(secret) = client_secret {
                    form.push(("client_secret", secret.clone()));
                }
                Ok(request)
            }
            Self::Basic {
                client_id,
                client_secret,
            } => Ok(request.basic_auth(form_encode(client_id), Some(form_encode(client_secret)))),
            Self::PrivateKeyJwt(signer) => {
                let audience = match signer.audience {
                    AssertionAudience::TokenEndpoint => token_url,
                    AssertionAudience::Issuer => issuer.ok_or_else(|| {
                        "no issuer identifier for the client assertion audience".to_owned()
                    })?,
                };
                let assertion = signer.sign(audience)?;
                form.push(("client_id", signer.client_id.clone()));
                form.push((
                    "client_assertion_type",
                    CLIENT_ASSERTION_TYPE_JWT.to_owned(),
                ));
                form.push(("client_assertion", assertion));
                Ok(request)
            }
        }
    }
}

impl AssertionSigner {
    /// A fresh client assertion: `iss` = `sub` = client id, a new `jti`, and
    /// an expiry [`ASSERTION_LIFETIME_SECS`] after `iat`.
    fn sign(&self, audience: &str) -> Result<String, String> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| "system clock is before the Unix epoch".to_owned())?
            .as_secs();
        self.encode(audience, now)
            .map_err(|e| format!("client assertion signing failed: {e}"))
    }

    /// The assertion issued at `iat`, in Unix seconds.
    fn encode(&self, audience: &str, iat: u64) -> jsonwebtoken::errors::Result<String> {
        let claims = AssertionClaims {
            iss: &self.client_id,
            sub: &self.client_id,
            aud: audience,
            jti: uuid::Uuid::new_v4().to_string(),
            iat,
            exp: iat + ASSERTION_LIFETIME_SECS,
        };
        let mut header = Header::new(self.alg);
        header.kid = self.key_id.clone();
        jsonwebtoken::encode(&header, &claims, &self.key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{DecodingKey, Validation};
    use serde_json::Value;

    const RSA_PRIV: &str = include_str!("testdata/rsa_priv.pem");
    const RSA_PUB: &str = include_str!("testdata/rsa_pub.pem");
    const EC_PRIV: &str = include_str!("testdata/ec_priv.pem");
    const EC_PUB: &str = include_str!("testdata/ec_pub.pem");
    const EC_P384_PRIV: &str = include_str!("testdata/ec_p384_priv.pem");
    const EC_P384_PUB: &str = include_str!("testdata/ec_p384_pub.pem");
    const ED_PRIV: &str = include_str!("testdata/ed25519_priv.pem");
    const ED_PUB: &str = include_str!("testdata/ed25519_pub.pem");

    const TOKEN_URL: &str = "https://idp.example.com/oauth2/v1/token";

    fn settings<'a>(method: Option<ClientAuthMethod>) -> ClientAuthSettings<'a> {
        ClientAuthSettings {
            prefix: "",
            method,
            client_id: Some("agent-1"),
            client_secret: None,
            private_key: None,
            key_id: None,
            signing_alg: None,
            assertion_audience: None,
            issuer_available: false,
            issuer_setting: "idp_issuer",
        }
    }

    fn key_settings(pem: &str) -> ClientAuthSettings<'_> {
        ClientAuthSettings {
            private_key: Some(pem),
            key_id: Some("kid-1"),
            ..settings(Some(ClientAuthMethod::PrivateKeyJwt))
        }
    }

    fn jwt_settings(pem: &str, alg: SigningAlg) -> ClientAuthSettings<'_> {
        ClientAuthSettings {
            signing_alg: Some(alg),
            ..key_settings(pem)
        }
    }

    fn form_of(
        auth: &ClientAuth,
        issuer: Option<&str>,
    ) -> (reqwest::Request, Vec<(&'static str, String)>) {
        let mut form = Vec::new();
        let request = reqwest::Client::new().post(TOKEN_URL);
        let request = auth
            .authenticate(request, &mut form, TOKEN_URL, issuer)
            .unwrap()
            .build()
            .unwrap();
        (request, form)
    }

    fn field<'a>(form: &'a [(&'static str, String)], name: &str) -> Option<&'a str> {
        form.iter()
            .find(|(k, _)| *k == name)
            .map(|(_, v)| v.as_str())
    }

    fn decode(assertion: &str, alg: Algorithm, key: &DecodingKey, aud: &str) -> Value {
        let mut validation = Validation::new(alg);
        validation.set_audience(&[aud]);
        validation.set_issuer(&["agent-1"]);
        let data = jsonwebtoken::decode::<Value>(assertion, key, &validation).unwrap();
        assert_eq!(data.header.kid.as_deref(), Some("kid-1"));
        data.claims
    }

    fn assert_assertion_claims(claims: &Value) {
        assert_eq!(claims["iss"], "agent-1");
        assert_eq!(claims["sub"], "agent-1");
        let iat = claims["iat"].as_u64().unwrap();
        let exp = claims["exp"].as_u64().unwrap();
        assert!(
            exp > iat && exp - iat <= 300,
            "lifetime within five minutes"
        );
        assert!(!claims["jti"].as_str().unwrap().is_empty());
    }

    #[test]
    fn implicit_post_sends_only_what_is_configured() {
        let auth = ClientAuth::compile(&settings(None)).unwrap();
        let (request, form) = form_of(&auth, None);
        assert_eq!(field(&form, "client_id"), Some("agent-1"));
        assert_eq!(field(&form, "client_secret"), None);
        assert!(request.headers().get("authorization").is_none());
    }

    #[test]
    fn explicit_post_and_basic_require_a_secret() {
        for method in [
            ClientAuthMethod::ClientSecretPost,
            ClientAuthMethod::ClientSecretBasic,
        ] {
            let err = ClientAuth::compile(&settings(Some(method))).err().unwrap();
            assert!(err.contains("client_secret"), "{err}");
        }
    }

    #[test]
    fn basic_puts_form_encoded_credentials_in_the_header_only() {
        let auth = ClientAuth::compile(&ClientAuthSettings {
            client_id: Some("agent:1"),
            client_secret: Some("s3cr+t/="),
            ..settings(Some(ClientAuthMethod::ClientSecretBasic))
        })
        .unwrap();
        let (request, form) = form_of(&auth, None);
        assert!(form.is_empty(), "no credentials in the body");
        let header = request.headers()["authorization"].to_str().unwrap();
        // base64("agent%3A1:s3cr%2Bt%2F%3D")
        assert_eq!(header, "Basic YWdlbnQlM0ExOnMzY3IlMkJ0JTJGJTNE");
    }

    #[test]
    fn private_key_jwt_rs256_targets_the_token_endpoint_by_default() {
        let auth = ClientAuth::compile(&jwt_settings(RSA_PRIV, SigningAlg::Rs256)).unwrap();
        let (request, form) = form_of(&auth, None);
        assert!(request.headers().get("authorization").is_none());
        assert_eq!(field(&form, "client_id"), Some("agent-1"));
        assert_eq!(
            field(&form, "client_assertion_type"),
            Some(CLIENT_ASSERTION_TYPE_JWT)
        );
        let claims = decode(
            field(&form, "client_assertion").unwrap(),
            Algorithm::RS256,
            &DecodingKey::from_rsa_pem(RSA_PUB.as_bytes()).unwrap(),
            TOKEN_URL,
        );
        assert_assertion_claims(&claims);
        assert_eq!(claims["aud"], TOKEN_URL);
    }

    #[test]
    fn private_key_jwt_es256_can_target_the_issuer() {
        let auth = ClientAuth::compile(&ClientAuthSettings {
            assertion_audience: Some(AssertionAudience::Issuer),
            issuer_available: true,
            ..jwt_settings(EC_PRIV, SigningAlg::Es256)
        })
        .unwrap();
        let (_, form) = form_of(&auth, Some("https://idp.example.com"));
        let claims = decode(
            field(&form, "client_assertion").unwrap(),
            Algorithm::ES256,
            &DecodingKey::from_ec_pem(EC_PUB.as_bytes()).unwrap(),
            "https://idp.example.com",
        );
        assert_assertion_claims(&claims);
    }

    #[test]
    fn private_key_jwt_eddsa_signs_and_every_assertion_is_fresh() {
        let auth = ClientAuth::compile(&jwt_settings(ED_PRIV, SigningAlg::EdDsa)).unwrap();
        let key = DecodingKey::from_ed_pem(ED_PUB.as_bytes()).unwrap();
        let (_, first) = form_of(&auth, None);
        let (_, second) = form_of(&auth, None);
        let a = decode(
            field(&first, "client_assertion").unwrap(),
            Algorithm::EdDSA,
            &key,
            TOKEN_URL,
        );
        let b = decode(
            field(&second, "client_assertion").unwrap(),
            Algorithm::EdDSA,
            &key,
            TOKEN_URL,
        );
        assert_ne!(a["jti"], b["jti"], "jti is never reused");
    }

    #[test]
    fn private_key_jwt_signs_with_the_algorithm_the_key_type_implies() {
        for (pem, public, alg) in [
            (
                RSA_PRIV,
                DecodingKey::from_rsa_pem(RSA_PUB.as_bytes()),
                Algorithm::RS256,
            ),
            (
                EC_PRIV,
                DecodingKey::from_ec_pem(EC_PUB.as_bytes()),
                Algorithm::ES256,
            ),
            (
                EC_P384_PRIV,
                DecodingKey::from_ec_pem(EC_P384_PUB.as_bytes()),
                Algorithm::ES384,
            ),
            (
                ED_PRIV,
                DecodingKey::from_ed_pem(ED_PUB.as_bytes()),
                Algorithm::EdDSA,
            ),
        ] {
            let auth =
                ClientAuth::compile(&key_settings(pem)).unwrap_or_else(|e| panic!("{alg:?}: {e}"));
            let (_, form) = form_of(&auth, None);
            let assertion = field(&form, "client_assertion").unwrap();
            assert_eq!(jsonwebtoken::decode_header(assertion).unwrap().alg, alg);
            assert_assertion_claims(&decode(assertion, alg, &public.unwrap(), TOKEN_URL));
        }
    }

    #[test]
    fn an_explicit_signing_alg_wins_over_the_key_type() {
        let public = DecodingKey::from_rsa_pem(RSA_PUB.as_bytes()).unwrap();
        for alg in [SigningAlg::Ps256, SigningAlg::Rs512] {
            let auth = ClientAuth::compile(&jwt_settings(RSA_PRIV, alg)).unwrap();
            let (_, form) = form_of(&auth, None);
            let assertion = field(&form, "client_assertion").unwrap();
            assert_eq!(
                jsonwebtoken::decode_header(assertion).unwrap().alg,
                alg.algorithm()
            );
            decode(assertion, alg.algorithm(), &public, TOKEN_URL);
        }
    }

    #[test]
    fn escaped_newlines_from_an_env_var_are_accepted() {
        let escaped = RSA_PRIV.trim().replace('\n', "\\n");
        assert!(ClientAuth::compile(&jwt_settings(&escaped, SigningAlg::Rs256)).is_ok());
        let escaped = EC_PRIV.trim().replace('\n', "\\n");
        let auth = ClientAuth::compile(&key_settings(&escaped)).unwrap();
        let (_, form) = form_of(&auth, None);
        let header = jsonwebtoken::decode_header(field(&form, "client_assertion").unwrap());
        assert_eq!(header.unwrap().alg, Algorithm::ES256);
    }

    #[test]
    fn private_key_jwt_rejects_bad_combinations() {
        let cases: Vec<(ClientAuthSettings<'_>, &str)> = vec![
            (
                ClientAuthSettings {
                    private_key: None,
                    ..jwt_settings(RSA_PRIV, SigningAlg::Rs256)
                },
                "requires private_key",
            ),
            (
                ClientAuthSettings {
                    client_secret: Some("shh"),
                    ..jwt_settings(RSA_PRIV, SigningAlg::Rs256)
                },
                "client_secret must not be set",
            ),
            (
                ClientAuthSettings {
                    client_id: None,
                    ..jwt_settings(RSA_PRIV, SigningAlg::Rs256)
                },
                "requires client_id",
            ),
            (
                ClientAuthSettings {
                    assertion_audience: Some(AssertionAudience::Issuer),
                    ..jwt_settings(RSA_PRIV, SigningAlg::Rs256)
                },
                "requires idp_issuer",
            ),
            (key_settings("not a pem"), "is not a usable PEM private key"),
            (
                jwt_settings("not a pem", SigningAlg::Rs256),
                "cannot sign RS256: expected an RSA key",
            ),
            (
                jwt_settings(EC_PRIV, SigningAlg::Rs256),
                "cannot sign RS256: expected an RSA key",
            ),
            (
                jwt_settings(RSA_PRIV, SigningAlg::Es256),
                "cannot sign ES256: expected a P-256 key",
            ),
            (
                jwt_settings(EC_P384_PRIV, SigningAlg::Es256),
                "cannot sign ES256: expected a P-256 key",
            ),
            (
                jwt_settings(EC_PRIV, SigningAlg::Es384),
                "cannot sign ES384: expected a P-384 key",
            ),
            (
                jwt_settings(ED_PRIV, SigningAlg::Ps256),
                "cannot sign PS256: expected an RSA key",
            ),
            (
                jwt_settings(RSA_PRIV, SigningAlg::EdDsa),
                "cannot sign EdDSA: expected an Ed25519 key",
            ),
        ];
        for (settings, expected) in cases {
            let err = ClientAuth::compile(&settings).err().unwrap();
            assert!(err.contains(expected), "{expected:?} not in {err:?}");
            assert!(!err.contains("BEGIN"), "key material leaked: {err}");
        }
    }

    #[test]
    fn a_key_that_loads_but_does_not_sign_keeps_the_signing_error() {
        let expected = "private_key cannot sign ES256: expected a P-256 key in PKCS#8 PEM";
        let refused = ClientAuth::compile(&jwt_settings(EC_P384_PRIV, SigningAlg::Es256))
            .err()
            .unwrap();
        let cause = refused
            .strip_prefix(expected)
            .and_then(|rest| rest.strip_prefix(" ("))
            .and_then(|rest| rest.strip_suffix(')'))
            .unwrap_or_else(|| panic!("no signing error in {refused:?}"));
        assert!(!cause.is_empty() && !cause.contains("BEGIN"), "{refused}");
        let unloadable = ClientAuth::compile(&jwt_settings("not a pem", SigningAlg::Es256))
            .err()
            .unwrap();
        assert_eq!(unloadable, expected);
    }

    /// Held by this signer and by the gateway's login client alike.
    const VECTOR: &str = include_str!("testdata/client_assertion_vector.json");

    fn fixture_pem(name: &str) -> &'static str {
        match name {
            "rsa_priv.pem" => RSA_PRIV,
            "rsa_pub.pem" => RSA_PUB,
            "ec_priv.pem" => EC_PRIV,
            "ec_pub.pem" => EC_PUB,
            "ed25519_priv.pem" => ED_PRIV,
            "ed25519_pub.pem" => ED_PUB,
            other => panic!("no fixture {other}"),
        }
    }

    fn public_key(alg: Algorithm, pem: &str) -> DecodingKey {
        match alg {
            Algorithm::ES256 | Algorithm::ES384 => DecodingKey::from_ec_pem(pem.as_bytes()),
            Algorithm::EdDSA => DecodingKey::from_ed_pem(pem.as_bytes()),
            _ => DecodingKey::from_rsa_pem(pem.as_bytes()),
        }
        .unwrap()
    }

    #[test]
    fn assertions_match_the_shared_client_assertion_vector() {
        let vector: Value = serde_json::from_str(VECTOR).unwrap();
        let text = |key: &str| vector[key].as_str().unwrap();
        let client_id = text("client_id");
        let form_fields: Vec<&str> = vector["form_fields"]
            .as_array()
            .unwrap()
            .iter()
            .map(|name| name.as_str().unwrap())
            .collect();
        for signer in vector["signers"].as_array().unwrap() {
            let alg: SigningAlg = serde_json::from_value(signer["alg"].clone()).unwrap();
            let decoding = public_key(
                alg.algorithm(),
                fixture_pem(signer["public_key"].as_str().unwrap()),
            );
            for rule in vector["audiences"].as_array().unwrap() {
                let audience: AssertionAudience =
                    serde_json::from_value(rule["assertion_audience"].clone()).unwrap();
                let auth = ClientAuth::compile(&ClientAuthSettings {
                    prefix: "",
                    method: Some(ClientAuthMethod::PrivateKeyJwt),
                    client_id: Some(client_id),
                    client_secret: None,
                    private_key: Some(fixture_pem(signer["private_key"].as_str().unwrap())),
                    key_id: Some(text("key_id")),
                    signing_alg: Some(alg),
                    assertion_audience: Some(audience),
                    issuer_available: true,
                    issuer_setting: "idp_issuer",
                })
                .unwrap();
                let mut form = Vec::new();
                let request = auth
                    .authenticate(
                        reqwest::Client::new().post(text("token_endpoint")),
                        &mut form,
                        text("token_endpoint"),
                        Some(text("issuer")),
                    )
                    .unwrap()
                    .build()
                    .unwrap();
                assert!(request.headers().get("authorization").is_none());
                let case = format!("{} {}", alg.as_str(), rule["assertion_audience"]);
                let names: Vec<&str> = form.iter().map(|(name, _)| *name).collect();
                assert_eq!(names, form_fields, "{case}");
                assert_eq!(field(&form, "client_id"), Some(client_id), "{case}");
                assert_eq!(
                    field(&form, "client_assertion_type"),
                    Some(text("client_assertion_type")),
                    "{case}"
                );
                let aud = rule["aud"].as_str().unwrap();
                let mut validation = Validation::new(alg.algorithm());
                validation.set_audience(&[aud]);
                validation.set_issuer(&[client_id]);
                let data = jsonwebtoken::decode::<Value>(
                    field(&form, "client_assertion").unwrap(),
                    &decoding,
                    &validation,
                )
                .unwrap_or_else(|e| panic!("{case}: {e}"));
                assert_eq!(data.header.alg, alg.algorithm(), "{case}");
                assert_eq!(data.header.kid.as_deref(), Some(text("key_id")), "{case}");
                assert_eq!(
                    data.header.typ.as_deref(),
                    Some(text("header_typ")),
                    "{case}"
                );
                assert_eq!(data.claims["iss"], client_id, "{case}");
                assert_eq!(data.claims["sub"], client_id, "{case}");
                assert_eq!(data.claims["aud"], aud, "{case}");
                assert_eq!(
                    data.claims["exp"].as_u64().unwrap() - data.claims["iat"].as_u64().unwrap(),
                    vector["lifetime_secs"].as_u64().unwrap(),
                    "{case}"
                );
                assert!(
                    data.claims["jti"]
                        .as_str()
                        .is_some_and(|jti| !jti.is_empty()),
                    "{case}"
                );
            }
        }

        let basic = &vector["client_secret_basic"];
        let auth = ClientAuth::compile(&ClientAuthSettings {
            client_id: basic["client_id"].as_str(),
            client_secret: basic["client_secret"].as_str(),
            ..settings(Some(ClientAuthMethod::ClientSecretBasic))
        })
        .unwrap();
        let (request, form) = form_of(&auth, None);
        assert!(form.is_empty());
        assert_eq!(
            request.headers()["authorization"].to_str().unwrap(),
            basic["authorization"].as_str().unwrap()
        );
    }

    #[test]
    fn key_settings_without_private_key_jwt_are_rejected() {
        let err = ClientAuth::compile(&ClientAuthSettings {
            prefix: "redeem_",
            private_key: Some(RSA_PRIV),
            ..settings(Some(ClientAuthMethod::ClientSecretBasic))
        })
        .err()
        .unwrap();
        assert!(err.contains("redeem_client_auth: private_key_jwt"), "{err}");
    }
}
