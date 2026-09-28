//! Outbound policy for token endpoints. Client credentials and subject
//! tokens are posted there, so a URL must be https unless the operator
//! allows plain http, and its host must not reach a private, loopback or
//! link-local address unless the operator allows the private network.

use std::error::Error;
use std::fmt;
use std::net::{IpAddr, SocketAddr};

use mcpg_plugin_protocol::security::is_private_address;

const PRIVATE_TARGET: &str = "targets a private, loopback or link-local address \
                              (set allow_private_network: true to permit)";

/// Egress switches for one provider's token endpoints.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct EgressPolicy {
    pub allow_insecure_http: bool,
    pub allow_private_network: bool,
}

/// Check a token-endpoint URL against `policy` before anything is sent.
/// The reason never echoes the URL, which may carry credentials.
pub(crate) fn check_endpoint(url: &str, policy: EgressPolicy) -> Result<(), String> {
    let parsed = url::Url::parse(url).map_err(|_| "is not an absolute URL".to_owned())?;
    match parsed.scheme() {
        "https" => {}
        "http" if policy.allow_insecure_http => {}
        "http" => {
            return Err(
                "must use https (set allow_insecure_http: true only for local development)"
                    .to_owned(),
            );
        }
        _ => return Err("must be an https URL".to_owned()),
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err("must not embed credentials".to_owned());
    }
    if parsed.fragment().is_some() {
        return Err("must not carry a fragment".to_owned());
    }
    let Some(host) = parsed.host() else {
        return Err("has no host".to_owned());
    };
    if !policy.allow_private_network && host_is_private(&host) {
        return Err(PRIVATE_TARGET.to_owned());
    }
    Ok(())
}

fn host_is_private(host: &url::Host<&str>) -> bool {
    match host {
        url::Host::Ipv4(v4) => is_private_address(&IpAddr::V4(*v4)),
        url::Host::Ipv6(v6) => is_private_address(&IpAddr::V6(*v6)),
        url::Host::Domain(name) => {
            let name = name.trim_end_matches('.').to_ascii_lowercase();
            name == "localhost" || name.ends_with(".localhost")
        }
    }
}

/// A token endpoint whose name resolved only to addresses the guard refuses.
#[derive(Debug)]
pub(crate) struct PrivateAddressRefused {
    host: String,
}

impl fmt::Display for PrivateAddressRefused {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "host `{}` resolves only to private, loopback or link-local addresses",
            self.host
        )
    }
}

impl Error for PrivateAddressRefused {}

/// DNS resolver that drops private, loopback and link-local addresses and
/// fails when nothing else is left. reqwest consults it for every new
/// connection, so a name that later rebinds to an internal address is still
/// refused.
///
/// Through an egress proxy reqwest resolves the proxy, not the endpoint, so
/// the proxy hosts resolve unfiltered and the proxy resolves the endpoint:
/// only [`check_endpoint`] applies to the endpoint's host then.
#[derive(Debug, Default)]
pub(crate) struct PublicAddressResolver {
    proxy_hosts: Vec<String>,
}

impl reqwest::dns::Resolve for PublicAddressResolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let host = name.as_str().to_owned();
        if self.proxy_hosts.contains(&normalize_host(&host)) {
            Box::pin(resolve_any(host))
        } else {
            Box::pin(resolve_public(host))
        }
    }
}

/// The variables reqwest reads its system proxy from.
const PROXY_ENV_VARS: [&str; 6] = [
    "ALL_PROXY",
    "all_proxy",
    "HTTPS_PROXY",
    "https_proxy",
    "HTTP_PROXY",
    "http_proxy",
];

fn env_proxy_hosts() -> Vec<String> {
    PROXY_ENV_VARS
        .iter()
        .filter_map(|var| std::env::var(var).ok())
        .filter_map(|value| proxy_host(&value))
        .collect()
}

/// The host name in a proxy setting, with or without a scheme. `None` for
/// an IP literal, which reqwest connects to without resolving.
fn proxy_host(value: &str) -> Option<String> {
    let value = value.trim();
    if value.is_empty() {
        return None;
    }
    let parsed = if value.contains("://") {
        url::Url::parse(value)
    } else {
        url::Url::parse(&format!("http://{value}"))
    };
    match parsed.ok()?.host()? {
        url::Host::Domain(name) => Some(normalize_host(name)),
        url::Host::Ipv4(_) | url::Host::Ipv6(_) => None,
    }
}

fn normalize_host(name: &str) -> String {
    name.trim_end_matches('.').to_ascii_lowercase()
}

async fn resolve_any(host: String) -> Result<reqwest::dns::Addrs, Box<dyn Error + Send + Sync>> {
    let resolved: Vec<SocketAddr> = tokio::net::lookup_host((host.as_str(), 0)).await?.collect();
    Ok(Box::new(resolved.into_iter()))
}

async fn resolve_public(host: String) -> Result<reqwest::dns::Addrs, Box<dyn Error + Send + Sync>> {
    let resolved: Vec<SocketAddr> = tokio::net::lookup_host((host.as_str(), 0)).await?.collect();
    if resolved.is_empty() {
        return Err(format!("DNS returned no addresses for `{host}`").into());
    }
    let public: Vec<SocketAddr> = resolved
        .into_iter()
        .filter(|addr| !is_private_address(&addr.ip()))
        .collect();
    if public.is_empty() {
        metrics::counter!("mcpg_dns_rebinding_blocked_total", "host" => host.clone()).increment(1);
        return Err(Box::new(PrivateAddressRefused { host }));
    }
    Ok(Box::new(public.into_iter()))
}

/// Whether `err`, or anything in its source chain, is a guard refusal.
pub(crate) fn is_private_address_refusal(err: &(dyn Error + 'static)) -> bool {
    let mut current = Some(err);
    while let Some(e) = current {
        if e.is::<PrivateAddressRefused>() {
            return true;
        }
        // `io::Error::source` skips the error it wraps, so look inside.
        if let Some(io) = e.downcast_ref::<std::io::Error>()
            && io
                .get_ref()
                .is_some_and(|inner| inner.is::<PrivateAddressRefused>())
        {
            return true;
        }
        current = e.source();
    }
    false
}

/// HTTP client for token requests. Redirects are never followed: the
/// credentials in the request would go to a host no check has seen.
pub(crate) fn build_client(guard_private_network: bool) -> reqwest::Client {
    let proxy_hosts = if guard_private_network {
        Some(env_proxy_hosts())
    } else {
        None
    };
    client_builder(proxy_hosts)
        .build()
        .expect("token-endpoint HTTP client builds with a static configuration")
}

/// `proxy_hosts` is `Some` for a guarded client: the hosts exempt from the
/// private-address filter. reqwest reads its proxy variables when the
/// client is built, as [`build_client`] does.
fn client_builder(proxy_hosts: Option<Vec<String>>) -> reqwest::ClientBuilder {
    let builder = reqwest::Client::builder().redirect(reqwest::redirect::Policy::none());
    match proxy_hosts {
        Some(proxy_hosts) => builder.dns_resolver(PublicAddressResolver { proxy_hosts }),
        None => builder,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::any;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const STRICT: EgressPolicy = EgressPolicy {
        allow_insecure_http: false,
        allow_private_network: false,
    };

    #[test]
    fn https_public_endpoint_passes() {
        assert!(check_endpoint("https://idp.example.com/oauth2/v1/token", STRICT).is_ok());
    }

    #[test]
    fn http_needs_the_insecure_opt_in() {
        let url = "http://idp.example.com/token";
        assert!(check_endpoint(url, STRICT).unwrap_err().contains("https"));
        let relaxed = EgressPolicy {
            allow_insecure_http: true,
            ..STRICT
        };
        assert!(check_endpoint(url, relaxed).is_ok());
    }

    #[test]
    fn other_schemes_and_malformed_urls_are_refused() {
        for url in [
            "ftp://idp.example.com/token",
            "file:///etc/passwd",
            "not a url",
        ] {
            assert!(check_endpoint(url, STRICT).is_err(), "{url}");
        }
    }

    #[test]
    fn private_hosts_need_the_private_network_opt_in() {
        for url in [
            "https://127.0.0.1/token",
            "https://10.1.2.3/token",
            "https://169.254.169.254/token",
            "https://[::1]/token",
            "https://[::ffff:127.0.0.1]/token",
            "https://localhost/token",
            "https://idp.localhost./token",
        ] {
            let err = check_endpoint(url, STRICT).unwrap_err();
            assert!(err.contains("allow_private_network"), "{url}: {err}");
            let relaxed = EgressPolicy {
                allow_private_network: true,
                ..STRICT
            };
            assert!(check_endpoint(url, relaxed).is_ok(), "{url}");
        }
    }

    #[test]
    fn credentials_and_fragments_are_refused_without_echo() {
        let err = check_endpoint("https://user:hunter2@idp.example.com/token", STRICT).unwrap_err();
        assert!(
            err.contains("credentials") && !err.contains("hunter2"),
            "{err}"
        );
        assert!(check_endpoint("https://idp.example.com/token#x", STRICT).is_err());
    }

    #[tokio::test]
    async fn resolver_refuses_names_that_resolve_to_loopback() {
        let err = match resolve_public("localhost".to_owned()).await {
            Ok(_) => panic!("localhost must be refused"),
            Err(err) => err,
        };
        assert!(err.is::<PrivateAddressRefused>(), "{err}");
    }

    #[test]
    fn proxy_host_reads_the_name_from_every_proxy_setting_shape() {
        for (value, host) in [
            ("http://proxy.corp:3128", Some("proxy.corp")),
            ("proxy.corp:3128", Some("proxy.corp")),
            ("https://user:pw@Proxy.Corp.:8443/", Some("proxy.corp")),
            ("  http://egress.internal  ", Some("egress.internal")),
            ("http://10.0.0.5:3128", None),
            ("http://[fd00::5]:3128", None),
            ("", None),
        ] {
            assert_eq!(proxy_host(value).as_deref(), host, "{value:?}");
        }
    }

    #[tokio::test]
    async fn resolver_resolves_a_proxy_host_on_a_private_address() {
        let resolver = PublicAddressResolver {
            proxy_hosts: vec!["localhost".to_owned()],
        };
        let name: reqwest::dns::Name = "LocalHost".parse().unwrap();
        let addrs: Vec<SocketAddr> = reqwest::dns::Resolve::resolve(&resolver, name)
            .await
            .expect("the proxy host resolves")
            .collect();
        assert!(addrs.iter().all(|a| a.ip().is_loopback()), "{addrs:?}");
        assert!(!addrs.is_empty());
    }

    /// A proxy on a private address carries the request; without the
    /// exemption the guard refuses the proxy's own name.
    #[tokio::test]
    async fn guarded_client_reaches_the_endpoint_through_a_private_proxy() {
        let proxy = MockServer::start().await;
        Mock::given(any())
            .respond_with(ResponseTemplate::new(204))
            .expect(1)
            .mount(&proxy)
            .await;
        let proxy_url = format!("http://localhost:{}", proxy.address().port());
        let via_proxy = |proxy_hosts: Vec<String>| {
            client_builder(Some(proxy_hosts))
                .proxy(reqwest::Proxy::http(&proxy_url).unwrap())
                .build()
                .unwrap()
        };

        let response = via_proxy(vec!["localhost".to_owned()])
            .post("http://token.example.test/token")
            .send()
            .await
            .unwrap();
        assert_eq!(response.status().as_u16(), 204);

        let err = via_proxy(Vec::new())
            .post("http://token.example.test/token")
            .send()
            .await
            .unwrap_err();
        assert!(is_private_address_refusal(&err), "{err:?}");
    }

    #[tokio::test]
    async fn guarded_client_never_connects_to_a_private_address() {
        let server = MockServer::start().await;
        Mock::given(any())
            .respond_with(ResponseTemplate::new(200))
            .expect(0)
            .mount(&server)
            .await;
        let port = server.address().port();
        let err = build_client(true)
            .post(format!("http://localhost:{port}/token"))
            .send()
            .await
            .unwrap_err();
        assert!(is_private_address_refusal(&err), "{err:?}");
    }

    #[tokio::test]
    async fn unguarded_client_reaches_a_private_address() {
        let server = MockServer::start().await;
        Mock::given(any())
            .respond_with(ResponseTemplate::new(204))
            .expect(1)
            .mount(&server)
            .await;
        let port = server.address().port();
        let response = build_client(false)
            .post(format!("http://localhost:{port}/token"))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status().as_u16(), 204);
    }

    #[tokio::test]
    async fn redirects_are_not_followed() {
        let server = MockServer::start().await;
        Mock::given(wiremock::matchers::path("/token"))
            .respond_with(ResponseTemplate::new(307).insert_header("location", "/elsewhere"))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(wiremock::matchers::path("/elsewhere"))
            .respond_with(ResponseTemplate::new(200))
            .expect(0)
            .mount(&server)
            .await;
        let response = build_client(false)
            .post(format!("{}/token", server.uri()))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status().as_u16(), 307);
    }
}
