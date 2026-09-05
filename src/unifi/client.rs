//! HTTP handler for every UniFi API this CLI speaks to.
//!
//! A local console answers on three separate surfaces, all with the same
//! `X-API-KEY` header (see [`Surface`]); the cloud is a fourth base URL. One
//! client covers them because only the base URL, the envelope and the paging
//! style differ.

use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use reqwest::header::{HeaderMap, HeaderValue, ACCEPT, CONTENT_TYPE};
use reqwest::{Method, StatusCode};
use serde_json::Value;

use crate::unifi::config::{normalize_host, Mode, Profile};

/// Cap on a response body, so a misbehaving console cannot exhaust memory.
const MAX_RESPONSE_BYTES: usize = 32 << 20;

/// Default page size when walking every page.
const PAGE_SIZE: u32 = 200;

/// Cloud base URL, overridable through `UNIFI_SITE_MANAGER_URL` for testing.
const CLOUD_BASE: &str = "https://api.ui.com";

/// Which API surface of a console a request goes to.
///
/// Only [`Surface::Integration`] is documented by Ubiquiti. The other two are
/// what the web app calls for itself: far richer, and free to disappear on any
/// firmware update — so anything built on them degrades rather than fails.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Surface {
    /// `/proxy/network/integration/v1` — documented, offset paging, site UUID.
    Integration,
    /// `/proxy/network/api` — the legacy API: `{meta,data}` envelope, no
    /// paging, and the short site name rather than the UUID.
    Legacy,
    /// `/proxy/network/v2/api` — plain JSON, no envelope, no paging.
    V2,
}

/// A non-2xx response from either API.
#[derive(Debug)]
pub struct ApiError {
    pub status: StatusCode,
    pub code: String,
    pub message: String,
    pub retry_after: Option<u64>,
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "API error {}", self.status.as_u16())?;
        if !self.code.is_empty() {
            write!(f, " [{}]", self.code)?;
        }
        if !self.message.is_empty() {
            write!(f, ": {}", self.message)?;
        }
        if let Some(ra) = self.retry_after {
            write!(f, " (retry after {ra}s)")?;
        }
        if self.status == StatusCode::UNAUTHORIZED || self.status == StatusCode::FORBIDDEN {
            write!(
                f,
                "\nhint: check the API key, and that it belongs to this console"
            )?;
        }
        Ok(())
    }
}

impl std::error::Error for ApiError {}

/// A configured connection to one UniFi endpoint.
pub struct Client {
    http: reqwest::Client,
    /// Base URL of the documented surface; also what `base()` reports.
    base: String,
    /// `https://<host>`, the root the other surfaces hang off. Empty in cloud
    /// mode, which has only one surface.
    root: String,
    mode: Mode,
}

impl Client {
    /// Build a client from a validated profile.
    pub fn new(profile: &Profile, timeout: Duration) -> Result<Self> {
        profile.validate()?;

        let mut root = String::new();
        let base = match profile.mode {
            Mode::Local => {
                let host = normalize_host(&profile.host)?;
                root = format!("https://{host}");
                format!("{root}/proxy/network/integration/v1")
            }
            Mode::Cloud => std::env::var("UNIFI_SITE_MANAGER_URL")
                .ok()
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| CLOUD_BASE.to_string())
                .trim_end_matches('/')
                .to_string(),
        };

        let mut headers = HeaderMap::new();
        let mut key = HeaderValue::from_str(profile.api_key.trim())
            .context("api key contains characters that cannot go in a header")?;
        key.set_sensitive(true);
        headers.insert("X-API-KEY", key);
        headers.insert(ACCEPT, HeaderValue::from_static("application/json"));

        let http = reqwest::Client::builder()
            .default_headers(headers)
            .timeout(timeout)
            .danger_accept_invalid_certs(profile.insecure())
            // The API key rides in a default header, which reqwest would replay
            // on a cross-host redirect; refuse to follow one instead.
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .context("building the HTTP client")?;

        Ok(Client {
            http,
            base,
            root,
            mode: profile.mode,
        })
    }

    pub fn mode(&self) -> Mode {
        self.mode
    }

    pub fn base(&self) -> &str {
        &self.base
    }

    /// Base URL of one surface. Only the documented one exists in cloud mode.
    fn surface_base(&self, surface: Surface) -> Result<String> {
        if self.mode == Mode::Cloud {
            return match surface {
                Surface::Integration => Ok(self.base.clone()),
                _ => Err(anyhow!("the Site Manager API has no legacy or v2 surface")),
            };
        }
        Ok(match surface {
            Surface::Integration => self.base.clone(),
            Surface::Legacy => format!("{}/proxy/network/api", self.root),
            Surface::V2 => format!("{}/proxy/network/v2/api", self.root),
        })
    }

    /// The core handler: one request, one parsed JSON body.
    ///
    /// `path` is relative to the base URL and starts with `/`; it is sent as
    /// given (it legitimately contains slashes), so callers escape their own
    /// path segments. Every other command in the CLI goes through here.
    pub async fn request(
        &self,
        method: Method,
        path: &str,
        query: &[(String, String)],
        body: Option<&Value>,
    ) -> Result<Value> {
        self.request_on(Surface::Integration, method, path, query, body)
            .await
    }

    /// The same, against a chosen surface. The legacy `{meta,data}` envelope is
    /// checked and unwrapped here so callers only ever see the payload.
    pub async fn request_on(
        &self,
        surface: Surface,
        method: Method,
        path: &str,
        query: &[(String, String)],
        body: Option<&Value>,
    ) -> Result<Value> {
        let v = self.raw(surface, method, path, query, body).await?;
        if surface == Surface::Legacy {
            return unwrap_legacy(v);
        }
        Ok(v)
    }

    async fn raw(
        &self,
        surface: Surface,
        method: Method,
        path: &str,
        query: &[(String, String)],
        body: Option<&Value>,
    ) -> Result<Value> {
        let url = format!("{}{}", self.surface_base(surface)?, path);
        let mut req = self.http.request(method.clone(), &url);
        if !query.is_empty() {
            req = req.query(query);
        }
        if let Some(b) = body {
            req = req.header(CONTENT_TYPE, "application/json").json(b);
        }

        let resp = req.send().await.map_err(|e| {
            // reqwest hides the interesting part (certificate, DNS, refused) in
            // the source chain, so flatten it before adding a hint.
            let cause = error_chain(&e);
            let mut msg = format!("{method} {url}: {cause}");
            let lower = cause.to_lowercase();
            if lower.contains("certificate") || lower.contains("unknownissuer") || lower.contains("tls") {
                msg.push_str(
                    "\nhint: consoles serve a self-signed certificate; drop --secure, or pass --insecure",
                );
            } else if e.is_timeout() {
                msg.push_str("\nhint: raise --timeout");
            } else if e.is_connect() && self.mode == Mode::Local {
                msg.push_str(
                    "\nhint: is the console reachable, and is it UniFi Network 9.x+ with the Integration API turned on?",
                );
            }
            anyhow!(msg)
        })?;

        let status = resp.status();
        if status.is_redirection() {
            let to = resp
                .headers()
                .get(reqwest::header::LOCATION)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("(no Location)");
            return Err(anyhow!(
                "{method} {url} redirected to {to}; not following it, the API key would leak to the new host"
            ));
        }

        let retry_after = resp
            .headers()
            .get(reqwest::header::RETRY_AFTER)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<u64>().ok());

        let bytes = resp.bytes().await.context("reading the response body")?;
        if bytes.len() > MAX_RESPONSE_BYTES {
            return Err(anyhow!("response body over {MAX_RESPONSE_BYTES} bytes"));
        }

        if !status.is_success() {
            return Err(parse_error(status, &bytes, retry_after).into());
        }
        if bytes.is_empty() {
            return Ok(Value::Null);
        }
        serde_json::from_slice(&bytes).with_context(|| {
            let preview: String = String::from_utf8_lossy(&bytes).chars().take(200).collect();
            format!("decoding the response of {method} {url}: {preview}")
        })
    }

    /// A list endpoint on the documented surface.
    ///
    /// `limit` is what decides how much is fetched: `None` walks every page
    /// from `offset`, `Some(n)` returns exactly that one page. Both paging
    /// styles are handled here so callers never see them.
    pub async fn list(
        &self,
        path: &str,
        query: &[(String, String)],
        offset: u32,
        limit: Option<u32>,
    ) -> Result<Vec<Value>> {
        match self.mode {
            Mode::Local => self.list_offset(path, query, offset, limit).await,
            Mode::Cloud => self.list_cursor(path, query, limit).await,
        }
    }

    /// A list on one of the internal surfaces. Neither paginates: the console
    /// returns the whole collection in one response.
    pub async fn list_on(
        &self,
        surface: Surface,
        path: &str,
        query: &[(String, String)],
    ) -> Result<Vec<Value>> {
        if surface == Surface::Integration {
            return self.list(path, query, 0, None).await;
        }
        let v = self
            .request_on(surface, Method::GET, path, query, None)
            .await?;
        Ok(array_of(&v))
    }

    /// Local paging: `offset` / `limit`, stop once `totalCount` is covered.
    async fn list_offset(
        &self,
        path: &str,
        query: &[(String, String)],
        offset: u32,
        limit: Option<u32>,
    ) -> Result<Vec<Value>> {
        let page_size = limit.unwrap_or(PAGE_SIZE);
        let mut out = Vec::new();
        let mut at = offset;

        loop {
            let mut q = query.to_vec();
            q.push(("offset".into(), at.to_string()));
            q.push(("limit".into(), page_size.to_string()));

            let page = self.request(Method::GET, path, &q, None).await?;
            let items = page.get("data").map(array_of).unwrap_or_default();
            let total = page.get("totalCount").and_then(Value::as_u64).unwrap_or(0);

            let got = items.len() as u32;
            out.extend(items);
            if limit.is_some() || got == 0 || (at + got) as u64 >= total {
                break;
            }
            at += got;
        }
        Ok(out)
    }

    /// Cloud paging: `pageSize` / `nextToken`.
    async fn list_cursor(
        &self,
        path: &str,
        query: &[(String, String)],
        limit: Option<u32>,
    ) -> Result<Vec<Value>> {
        let mut out = Vec::new();
        let mut next: Option<String> = None;

        loop {
            let mut q = query.to_vec();
            if let Some(n) = limit {
                q.push(("pageSize".into(), n.to_string()));
            }
            if let Some(tok) = &next {
                q.push(("nextToken".into(), tok.clone()));
            }

            let page = self.request(Method::GET, path, &q, None).await?;
            out.extend(page.get("data").map(array_of).unwrap_or_default());

            next = page
                .get("nextToken")
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty())
                .map(str::to_string);
            if limit.is_some() || next.is_none() {
                break;
            }
        }
        Ok(out)
    }

    /// GET a single object, unwrapping the cloud's `{ "data": ... }` envelope.
    pub async fn get_one(&self, path: &str) -> Result<Value> {
        let v = self.request(Method::GET, path, &[], None).await?;
        Ok(unwrap_data(v))
    }
}

/// Turn an API JSON error body into a typed error.
fn parse_error(status: StatusCode, body: &[u8], retry_after: Option<u64>) -> ApiError {
    let text = String::from_utf8_lossy(body).trim().to_string();

    let (code, message) = match serde_json::from_slice::<Value>(body) {
        Ok(v) => {
            let code = v
                .get("code")
                .or_else(|| v.get("statusName"))
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string();
            let message = v
                .get("message")
                .and_then(Value::as_str)
                .map(str::to_string)
                .unwrap_or_else(|| text.clone());
            (code, message)
        }
        Err(_) => (String::new(), text),
    };

    ApiError {
        status,
        code,
        message,
        retry_after,
    }
}

/// Check and strip the legacy `{meta:{rc,msg},data:[...]}` envelope.
///
/// The legacy API answers 200 with `rc: "error"` for a refusal, so the status
/// code alone would let a failure through as an empty list.
fn unwrap_legacy(v: Value) -> Result<Value> {
    let Some(meta) = v.get("meta") else {
        return Ok(v); // not enveloped after all; pass it through
    };
    if meta.get("rc").and_then(Value::as_str) == Some("error") {
        let msg = meta
            .get("msg")
            .and_then(Value::as_str)
            .unwrap_or("unknown error");
        return Err(anyhow!("legacy API error: {msg}"));
    }
    Ok(v.get("data").cloned().unwrap_or(Value::Null))
}

/// Flatten an error and its sources into one line.
fn error_chain(e: &dyn std::error::Error) -> String {
    let mut parts = vec![e.to_string()];
    let mut src = e.source();
    while let Some(s) = src {
        parts.push(s.to_string());
        src = s.source();
    }
    parts.join(": ")
}

/// A JSON value as a vector: arrays pass through, `null` is empty.
fn array_of(v: &Value) -> Vec<Value> {
    match v {
        Value::Array(a) => a.clone(),
        Value::Null => Vec::new(),
        other => vec![other.clone()],
    }
}

/// Return the inner `data` of a single-object response, or the body as-is.
pub fn unwrap_data(v: Value) -> Value {
    match v {
        Value::Object(ref map) if map.contains_key("data") && map.len() <= 2 => {
            map.get("data").cloned().unwrap_or(Value::Null)
        }
        other => other,
    }
}

/// Percent-escape one path segment (ids can contain `/` in theory).
pub fn esc(segment: &str) -> String {
    let mut out = String::with_capacity(segment.len());
    for b in segment.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn esc_escapes_path_separators() {
        assert_eq!(esc("abc-123_x.y~z"), "abc-123_x.y~z");
        assert_eq!(esc("a/b c"), "a%2Fb%20c");
    }

    #[test]
    fn unwrap_data_only_unwraps_envelopes() {
        assert_eq!(unwrap_data(json!({"data": {"id": 1}})), json!({"id": 1}));
        let plain = json!({"id": 1, "name": "x", "data": 2});
        assert_eq!(
            unwrap_data(plain.clone()),
            plain,
            "a real field named data stays put"
        );
    }

    #[test]
    fn array_of_normalizes_page_data() {
        assert_eq!(array_of(&json!([1, 2])).len(), 2);
        assert!(array_of(&Value::Null).is_empty());
    }

    #[test]
    fn parse_error_reads_both_error_shapes() {
        let e = parse_error(
            StatusCode::NOT_FOUND,
            br#"{"code":"NF","message":"gone"}"#,
            None,
        );
        assert_eq!(e.code, "NF");
        assert_eq!(e.message, "gone");

        let e = parse_error(
            StatusCode::UNAUTHORIZED,
            br#"{"statusName":"Unauthorized"}"#,
            Some(3),
        );
        assert_eq!(e.code, "Unauthorized");
        assert!(e.to_string().contains("retry after 3s"));

        let e = parse_error(StatusCode::BAD_GATEWAY, b"<html>nope</html>", None);
        assert_eq!(e.message, "<html>nope</html>");
    }
}
