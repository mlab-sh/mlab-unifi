//! `live` — attach to a console's event stream and print what arrives.
//!
//! **The message format is not documented and has not been observed.** All
//! three channels accept the API key and hold the connection open, but no frame
//! arrived during any observation window on a quiet site, so nothing here
//! claims to know what a frame looks like.
//!
//! The command is therefore built to *find out*: it renders whatever structure
//! it can recognise, prints the rest verbatim rather than dropping it, and can
//! record everything to a file for later. When the shape is known, decoding it
//! properly is a small change in one function.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use clap::Args;
use futures_util::StreamExt;
use serde_json::Value;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::Connector;

use crate::cli::Ctx;
use crate::ui::{self, render};
use crate::unifi::{self, esc, iso8601, site, Client};

#[derive(Args, Debug)]
pub struct LiveArgs {
    /// Which stream to attach to
    #[arg(long, default_value = "network",
          value_parser = ["network", "protect-devices", "protect-events"])]
    pub channel: String,

    /// Stop after this many seconds instead of running until interrupted
    #[arg(long, value_name = "SECS")]
    pub for_seconds: Option<u64>,

    /// Stop after this many frames
    #[arg(long, value_name = "N")]
    pub max: Option<usize>,

    /// Print each frame exactly as it arrived, with no interpretation
    #[arg(long)]
    pub raw: bool,

    /// Append every frame to this file, one JSON object per line
    #[arg(long, value_name = "FILE")]
    pub record: Option<PathBuf>,
}

pub async fn run(c: &Client, ctx: &Ctx, a: &LiveArgs) -> Result<()> {
    unifi::local_only(c, "live")?;
    let site = site::resolve(c, &ctx.profile.site).await?;
    let legacy = site::resolve_legacy(c, &site).await?;

    let host = unifi::config::normalize_host(&ctx.profile.host)?;
    let path = match a.channel.as_str() {
        "protect-devices" => "/proxy/protect/integration/v1/subscribe/devices".to_string(),
        "protect-events" => "/proxy/protect/integration/v1/subscribe/events".to_string(),
        _ => format!("/proxy/network/wss/s/{}/events", esc(&legacy)),
    };
    let url = format!("wss://{host}{path}");

    let mut request = url
        .as_str()
        .into_client_request()
        .context("building the request")?;
    request.headers_mut().insert(
        "X-API-KEY",
        ctx.profile.api_key.parse().context("api key in a header")?,
    );

    // Same decision as every other request to a console: the certificate is
    // self-signed, and verifying it here while accepting it everywhere else
    // would only make the command unusable.
    let connector = if ctx.profile.insecure() {
        Some(Connector::Rustls(Arc::new(unverified_tls()?)))
    } else {
        None
    };

    let (stream, response) = ui::spin(
        &format!("Attaching to {url}"),
        tokio_tungstenite::connect_async_tls_with_config(request, None, false, connector),
    )
    .await
    .with_context(|| format!("connecting to {url}"))?;

    ui::success(&format!("attached, {}", response.status()));
    if !render::is_json() {
        ui::info(
            "the frame format of this stream is undocumented and was never observed during \
             development; frames are printed as they arrive, use --raw to see them verbatim",
        );
    }

    let deadline = a
        .for_seconds
        .map(|s| tokio::time::Instant::now() + Duration::from_secs(s));
    let mut recorder = match &a.record {
        Some(p) => Some(open_record(p)?),
        None => None,
    };

    let mut stream = stream;
    let mut seen = 0usize;
    let mut closed_early = false;
    let mut interrupted = false;
    let started = Instant::now();

    loop {
        // The deadline is absolute, so rebuilding the timer each turn is
        // correct. Without one it never fires, which is what running until
        // interrupted means here.
        let timer = async {
            match deadline {
                Some(end) => tokio::time::sleep_until(end).await,
                None => std::future::pending::<()>().await,
            }
        };

        let message = tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                interrupted = true;
                break;
            }
            _ = timer => break,
            m = stream.next() => match m {
                Some(m) => m.context("reading from the stream")?,
                None => break,
            },
        };

        let payload = match message {
            Message::Text(t) => t.to_string(),
            Message::Binary(b) => String::from_utf8_lossy(&b).to_string(),
            Message::Close(f) => {
                // The close code is the only diagnostic these channels give: an
                // immediate close means the upgrade was accepted by the proxy
                // and refused by the application behind it.
                let detail = f
                    .map(|f| {
                        let reason = if f.reason.is_empty() {
                            "no reason given".to_string()
                        } else {
                            f.reason.to_string()
                        };
                        format!(" with code {} ({reason})", u16::from(f.code))
                    })
                    .unwrap_or_default();
                closed_early = started.elapsed() < Duration::from_secs(2);
                ui::warning(&format!(
                    "the console closed the stream{detail} after {:.1}s",
                    started.elapsed().as_secs_f64()
                ));
                break;
            }
            // Ping and pong are answered by the library; nothing to show.
            _ => continue,
        };

        seen += 1;
        if let Some(w) = recorder.as_mut() {
            use std::io::Write;
            let _ = writeln!(w, "{payload}");
        }
        emit(&payload, a.raw);

        if a.max.is_some_and(|n| seen >= n) {
            break;
        }
    }

    // Leave politely rather than dropping the socket, and put the terminal back
    // the way it was: an interrupt runs no destructors.
    let _ = stream.close(None).await;
    if interrupted {
        ui::restore();
        ui::info("interrupted");
    }

    // An upgrade accepted and then closed straight away is the signature of a
    // channel the proxy admits and the application behind it does not.
    if seen == 0 && closed_early && !render::is_json() {
        ui::warning(
            "the stream closed immediately without sending anything, which is what this \
             channel does when the API key is not what it wants; the Protect channels \
             behave differently and stay open",
        );
    }

    if !render::is_json() {
        match seen {
            0 => ui::info(
                "no frame arrived: these streams are silent until something happens on the \
                 site, so an empty run says the network was quiet, not that the channel is dead",
            ),
            n => ui::info(&format!("{n} frame(s)")),
        }
        if let Some(p) = &a.record {
            ui::info(&format!("recorded to {}", p.display()));
        }
    }
    Ok(())
}

/// Print one frame.
///
/// In JSON mode each frame is one line, because a stream has no end and cannot
/// be an array. That is deliberately different from every other command here.
fn emit(payload: &str, raw: bool) {
    if render::is_json() || raw {
        println!("{payload}");
        return;
    }

    let Ok(v) = serde_json::from_str::<Value>(payload) else {
        // Not JSON at all, which is itself worth seeing rather than hiding.
        println!("{payload}");
        return;
    };

    render::heading(&format!("{}  {}", iso8601(now()), label(&v)));
    render::one(&v);
}

/// A short name for a frame, from whatever the payload offers.
///
/// The legacy event envelope puts one in `meta.message`; nothing else is known,
/// so anything else falls back to naming the keys present.
fn label(v: &Value) -> String {
    if let Some(m) = v.pointer("/meta/message").and_then(Value::as_str) {
        return m.to_string();
    }
    for key in ["type", "event", "action", "modelKey"] {
        if let Some(s) = v.get(key).and_then(Value::as_str) {
            return s.to_string();
        }
    }
    match v.as_object() {
        Some(o) => o.keys().take(4).cloned().collect::<Vec<_>>().join(", "),
        None => "frame".to_string(),
    }
}

fn open_record(path: &PathBuf) -> Result<std::fs::File> {
    std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .with_context(|| format!("opening {}", path.display()))
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// A TLS configuration that accepts a console's self-signed certificate.
///
/// The same posture the HTTP client takes in local mode, expressed against
/// rustls directly because the WebSocket library needs a configuration rather
/// than a flag. It is only ever built when the profile already says so.
fn unverified_tls() -> Result<rustls::ClientConfig> {
    let provider = rustls::crypto::CryptoProvider::get_default()
        .cloned()
        .unwrap_or_else(|| Arc::new(rustls::crypto::ring::default_provider()));

    Ok(rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .context("selecting TLS protocol versions")?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyCertificate))
        .with_no_client_auth())
}

/// Accepts any certificate. Reachable only through `--insecure`, which is the
/// default in local mode because consoles ship a self-signed certificate.
#[derive(Debug)]
struct AcceptAnyCertificate;

impl rustls::client::danger::ServerCertVerifier for AcceptAnyCertificate {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_frame_is_named_from_whatever_it_offers() {
        assert_eq!(
            label(&json!({"meta": {"message": "device:sync"}})),
            "device:sync"
        );
        assert_eq!(label(&json!({"type": "add"})), "add");
        assert_eq!(label(&json!({"modelKey": "camera"})), "camera");
    }

    #[test]
    fn an_unrecognised_frame_is_described_rather_than_called_unknown() {
        // The format is undocumented, so naming the keys present is more use
        // than a generic label when a new shape turns up.
        assert_eq!(label(&json!({"alpha": 1, "beta": 2})), "alpha, beta");
        assert_eq!(label(&json!([1, 2])), "frame");
    }
}
