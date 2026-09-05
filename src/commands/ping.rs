//! `ping` — can this profile reach its API, and what is on the other end.

use anyhow::Result;
use reqwest::Method;
use serde_json::Value;

use crate::cli::Ctx;
use crate::ui::{self, render};
use crate::unifi::{Client, Mode};

pub async fn run(c: &Client, ctx: &Ctx) -> Result<()> {
    let started = std::time::Instant::now();

    let version = match c.mode() {
        Mode::Local => {
            let v = ui::spin(
                "Reaching the console",
                c.request(Method::GET, "/info", &[], None),
            )
            .await?;
            v.get("applicationVersion")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string()
        }
        Mode::Cloud => {
            ui::spin("Reaching api.ui.com", c.list("/v1/hosts", &[], 0, Some(1))).await?;
            String::new()
        }
    };
    let took = ui::elapsed(started.elapsed());

    if render::is_json() {
        render::print_json(&serde_json::json!({
            "profile": ctx.name,
            "mode": c.mode().to_string(),
            "endpoint": c.base(),
            "applicationVersion": version,
            "site": ctx.profile.site,
            "tlsVerified": !ctx.profile.insecure(),
            "elapsed": took,
        }));
        return Ok(());
    }

    ui::success(&format!("answered in {took}"));
    render::pairs(&[
        ("profile", format!("{} ({})", ctx.name, c.mode())),
        ("endpoint", c.base().to_string()),
        (
            "console",
            match c.mode() {
                Mode::Local => format!("UniFi Network {version}"),
                Mode::Cloud => "Site Manager".to_string(),
            },
        ),
        ("site", ctx.profile.site.clone()),
        (
            "tls",
            if ctx.profile.insecure() {
                "not verified"
            } else {
                "verified"
            }
            .to_string(),
        ),
    ]);
    Ok(())
}
