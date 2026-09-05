//! `login` — create or update a profile, prove it works, save it.

use std::io::IsTerminal;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use clap::Args;
use reqwest::Method;
use serde_json::Value;

use crate::cli::Overrides;
use crate::commands::prompt::{ask, ask_secret};
use crate::ui::{self, render};
use crate::unifi::{config, Client, Mode, Profile};

#[derive(Args, Debug)]
pub struct LoginArgs {
    /// Profile name to create or update
    #[arg(long, short = 'n', default_value = "default", value_name = "NAME")]
    pub name: String,

    /// Make this profile the default one
    #[arg(long)]
    pub set_default: bool,

    /// Save without checking that the credentials work
    #[arg(long)]
    pub no_test: bool,

    /// Never prompt; fail when something is missing
    #[arg(long)]
    pub non_interactive: bool,
}

pub async fn run(ov: &Overrides, args: &LoginArgs) -> Result<()> {
    let mut cfg = config::load()?;
    let existing = cfg.profiles.get(&args.name).cloned();
    let base = existing.clone().unwrap_or_default();
    let interactive = !args.non_interactive && std::io::stdin().is_terminal();

    let mode: Mode = match ov.mode.clone().or_else(|| config::env("MODE")) {
        Some(m) => m.parse()?,
        None if existing.is_some() => base.mode,
        None if interactive => ask("mode (local|cloud)", "local")?.parse()?,
        None => Mode::Local,
    };

    let mut host = ov
        .host
        .clone()
        .or_else(|| config::env("HOST"))
        .unwrap_or_else(|| base.host.clone());
    if mode == Mode::Local {
        if host.is_empty() {
            if !interactive {
                bail!("--host is required in local mode");
            }
            host = ask("console host (e.g. 192.168.1.1 or unifi.lan)", "")?;
        }
        host = config::normalize_host(&host)?;
    }

    let api_key = api_key(ov, &base, mode, interactive)?;

    let mut p = Profile {
        mode,
        host,
        api_key,
        site: ov.site.clone().unwrap_or_else(|| base.site.clone()),
        insecure: ov.insecure.or(base.insecure),
        output: ov.output.clone().or(base.output.clone()),
    };
    p.validate()?;

    if args.no_test {
        ui::warning("skipping the connection test (--no-test)");
    } else {
        verify(&mut p, interactive).await?;
    }

    let first = cfg.profiles.is_empty();
    cfg.profiles.insert(args.name.clone(), p.clone());
    if args.set_default || first || cfg.default_profile.is_none() {
        cfg.default_profile = Some(args.name.clone());
    }
    config::save(&cfg)?;

    ui::success(&format!(
        "saved profile {:?} to {}",
        args.name,
        config::path().display()
    ));
    render::one(&serde_json::to_value(p.redacted())?);
    Ok(())
}

/// A key from the flags, the environment, the stored profile, or the terminal.
fn api_key(ov: &Overrides, base: &Profile, mode: Mode, interactive: bool) -> Result<String> {
    let mut key = ov
        .api_key
        .clone()
        .or_else(|| config::env("API_KEY"))
        .unwrap_or_default();

    if key.is_empty() {
        if !base.api_key.is_empty() {
            ui::info(&format!(
                "keeping the stored API key ({})",
                config::redact(&base.api_key)
            ));
            key = base.api_key.clone();
        } else if interactive {
            key = ask_secret(match mode {
                Mode::Local => "API key (console: Settings -> Control Plane -> Integrations)",
                Mode::Cloud => "API key (unifi.ui.com -> API)",
            })?;
        } else {
            bail!("--api-key or UNIFI_API_KEY is required");
        }
    }

    if key.trim().is_empty() {
        bail!("the API key is empty");
    }
    Ok(key.trim().to_string())
}

/// Prove the profile works before it is written, and settle its site.
async fn verify(p: &mut Profile, interactive: bool) -> Result<()> {
    let c = Client::new(p, Duration::from_secs(30))?;

    match p.mode {
        Mode::Local => {
            let info = ui::spin(
                &format!("Testing {}", c.base()),
                c.request(Method::GET, "/info", &[], None),
            )
            .await?;
            let ver = info
                .get("applicationVersion")
                .and_then(Value::as_str)
                .unwrap_or("unknown");
            ui::success(&format!("connected to UniFi Network {ver}"));
            p.site = pick_site(&c, &p.site, interactive).await?;
        }
        Mode::Cloud => {
            let hosts = ui::spin(
                "Testing api.ui.com",
                c.list("/v1/hosts", &[], false, 0, Some(10)),
            )
            .await?;
            ui::success(&format!(
                "connected, {} host(s) on the account",
                hosts.len()
            ));
        }
    }

    if p.insecure() {
        ui::warning("TLS certificate verification is off for this profile");
    }
    Ok(())
}

/// Confirm the configured site, or choose one from the console.
async fn pick_site(c: &Client, want: &str, interactive: bool) -> Result<String> {
    let sites = ui::spin("Listing sites", c.list("/sites", &[], true, 0, None))
        .await
        .context("listing sites")?;
    let field = |v: &Value, k: &str| v.get(k).and_then(Value::as_str).unwrap_or("").to_string();

    if sites.is_empty() {
        ui::warning("this console reports no site");
        return Ok(want.to_string());
    }

    if !want.is_empty() {
        for s in &sites {
            if field(s, "id") == want || field(s, "name").eq_ignore_ascii_case(want) {
                return Ok(field(s, "id"));
            }
        }
        bail!("no site matches {want:?}");
    }

    if sites.len() == 1 {
        let id = field(&sites[0], "id");
        ui::info(&format!("site {} ({id})", field(&sites[0], "name")));
        return Ok(id);
    }

    eprintln!();
    for (i, s) in sites.iter().enumerate() {
        eprintln!("    [{}] {} ({})", i + 1, field(s, "name"), field(s, "id"));
    }
    eprintln!();
    if !interactive {
        bail!("several sites exist; re-run with --site NAME");
    }

    let idx: usize = ask("site number", "1")?.trim().parse().unwrap_or(1);
    let chosen = sites.get(idx.saturating_sub(1)).unwrap_or(&sites[0]);
    Ok(field(chosen, "id"))
}
