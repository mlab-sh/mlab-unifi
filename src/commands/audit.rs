//! `audit` — every graded check in one report.
//!
//! Fetches what the checks need, once, and hands it to [`crate::audit`], which
//! holds the rules and knows nothing about the network. This file is only
//! collection and rendering.

use anyhow::Result;
use clap::Args;
use serde_json::{json, Value};

use crate::audit::{self as rules, Severity};
use crate::cli::Ctx;
use crate::ui::{self, render};
use crate::unifi::{self, esc, site, Client, Surface};

#[derive(Args, Debug)]
pub struct AuditArgs {
    /// Hide anything below this severity
    #[arg(long, default_value = "low",
          value_parser = ["critical", "high", "medium", "low"])]
    pub min_severity: String,

    /// Print the remediation for every finding, not only the severe ones
    #[arg(long)]
    pub fixes: bool,
}

pub async fn run(c: &Client, ctx: &Ctx, a: &AuditArgs) -> Result<()> {
    unifi::local_only(c, "audit")?;
    let site = site::resolve(c, &ctx.profile.site).await?;
    let legacy = site::resolve_legacy(c, &site).await?;

    // Every fetch degrades on its own: a surface that has moved costs the
    // checks that needed it, never the report.
    let spinner = ui::Spinner::start("Collecting");
    let input = rules::Input {
        settings: legacy_map(c, &legacy, "rest/setting").await,
        wlans: legacy_list(c, &legacy, "rest/wlanconf").await,
        forwards: legacy_list(c, &legacy, "rest/portforward").await,
        networks: legacy_list(c, &legacy, "rest/networkconf").await,
        devices: legacy_list(c, &legacy, "stat/device").await,
        zones: documented(c, &site, "firewall/zones").await,
        policies: documented(c, &site, "firewall/policies").await,
    };
    spinner.clear();

    let findings = rules::run(&input);
    let floor = match a.min_severity.as_str() {
        "critical" => Severity::Critical,
        "high" => Severity::High,
        "medium" => Severity::Medium,
        _ => Severity::Low,
    };
    let shown: Vec<&rules::Finding> = findings.iter().filter(|f| f.severity >= floor).collect();

    let rows: Vec<Value> = shown
        .iter()
        .map(|f| {
            json!({
                "severity": f.severity.label(),
                "area": f.area,
                "finding": f.title,
                "detail": f.detail,
                "fix": f.fix,
            })
        })
        .collect();

    render::heading(&format!("Audit of {}", ctx.profile.host));
    render::list(&rows, render::AUDIT_COLS);
    render::count(rows.len(), "finding");

    if render::is_json() {
        return Ok(());
    }

    let count = |s: Severity| findings.iter().filter(|f| f.severity == s).count();
    ui::info(&format!(
        "{} critical, {} high, {} medium, {} low",
        count(Severity::Critical),
        count(Severity::High),
        count(Severity::Medium),
        count(Severity::Low)
    ));

    // A check that could not run is neither a pass nor a failure, and saying so
    // is what stops an incomplete audit from reading as a clean one.
    let skipped = rules::skipped(&input);
    if !skipped.is_empty() {
        ui::warning(&format!(
            "{} check group(s) could not run and are not counted either way: {}",
            skipped.len(),
            skipped.join(", ")
        ));
    }

    // Detail and remediation, for what is worth acting on now.
    for f in shown
        .iter()
        .filter(|f| a.fixes || f.severity >= Severity::High)
    {
        println!();
        println!("  {} · {}", f.severity.label().to_uppercase(), f.title);
        println!("    {}", f.detail);
        println!("    fix: {}", f.fix);
    }

    if findings.is_empty() {
        ui::success("no finding, on the checks that could run");
    }
    Ok(())
}

async fn legacy_list(c: &Client, legacy: &str, path: &str) -> Vec<Value> {
    c.list_on(Surface::Legacy, &format!("/s/{}/{path}", esc(legacy)), &[])
        .await
        .unwrap_or_default()
}

async fn legacy_map(
    c: &Client,
    legacy: &str,
    path: &str,
) -> std::collections::HashMap<String, Value> {
    legacy_list(c, legacy, path)
        .await
        .into_iter()
        .filter_map(|s| Some((s.get("key")?.as_str()?.to_string(), s)))
        .collect()
}

async fn documented(c: &Client, site: &str, path: &str) -> Vec<Value> {
    c.list(&format!("/sites/{}/{path}", esc(site)), &[], 0, None)
        .await
        .unwrap_or_default()
}
