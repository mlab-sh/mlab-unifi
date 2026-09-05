//! `devices` — list, inspect, and act on the hardware of a site.

use std::collections::HashMap;

use anyhow::{bail, Context, Result};
use clap::Subcommand;
use reqwest::Method;
use serde_json::{json, Value};

use crate::cli::{Ctx, ListArgs};
use crate::enrich::{advisories, firmware};
use crate::ui::{self, render};
use crate::unifi::{self, esc, site, Client, Mode, Surface};

#[derive(Subcommand, Debug)]
pub enum DeviceCmd {
    /// List devices
    List {
        #[command(flatten)]
        page: ListArgs,
        /// Also list published advisories naming these models, through mlab.sh
        #[arg(long)]
        allow_web: bool,
        /// Skip the firmware posture, and list only what the documented API returns
        #[arg(long)]
        no_resolve: bool,
    },
    /// Show one device, by integration id or by MAC address
    Get {
        #[arg(value_name = "ID|MAC")]
        id: String,
    },
    /// Latest statistics for one device (local only)
    Stats {
        #[arg(value_name = "ID|MAC")]
        id: String,
    },
    /// Restart a device (local only)
    Restart {
        #[arg(value_name = "ID|MAC")]
        id: String,
    },
    /// Power-cycle one PoE port of a device (local only)
    PowerCycle {
        #[arg(value_name = "ID|MAC")]
        id: String,
        /// Port index
        #[arg(long, value_name = "IDX")]
        port: u32,
    },
}

pub async fn run(c: &Client, ctx: &Ctx, cmd: DeviceCmd) -> Result<()> {
    match cmd {
        DeviceCmd::List {
            page,
            allow_web,
            no_resolve,
        } => list(c, ctx, &page, allow_web, !no_resolve).await,
        DeviceCmd::Get { id } => get(c, ctx, &id).await,
        DeviceCmd::Stats { id } => stats(c, ctx, &id).await,
        DeviceCmd::Restart { id } => {
            action(
                c,
                ctx,
                &id,
                "RESTART",
                &format!("restart requested for {id}"),
            )
            .await
        }
        DeviceCmd::PowerCycle { id, port } => power_cycle(c, ctx, &id, port).await,
    }
}

async fn list(c: &Client, ctx: &Ctx, a: &ListArgs, allow_web: bool, resolve: bool) -> Result<()> {
    if c.mode() == Mode::Cloud {
        let rows = ui::spin(
            "Listing devices",
            c.list("/v1/devices", &[], a.offset, a.limit),
        )
        .await?;
        render::heading("Devices");
        render::list(&rows, render::DEVICE_COLS);
        render::count(rows.len(), "device");
        return Ok(());
    }

    let site = site::resolve(c, &ctx.profile.site).await?;
    let path = format!("/sites/{}/devices", esc(&site));
    let mut rows = ui::spin("Listing devices", c.list(&path, &[], a.offset, a.limit)).await?;

    let report = if resolve {
        posture(c, &site, &mut rows, allow_web).await
    } else {
        Report::default()
    };

    render::heading(&format!("Devices on {}", ctx.profile.host));
    render::list(
        &rows,
        if report.resolved {
            render::POSTURE_COLS
        } else {
            render::DEVICE_COLS
        },
    );
    render::count(rows.len(), "device");

    if !render::is_json() {
        for line in report.notes(allow_web) {
            ui::info(&line);
        }
    }
    Ok(())
}

/// What the posture pass established, and what it could not.
#[derive(Default)]
struct Report {
    resolved: bool,
    needs_action: usize,
    end_of_life: usize,
    unknown: usize,
    advisories: usize,
    exploited: usize,
    checked_advisories: bool,
    error: Option<String>,
}

impl Report {
    fn notes(&self, allow_web: bool) -> Vec<String> {
        let mut out = Vec::new();
        if let Some(e) = &self.error {
            out.push(format!("firmware posture incomplete: {e}"));
        }
        if !self.resolved {
            return out;
        }

        out.push(match (self.needs_action, self.end_of_life) {
            (0, 0) => "every firmware is current, every model still supported".to_string(),
            (n, 0) => format!("{n} device(s) need a firmware update"),
            (_, k) => format!(
                "{k} device(s) past end of support: no further fix will ship for them, \
                 whatever their firmware says"
            ),
        });
        if self.unknown > 0 {
            out.push(format!(
                "{} device(s) reported no firmware version",
                self.unknown
            ));
        }

        if !allow_web && !self.checked_advisories {
            out.push(
                "advisories not checked: run with --allow-web to list published CVEs \
                 naming these models"
                    .to_string(),
            );
        } else if self.checked_advisories {
            out.push(match (self.advisories, self.exploited) {
                (0, _) => "no published advisory names these models. That is not the \
                           same as unaffected: vendor data pins exact versions and often \
                           omits the model entirely"
                    .to_string(),
                (n, 0) => format!("{n} advisory(ies) name these models, to read, not a verdict"),
                (n, k) => format!(
                    "{n} advisory(ies) name these models, {k} of them known to be exploited"
                ),
            });
        }
        out
    }
}

/// Read the firmware verdict off the legacy records and attach it to each row.
async fn posture(c: &Client, site: &str, rows: &mut [Value], allow_web: bool) -> Report {
    let mut report = Report::default();

    let legacy = match legacy_devices(c, site).await {
        Ok(l) => l,
        Err(e) => {
            // The posture lives on the undocumented surface. Losing it costs
            // the extra columns, never the listing.
            report.error = Some(e.to_string());
            return report;
        }
    };
    report.resolved = true;

    let by_mac: HashMap<String, &Value> = legacy
        .iter()
        .filter_map(|d| {
            d.get("mac")
                .and_then(Value::as_str)
                .map(|m| (m.to_ascii_lowercase(), d))
        })
        .collect();

    // Models to look advisories up by: the marketing name people know, and the
    // internal code, in case the corpus uses it.
    let mut models: Vec<String> = Vec::new();
    let mut postures: Vec<firmware::Posture> = Vec::new();

    for r in rows.iter() {
        let mac = r
            .get("macAddress")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_ascii_lowercase();
        let p = by_mac
            .get(&mac)
            .map(|d| firmware::assess(d))
            .unwrap_or_default();

        for key in ["model"] {
            if let Some(m) = r.get(key).and_then(Value::as_str) {
                models.push(m.to_string());
            }
        }
        if let Some(code) = by_mac
            .get(&mac)
            .and_then(|d| d.get("model"))
            .and_then(Value::as_str)
        {
            models.push(code.to_string());
        }
        postures.push(p);
    }

    let found = if allow_web || advisories_cached() {
        let outcome = advisories::load(allow_web).await;
        if report.error.is_none() {
            report.error = outcome.error;
        }
        if outcome.items.is_empty() {
            None
        } else {
            report.checked_advisories = true;
            Some(outcome.items)
        }
    } else {
        None
    };

    for (r, p) in rows.iter_mut().zip(&postures) {
        if p.needs_action() {
            report.needs_action += 1;
        }
        if p.eol || p.unsupported {
            report.end_of_life += 1;
        }
        if p.label() == "unknown" {
            report.unknown += 1;
        }

        let obj = r.as_object_mut().expect("device rows are objects");
        obj.insert("posture".into(), json!(p.label()));
        obj.insert("support".into(), json!(p.support()));
        obj.insert("firmwareRequired".into(), json!(p.required));
        obj.insert("upgradable".into(), json!(p.upgradable));
        obj.insert("endOfLife".into(), json!(p.eol));
        obj.insert("belowMinimum".into(), json!(p.below_minimum));
        obj.insert("unsupported".into(), json!(p.unsupported));

        if let Some(list) = &found {
            let model = obj
                .get("model")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string();
            let hits = advisories::matching(list, &[model]);
            report.advisories += hits.len();
            report.exploited += hits.iter().filter(|a| a.in_kev).count();
            obj.insert(
                "advisories".into(),
                json!(hits.iter().map(|a| a.id.clone()).collect::<Vec<_>>()),
            );
        }
    }

    report
}

/// Whether an advisory list is already on disk, so a plain run can use it
/// without reaching the network.
fn advisories_cached() -> bool {
    crate::enrich::cache_dir()
        .join("advisories-ubiquiti.json")
        .exists()
}

/// The full device records, from the legacy surface.
async fn legacy_devices(c: &Client, site: &str) -> Result<Vec<Value>> {
    let legacy_site = site::resolve_legacy(c, site).await?;
    ui::spin(
        "Reading firmware posture",
        c.list_on(
            Surface::Legacy,
            &format!("/s/{}/stat/device", esc(&legacy_site)),
            &[],
        ),
    )
    .await
}

/// Accept a MAC address wherever a device id is expected, since the posture
/// columns take the place of the id column.
async fn resolve_device(c: &Client, site: &str, want: &str) -> Result<String> {
    let Some(mac) = as_mac(want) else {
        return Ok(want.to_string());
    };

    let path = format!("/sites/{}/devices", esc(site));
    let devices = ui::spin("Looking up the device", c.list(&path, &[], 0, None)).await?;

    for d in &devices {
        if d.get("macAddress")
            .and_then(Value::as_str)
            .map(str::to_ascii_lowercase)
            == Some(mac.clone())
        {
            return d
                .get("id")
                .and_then(Value::as_str)
                .map(str::to_string)
                .context("that device has no id");
        }
    }
    bail!("no device on this site with MAC {mac}")
}

/// Six colon- or hyphen-separated hex pairs, normalized. Anything else is an id.
fn as_mac(s: &str) -> Option<String> {
    let parts: Vec<&str> = s.split([':', '-']).collect();
    if parts.len() != 6
        || !parts
            .iter()
            .all(|p| p.len() == 2 && p.chars().all(|c| c.is_ascii_hexdigit()))
    {
        return None;
    }
    Some(s.to_ascii_lowercase().replace('-', ":"))
}

async fn get(c: &Client, ctx: &Ctx, id: &str) -> Result<()> {
    let v = match c.mode() {
        Mode::Local => {
            let site = site::resolve(c, &ctx.profile.site).await?;
            let id = resolve_device(c, &site, id).await?;
            let path = format!("/sites/{}/devices/{}", esc(&site), esc(&id));
            ui::spin("Reading the device", c.get_one(&path)).await?
        }
        Mode::Cloud => {
            ui::spin(
                "Reading the host",
                c.get_one(&format!("/v1/hosts/{}", esc(id))),
            )
            .await?
        }
    };

    render::heading(&render::name_of(&v, id));
    render::one(&v);
    Ok(())
}

async fn stats(c: &Client, ctx: &Ctx, id: &str) -> Result<()> {
    unifi::local_only(c, "devices stats")?;
    let site = site::resolve(c, &ctx.profile.site).await?;
    let id = resolve_device(c, &site, id).await?;
    let path = format!(
        "/sites/{}/devices/{}/statistics/latest",
        esc(&site),
        esc(&id)
    );

    let v = ui::spin("Reading statistics", c.get_one(&path)).await?;
    render::heading("Latest statistics");
    render::one(&v);
    Ok(())
}

/// POST one action to a device.
async fn action(c: &Client, ctx: &Ctx, id: &str, what: &str, done: &str) -> Result<()> {
    unifi::local_only(c, "devices actions")?;
    let site = site::resolve(c, &ctx.profile.site).await?;
    let id = resolve_device(c, &site, id).await?;
    let path = format!("/sites/{}/devices/{}/actions", esc(&site), esc(&id));
    let body = serde_json::json!({ "action": what });

    let v = ui::spin(
        &format!("Sending {what}"),
        c.request(Method::POST, &path, &[], Some(&body)),
    )
    .await?;
    ui::success(done);
    render::one(&v);
    Ok(())
}

async fn power_cycle(c: &Client, ctx: &Ctx, id: &str, port: u32) -> Result<()> {
    unifi::local_only(c, "devices power-cycle")?;
    let site = site::resolve(c, &ctx.profile.site).await?;
    let id = resolve_device(c, &site, id).await?;
    let path = format!(
        "/sites/{}/devices/{}/interfaces/ports/{port}/actions",
        esc(&site),
        esc(&id)
    );
    let body = serde_json::json!({ "action": "POWER_CYCLE" });

    let v = ui::spin(
        "Sending POWER_CYCLE",
        c.request(Method::POST, &path, &[], Some(&body)),
    )
    .await?;
    ui::success(&format!("power cycle requested for {id} port {port}"));
    render::one(&v);
    Ok(())
}
