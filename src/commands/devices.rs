//! `devices` — list, inspect, and act on the hardware of a site.

use anyhow::Result;
use clap::Subcommand;
use reqwest::Method;

use crate::cli::{Ctx, ListArgs};
use crate::ui::{self, render};
use crate::unifi::{self, esc, site, Client, Mode};

#[derive(Subcommand, Debug)]
pub enum DeviceCmd {
    /// List devices
    List(ListArgs),
    /// Show one device
    Get { id: String },
    /// Latest statistics for one device (local only)
    Stats { id: String },
    /// Restart a device (local only)
    Restart { id: String },
    /// Power-cycle one PoE port of a device (local only)
    PowerCycle {
        id: String,
        /// Port index
        #[arg(long, value_name = "IDX")]
        port: u32,
    },
}

pub async fn run(c: &Client, ctx: &Ctx, cmd: DeviceCmd) -> Result<()> {
    match cmd {
        DeviceCmd::List(a) => list(c, ctx, &a).await,
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

async fn list(c: &Client, ctx: &Ctx, a: &ListArgs) -> Result<()> {
    let (rows, title) = match c.mode() {
        Mode::Local => {
            let path = format!(
                "/sites/{}/devices",
                esc(&site::resolve(c, &ctx.profile.site).await?)
            );
            let rows = ui::spin("Listing devices", c.list(&path, &[], a.offset, a.limit)).await?;
            (rows, format!("Devices on {}", ctx.profile.host))
        }
        Mode::Cloud => {
            let rows = ui::spin(
                "Listing devices",
                c.list("/v1/devices", &[], a.offset, a.limit),
            )
            .await?;
            (rows, "Devices".to_string())
        }
    };

    render::heading(&title);
    render::list(&rows, render::DEVICE_COLS);
    render::count(rows.len(), "device");
    Ok(())
}

async fn get(c: &Client, ctx: &Ctx, id: &str) -> Result<()> {
    let v = match c.mode() {
        Mode::Local => {
            let site = site::resolve(c, &ctx.profile.site).await?;
            let path = format!("/sites/{}/devices/{}", esc(&site), esc(id));
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
    let path = format!(
        "/sites/{}/devices/{}/statistics/latest",
        esc(&site),
        esc(id)
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
    let path = format!("/sites/{}/devices/{}/actions", esc(&site), esc(id));
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
    let path = format!(
        "/sites/{}/devices/{}/interfaces/ports/{port}/actions",
        esc(&site),
        esc(id)
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
