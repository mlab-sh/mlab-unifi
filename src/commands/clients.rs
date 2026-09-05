//! `clients` — what is connected to a site.

use anyhow::Result;
use clap::Subcommand;
use reqwest::Method;

use crate::cli::{Ctx, ListArgs};
use crate::ui::{self, render};
use crate::unifi::{self, esc, site, Client};

#[derive(Subcommand, Debug)]
pub enum ClientCmd {
    /// List clients
    List(ListArgs),
    /// Show one client
    Get { id: String },
    /// Grant guest access to a client
    Authorize { id: String },
}

pub async fn run(c: &Client, ctx: &Ctx, cmd: ClientCmd) -> Result<()> {
    unifi::local_only(c, "clients")?;
    let site = site::resolve(c, &ctx.profile.site).await?;

    match cmd {
        ClientCmd::List(a) => {
            let path = format!("/sites/{}/clients", esc(&site));
            let rows = ui::spin(
                "Listing clients",
                c.list(&path, &[], a.all, a.offset, a.limit),
            )
            .await?;
            render::heading("Clients");
            render::list(&rows, render::CLIENT_COLS);
            render::count(rows.len(), "client");
        }
        ClientCmd::Get { id } => {
            let path = format!("/sites/{}/clients/{}", esc(&site), esc(&id));
            let v = ui::spin("Reading the client", c.get_one(&path)).await?;
            render::heading(&render::name_of(&v, &id));
            render::one(&v);
        }
        ClientCmd::Authorize { id } => {
            let path = format!("/sites/{}/clients/{}/actions", esc(&site), esc(&id));
            let body = serde_json::json!({ "action": "AUTHORIZE_GUEST_ACCESS" });
            let v = ui::spin(
                "Authorizing",
                c.request(Method::POST, &path, &[], Some(&body)),
            )
            .await?;
            ui::success(&format!("guest access granted to {id}"));
            render::one(&v);
        }
    }
    Ok(())
}
