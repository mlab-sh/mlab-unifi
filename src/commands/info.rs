//! `info` — what the console says about itself.

use anyhow::Result;
use reqwest::Method;

use crate::cli::Ctx;
use crate::ui::{self, render};
use crate::unifi::{self, Client};

pub async fn run(c: &Client, ctx: &Ctx) -> Result<()> {
    unifi::local_only(c, "info")?;
    let v = ui::spin(
        "Reading the console",
        c.request(Method::GET, "/info", &[], None),
    )
    .await?;
    render::heading(&format!("Console {}", ctx.profile.host));
    render::one(&v);
    Ok(())
}
