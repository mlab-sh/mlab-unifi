//! `sites` — the one list both APIs serve, under different paths.

use anyhow::Result;

use crate::cli::ListArgs;
use crate::ui::{self, render};
use crate::unifi::{Client, Mode};

pub async fn run(c: &Client, a: &ListArgs) -> Result<()> {
    let path = match c.mode() {
        Mode::Local => "/sites",
        Mode::Cloud => "/v1/sites",
    };
    let rows = ui::spin("Listing sites", c.list(path, &[], a.all, a.offset, a.limit)).await?;

    render::heading("Sites");
    render::list(&rows, render::SITE_COLS);
    render::count(rows.len(), "site");
    Ok(())
}
