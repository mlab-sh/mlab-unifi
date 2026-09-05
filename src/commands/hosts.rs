//! `hosts` — the consoles visible on a Site Manager account.

use anyhow::{bail, Result};

use crate::cli::ListArgs;
use crate::ui::{self, render};
use crate::unifi::{Client, Mode};

pub async fn run(c: &Client, a: &ListArgs) -> Result<()> {
    if c.mode() != Mode::Cloud {
        bail!("`hosts` is a cloud command; use --mode cloud or a cloud profile");
    }
    let rows = ui::spin(
        "Listing hosts",
        c.list("/v1/hosts", &[], a.all, a.offset, a.limit),
    )
    .await?;

    render::heading("Hosts");
    render::list(&rows, render::HOST_COLS);
    render::count(rows.len(), "host");
    Ok(())
}
