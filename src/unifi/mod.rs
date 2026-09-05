//! The UniFi side of the CLI: what to talk to, and how.

pub mod client;
pub mod config;
pub mod site;

pub use client::{esc, Client};
pub use config::{Mode, Profile};

use anyhow::{bail, Result};

/// Guard for the commands the Site Manager (cloud) API does not serve.
pub fn local_only(c: &Client, what: &str) -> Result<()> {
    if c.mode() != Mode::Local {
        bail!("`{what}` needs a local console; use --mode local or a local profile");
    }
    Ok(())
}
