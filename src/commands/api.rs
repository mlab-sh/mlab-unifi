//! `api` — the raw handler, for every endpoint the CLI does not wrap.
//!
//! This is the lab bench: try an endpoint here, and once it earns its place,
//! give it a module of its own next to this one.

use anyhow::{bail, Context, Result};
use clap::Args;
use reqwest::Method;
use serde_json::Value;

use crate::cli::Ctx;
use crate::ui::{self, render};
use crate::unifi::{esc, site, Client};

#[derive(Args, Debug)]
pub struct ApiArgs {
    /// HTTP method: GET, POST, PUT, PATCH, DELETE
    pub method: String,
    /// Path relative to the API base, e.g. /sites or /v1/hosts
    pub path: String,
    /// JSON body: inline, @file, or - for stdin
    #[arg(long, short = 'd', value_name = "JSON")]
    pub data: Option<String>,
    /// Extra query parameter, repeatable: --query key=value
    #[arg(long, short = 'q', value_name = "K=V")]
    pub query: Vec<String>,
    /// Treat the response as a paginated list and return the items
    #[arg(long)]
    pub list: bool,
    /// With --list, follow pagination to the end
    #[arg(long)]
    pub all: bool,
    /// With --list, page size
    #[arg(long, value_name = "N")]
    pub limit: Option<u32>,
}

pub async fn run(c: &Client, ctx: &Ctx, a: ApiArgs) -> Result<()> {
    let method = Method::from_bytes(a.method.to_ascii_uppercase().as_bytes())
        .with_context(|| format!("{:?} is not an HTTP method", a.method))?;

    let mut path = a.path.clone();
    if !path.starts_with('/') {
        path.insert(0, '/');
    }
    if path.contains("{site}") {
        let site = site::resolve(c, &ctx.profile.site).await?;
        path = path.replace("{site}", &esc(&site));
    }

    let mut query = Vec::new();
    for kv in &a.query {
        let (k, v) = kv
            .split_once('=')
            .with_context(|| format!("--query expects key=value, got {kv:?}"))?;
        query.push((k.to_string(), v.to_string()));
    }

    let body = match &a.data {
        None => None,
        Some(d) => Some(read_json(d)?),
    };

    let label = format!("{method} {path}");

    if a.list {
        if body.is_some() {
            bail!("--list cannot be combined with --data");
        }
        let rows = ui::spin(&label, c.list(&path, &query, a.all, 0, a.limit)).await?;
        render::heading(&label);
        render::list_auto(&rows);
        render::count(rows.len(), "item");
        return Ok(());
    }

    let v = ui::spin(&label, c.request(method, &path, &query, body.as_ref())).await?;
    render::one(&v);
    Ok(())
}

/// Read a JSON body from an inline string, `@file`, or `-` (stdin).
fn read_json(spec: &str) -> Result<Value> {
    let raw = if spec == "-" {
        use std::io::Read;
        let mut s = String::new();
        std::io::stdin()
            .read_to_string(&mut s)
            .context("reading the body from stdin")?;
        s
    } else if let Some(file) = spec.strip_prefix('@') {
        std::fs::read_to_string(file).with_context(|| format!("reading {file}"))?
    } else {
        spec.to_string()
    };
    serde_json::from_str(&raw).context("the request body is not valid JSON")
}
