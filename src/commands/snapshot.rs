//! `snapshot` — one dated, secret-free record of everything the console holds.
//!
//! The point of the command is not the file, it is the second file. Every
//! other command here reads a moment; a snapshot makes moments comparable, and
//! that is what turns an auditor into a detector.
//!
//! Two rules, both decided before a line was written because retrofitting
//! either means purging a history of snapshots:
//!
//! * **Secrets are dropped on write, never on display.** A snapshot taken
//!   naively is a credential dump on disk, repeated at every collection.
//! * **A resource that could not be read is recorded as unavailable.** Never
//!   omitted. An absent key and a failed fetch must not look alike to whatever
//!   compares two of these later.

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Args;
use serde_json::{json, Map, Value};

use crate::cli::Ctx;
use crate::ui::{self, render};
use crate::unifi::registry::RESOURCES;
use crate::unifi::{self, secrets, site, Client, Surface};

#[derive(Args, Debug)]
pub struct SnapshotArgs {
    /// Write here instead of the dated file under $HOME/.mlab/unifi/snapshots
    #[arg(long, value_name = "FILE")]
    pub out: Option<PathBuf>,

    /// List the snapshots already taken for this console
    #[arg(long)]
    pub list: bool,

    /// Print the resource catalogue and collect nothing
    #[arg(long)]
    pub resources: bool,
}

pub async fn run(c: &Client, ctx: &Ctx, a: &SnapshotArgs) -> Result<()> {
    if a.resources {
        return catalogue();
    }
    if a.list {
        return list(&ctx.profile.host);
    }
    unifi::local_only(c, "snapshot")?;

    let site_id = site::resolve(c, &ctx.profile.site).await?;
    let legacy = site::resolve_legacy(c, &site_id).await?;

    let mut resources = Map::new();
    let mut ok = 0usize;
    let mut unavailable = Vec::new();
    let mut redacted = 0usize;

    let spinner = ui::Spinner::start("Collecting");
    for r in RESOURCES {
        spinner.set(format!("Collecting {}", r.name));
        let path = r.path_for(&site_id, &legacy);

        let fetched = match r.surface {
            Surface::Integration => c.list(&path, &[], 0, None).await,
            surface => c.list_on(surface, &path, &[]).await,
        };

        let entry = match fetched {
            Ok(items) => {
                ok += 1;
                let mut items = Value::Array(items);
                redacted += secrets::redact(&mut items);
                json!({
                    "status": "ok",
                    "count": items.as_array().map(Vec::len).unwrap_or(0),
                    "items": items,
                })
            }
            Err(e) => {
                // Recorded, not skipped: a comparison that cannot tell a
                // failed fetch from an empty result will report a vanished
                // resource as a deletion.
                unavailable.push(r.name);
                json!({ "status": "unavailable", "error": format!("{e:#}") })
            }
        };
        resources.insert(r.name.to_string(), entry);
    }
    spinner.clear();

    let snapshot = json!({
        "version": 1,
        "takenAt": unifi::iso8601(now()),
        "console": {
            "host": ctx.profile.host,
            "site": site_id,
            "legacySite": legacy,
        },
        "collection": {
            "resources": RESOURCES.len(),
            "collected": ok,
            "unavailable": unavailable,
            "secretsRedacted": redacted,
        },
        "resources": Value::Object(resources),
    });

    let path = match &a.out {
        Some(p) => p.clone(),
        None => default_path(&ctx.profile.host),
    };
    write(&path, &snapshot)?;

    if render::is_json() {
        render::print_json(&json!({
            "path": path.to_string_lossy(),
            "collection": snapshot["collection"],
            "takenAt": snapshot["takenAt"],
        }));
        return Ok(());
    }

    ui::success(&format!("{} written", path.display()));
    render::pairs(&[
        (
            "taken",
            snapshot["takenAt"].as_str().unwrap_or_default().to_string(),
        ),
        ("resources", format!("{ok} of {}", RESOURCES.len())),
        ("secrets removed", redacted.to_string()),
        ("size", format!("{} KB", file_size(&path) / 1024)),
    ]);

    if !unavailable.is_empty() {
        ui::warning(&format!(
            "{} resource(s) could not be read and are recorded as unavailable, not as \
             empty: {}",
            unavailable.len(),
            unavailable.join(", ")
        ));
    }
    ui::info("a snapshot on its own answers nothing; take a second one later and compare them");
    Ok(())
}

// ---- the catalogue ----------------------------------------------------------

fn catalogue() -> Result<()> {
    let rows: Vec<Value> = RESOURCES
        .iter()
        .map(|r| {
            json!({
                "name": r.name,
                "surface": match r.surface {
                    Surface::Integration => "integration",
                    Surface::Legacy => "legacy",
                    Surface::V2 => "v2",
                },
                "path": r.path,
                "about": r.about,
            })
        })
        .collect();

    render::heading("What a snapshot collects");
    render::list(&rows, render::RESOURCE_COLS);
    render::count(rows.len(), "resource");
    Ok(())
}

// ---- files ------------------------------------------------------------------

fn snapshot_dir(host: &str) -> PathBuf {
    let safe: String = host
        .chars()
        .map(|c| if c.is_alphanumeric() { c } else { '-' })
        .collect();
    crate::enrich::cache_dir().join("snapshots").join(safe)
}

fn default_path(host: &str) -> PathBuf {
    // Sortable by name, and unambiguous across time zones.
    let stamp = unifi::iso8601(now()).replace([':'], "");
    snapshot_dir(host).join(format!("{stamp}.json"))
}

fn write(path: &PathBuf, snapshot: &Value) -> Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    }
    let mut data = serde_json::to_string_pretty(snapshot)?;
    data.push('\n');
    std::fs::write(path, data).with_context(|| format!("writing {}", path.display()))?;

    // Secrets are gone, but an inventory of a network is not public either.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

fn list(host: &str) -> Result<()> {
    let dir = snapshot_dir(host);
    let mut found: Vec<(String, u64)> = std::fs::read_dir(&dir)
        .into_iter()
        .flatten()
        .flatten()
        .filter(|e| e.path().extension().is_some_and(|x| x == "json"))
        .map(|e| {
            let size = e.metadata().map(|m| m.len()).unwrap_or(0);
            (e.file_name().to_string_lossy().to_string(), size)
        })
        .collect();
    found.sort();

    let rows: Vec<Value> = found
        .iter()
        .map(|(name, size)| json!({ "snapshot": name, "kb": size / 1024 }))
        .collect();

    render::heading(&format!("Snapshots of {host}"));
    render::list(&rows, render::SNAPSHOT_COLS);
    render::count(rows.len(), "snapshot");
    if rows.is_empty() && !render::is_json() {
        ui::info(&format!("nothing in {}", dir.display()));
    }
    Ok(())
}

fn file_size(path: &PathBuf) -> u64 {
    std::fs::metadata(path).map(|m| m.len()).unwrap_or(0)
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}
