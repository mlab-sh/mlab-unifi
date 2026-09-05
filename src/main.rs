//! `mlab-unifi` — a CLI over the two key-authenticated UniFi APIs: a console's
//! Network Integration API on the LAN, and the Site Manager API in the cloud.
//!
//! Layout:
//!
//! | module     | role                                                        |
//! | ---------- | ----------------------------------------------------------- |
//! | `unifi`    | the APIs: HTTP handler, profiles, site resolution            |
//! | `enrich`   | turning what the console observed into an identity           |
//! | `ui`       | everything the user sees: progress on stderr, rendering      |
//! | `cli`      | the clap surface and the dispatch                            |
//! | `commands` | one module per command                                       |

mod cli;
mod commands;
mod enrich;
mod ui;
mod unifi;

use colored::Colorize;

#[tokio::main]
async fn main() {
    if let Err(e) = cli::run().await {
        // A spinner may own a half-drawn line; wipe it before the message.
        ui::restore();
        eprintln!("  {} {e:#}", "✖".red().bold());
        std::process::exit(1);
    }
}
