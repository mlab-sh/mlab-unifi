//! The command line surface, and the dispatch behind it.
//!
//! Adding a command means: a module under [`crate::commands`], a variant in
//! [`Cmd`], and one arm in [`run`].

mod context;

pub use context::{Ctx, Overrides};

use anyhow::{Context as _, Result};
use clap::{Args, Parser, Subcommand};

use crate::commands;
use crate::ui::{self, render};
use crate::unifi::{config, Client};

#[derive(Parser, Debug)]
#[command(
    name = "mlab-unifi",
    version,
    about = "Talk to a UniFi console (local) or the UniFi Site Manager API (cloud)",
    long_about = "Talk to a UniFi console (local) or the UniFi Site Manager API (cloud).\n\n\
                  Connection settings live in profiles in $HOME/.mlab/unify.conf; run \
                  `mlab-unifi login` once to create one. Flags override environment \
                  variables (MLAB_UNIFI_* then UNIFI_*), which override the profile.",
    after_help = "Get an API key from the console UI: Settings -> Control Plane -> Integrations."
)]
pub struct Cli {
    /// Profile to use (default: the one marked default in the config)
    #[arg(long, short = 'p', global = true, value_name = "NAME")]
    pub profile: Option<String>,

    /// Console hostname or host:port (local mode)
    #[arg(long, global = true, value_name = "HOST")]
    pub host: Option<String>,

    /// API key; prefer UNIFI_API_KEY, a command line is visible to other users
    #[arg(long, global = true, value_name = "KEY")]
    pub api_key: Option<String>,

    /// Site id or name (local mode)
    #[arg(long, global = true, value_name = "SITE")]
    pub site: Option<String>,

    /// Override the profile's mode
    #[arg(long, global = true, value_name = "local|cloud")]
    pub mode: Option<String>,

    /// Output format: a terminal render, or raw JSON for scripting
    #[arg(long, short = 'o', global = true, value_parser = ["human", "json", "table"], value_name = "FORMAT")]
    pub output: Option<String>,

    /// Silence progress and status lines on stderr
    #[arg(long, short = 'q', global = true)]
    pub quiet: bool,

    /// Per-request timeout, in seconds
    #[arg(long, global = true, default_value_t = 30, value_name = "SECS")]
    pub timeout: u64,

    /// Skip TLS certificate verification (the default in local mode)
    #[arg(long, global = true, conflicts_with = "secure")]
    pub insecure: bool,

    /// Verify the TLS certificate even in local mode
    #[arg(long, global = true)]
    pub secure: bool,

    #[command(subcommand)]
    pub command: Cmd,
}

#[derive(Subcommand, Debug)]
pub enum Cmd {
    /// Create or update a profile, test it, and save it to the config file
    #[command(alias = "configure", alias = "setup")]
    Login(commands::login::LoginArgs),

    /// Manage saved profiles
    Profile {
        #[command(subcommand)]
        cmd: commands::profile::ProfileCmd,
    },

    /// Inspect the config file
    Config {
        #[command(subcommand)]
        cmd: commands::settings::ConfigCmd,
    },

    /// Check that the current profile can reach its API
    Ping,

    /// Application info of the local console
    Info,

    /// Consoles on the account (cloud only)
    Hosts(ListArgs),

    /// Sites
    Sites(ListArgs),

    /// Devices
    Devices {
        #[command(subcommand)]
        cmd: commands::devices::DeviceCmd,
    },

    /// Clients (local only)
    Clients {
        #[command(subcommand)]
        cmd: commands::clients::ClientCmd,
    },

    /// Networks, segmentation and inbound exposure (local only)
    Network {
        #[command(subcommand)]
        cmd: commands::network::NetworkCmd,
    },

    /// Wireless hardening, neighbourhood, impostors and airtime (local only)
    Wifi {
        #[command(subcommand)]
        cmd: Option<commands::wifi::WifiCmd>,
    },

    /// What turned up on the network that nobody announced (local only)
    Shadow(commands::shadow::ShadowArgs),

    /// What the site's settings say it is defending, and with what (local only)
    Posture,

    /// What this site looks like from the outside (local only)
    Footprint(commands::footprint::FootprintArgs),

    /// What a compromised client would reach (local only)
    Blast(commands::blast::BlastArgs),

    /// Raw request against the API base, for anything not wrapped yet
    #[command(
        after_help = "PATH is relative to the chosen surface and may contain {site},\n\
                      replaced by whichever site identifier that surface expects.\n\n\
                      Surfaces: integration (documented), legacy and v2 (internal,\n\
                      far richer, undocumented and liable to change).\n\n\
                      Examples:\n  \
                      mlab-unifi api GET /sites\n  \
                      mlab-unifi api GET '/sites/{site}/devices' --list\n  \
                      mlab-unifi api GET '/s/{site}/stat/rogueap' --surface legacy --list\n  \
                      mlab-unifi api GET '/site/{site}/topology' --surface v2\n  \
                      mlab-unifi api POST '/sites/{site}/clients/ID/actions' --data '{\"action\":\"AUTHORIZE_GUEST_ACCESS\"}'"
    )]
    Api(commands::api::ApiArgs),
}

/// Paging flags, shared by every list command.
///
/// Everything is fetched by default; the flags are there to take a slice
/// instead, which is what `--limit` means: one page of that size.
#[derive(Args, Debug, Clone, Default)]
pub struct ListArgs {
    /// Return a single page of this size instead of everything
    #[arg(long, value_name = "N")]
    pub limit: Option<u32>,
    /// Where that page starts
    #[arg(long, default_value_t = 0, value_name = "N")]
    pub offset: u32,
}

/// Parse, set up output, then hand over to a command.
pub async fn run() -> Result<()> {
    let cli = Cli::parse();
    ui::init(cli.quiet);
    // Resolved again from the profile in `Ctx::build` when neither the flag nor
    // the environment picked a format.
    render::init(cli.output.as_deref().or(config::env("OUTPUT").as_deref()));

    // Commands that only touch the config file need no connection.
    match &cli.command {
        Cmd::Login(args) => return commands::login::run(&Overrides::from(&cli), args).await,
        Cmd::Profile { cmd } => return commands::profile::run(cmd),
        Cmd::Config { cmd } => return commands::settings::run(cmd),
        _ => {}
    }

    if let Some(w) = config::perms_warning() {
        ui::warning(&w);
    }

    let ctx = Ctx::build(&cli)?;
    let c = Client::new(&ctx.profile, ctx.timeout)
        .with_context(|| format!("profile {:?}", ctx.name))?;

    match cli.command {
        Cmd::Login(_) | Cmd::Profile { .. } | Cmd::Config { .. } => unreachable!(),
        Cmd::Ping => commands::ping::run(&c, &ctx).await,
        Cmd::Info => commands::info::run(&c, &ctx).await,
        Cmd::Hosts(a) => commands::hosts::run(&c, &a).await,
        Cmd::Sites(a) => commands::sites::run(&c, &a).await,
        Cmd::Devices { cmd } => commands::devices::run(&c, &ctx, cmd).await,
        Cmd::Clients { cmd } => commands::clients::run(&c, &ctx, cmd).await,
        Cmd::Network { cmd } => commands::network::run(&c, &ctx, cmd).await,
        Cmd::Wifi { cmd } => commands::wifi::run(&c, &ctx, cmd).await,
        Cmd::Shadow(a) => commands::shadow::run(&c, &ctx, &a).await,
        Cmd::Posture => commands::posture::run(&c, &ctx).await,
        Cmd::Footprint(a) => commands::footprint::run(&c, &ctx, &a).await,
        Cmd::Blast(a) => commands::blast::run(&c, &ctx, &a).await,
        Cmd::Api(a) => commands::api::run(&c, &ctx, a).await,
    }
}
