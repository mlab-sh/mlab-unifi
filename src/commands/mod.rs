//! One module per command.
//!
//! Each exposes a `run` taking whatever it needs — a [`Client`](crate::unifi::Client)
//! and the resolved [`Ctx`](crate::cli::Ctx) for the API commands, nothing but
//! its own arguments for the ones that only touch the config file.

pub mod api;
pub mod blast;
pub mod clients;
pub mod devices;
pub mod footprint;
pub mod hosts;
pub mod info;
pub mod live;
pub mod login;
pub mod network;
pub mod ping;
pub mod posture;
pub mod profile;
pub mod prompt;
pub mod settings;
pub mod shadow;
pub mod sites;
pub mod wifi;
