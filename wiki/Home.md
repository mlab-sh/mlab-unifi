# mlab-unifi

**A CLI over the UniFi APIs, built as a base for passive network security work.**

mlab-unifi talks to a UniFi console on the LAN (the Network Integration API) or
to a UniFi Site Manager account in the cloud. Both authenticate with the same
`X-API-KEY` header, so one client covers them, and a profile in
`$HOME/.mlab/unify.conf` says which one to reach and how.

It reads. Nothing in the tool changes a configuration except the device actions
you ask for explicitly, and no data leaves your machine.

---

## The commands

| Command | What it does |
| --- | --- |
| [`login`](Login) | Create or update a profile, prove the credentials work, save them. |
| [`ping`](Ping) | Check that the current profile reaches its API, and report what is on the other end. |
| [`info`](Info) | The console's own version information. |
| [`sites`](Sites) | List sites, on either mode. |
| [`devices`](Devices) | List, inspect and act on the managed hardware of a site. |
| [`clients`](Clients) | What is connected now, or with `--all` every client ever seen. |
| [`network`](Network) | Segmentation, firewall zones, and what can reach the site from outside. |
| [`wifi`](Wifi) | Wireless hardening, the neighbourhood, impostors, and airtime. |
| [`shadow`](Shadow) | What turned up on the network that nobody announced. |
| [`posture`](Posture) | What the site's settings say it is defending, and with what. |
| [`footprint`](Footprint) | What this site looks like from the outside. |
| [`blast`](Blast) | What a compromised client would reach. |
| [`live`](Live) | Attach to a console event stream and print what arrives. |
| [`hosts`](Hosts) | Consoles visible on a Site Manager account (cloud only). |
| [`api`](Api) | Raw request against any [surface](Surfaces), for everything not wrapped yet. |
| [`profile`](Configuration) | List, show, select and delete saved profiles. |
| [`config`](Configuration) | Where the config file is, and what is in it. |

## Key concepts

- **[Surfaces](Surfaces)** - a console answers on three separate HTTP APIs of
  very different richness, plus WebSocket streams. Knowing which one a command
  uses explains most of its behaviour.
- **[Configuration](Configuration)** - profiles, the precedence between flags,
  environment and file, and where secrets live.
- **[Identity](Identity)** - how a MAC becomes a named device: the console's
  fingerprint engine, what `--min-score` actually gates, and the opt-in vendor
  lookup for the gaps.
- **[Output](Output)** - a terminal render by default, raw JSON with
  `-o json`, and the rules that keep the two from mixing.
- **[Passive security](Passive-Security)** - the catalogue of defensive work
  this data supports without emitting a single packet at a target.
- **[Secrets](Secrets)** - a read-only API key returns credentials in clear
  text. What that means for how you store the key and what the tool writes to
  disk.
- **[Roadmap](Roadmap)** - what is built, what is next, in order.

## Getting started

```bash
cargo build --release
./target/release/mlab-unifi login --name lab --host 192.168.1.1
./target/release/mlab-unifi ping
```

See [Install](Install) for the rest.

## Scope and stability

The documented Integration API is stable and versioned. The legacy and v2
surfaces are what the web app calls for itself: far richer, undocumented, and
free to change on any firmware update. Commands that depend on them say so on
their page, and are expected to degrade rather than fail when a route
disappears.
