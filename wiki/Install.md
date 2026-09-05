# Install

mlab-unifi is a single Rust binary with no runtime dependencies.

```bash
git clone <this repo>
cd mlab-unifi
cargo build --release
```

The binary lands at `target/release/mlab-unifi`. Copy it anywhere on your
`PATH`:

```bash
install -m 0755 target/release/mlab-unifi ~/.local/bin/
```

## Requirements

| | |
| --- | --- |
| Rust | 1.80 or later (2021 edition) |
| Console | UniFi Network 9.x or later, on UniFi OS 9.3.43 or later |
| Access | An API key, created in the console UI |

The Integration API only exists from UniFi Network 9.x. On an older console
every command fails at the first request with a connection or 404 error.

## Getting an API key

On the console: **Settings, then Control Plane, then Integrations**, and create
a key. For a Site Manager (cloud) profile the key comes from `unifi.ui.com`
instead, under **API**.

Treat that key as an administrator credential, not as a read-only token. It
returns secrets in clear text: see [Secrets](Secrets).

## First run

```bash
mlab-unifi login --name lab --host 192.168.1.1
```

The wizard asks for the key without echoing it, tests the connection, picks the
site, and writes `$HOME/.mlab/unify.conf` with mode 0600 inside a 0700
directory. Then:

```bash
mlab-unifi ping
mlab-unifi devices list
```

## Non-interactive install

For a script or a CI job, pass everything and skip the prompts:

```bash
UNIFI_API_KEY=... mlab-unifi login --name lab --host 192.168.1.1 --non-interactive
```

Prefer the environment variable over `--api-key`: a command line is visible to
every other process on the machine.
