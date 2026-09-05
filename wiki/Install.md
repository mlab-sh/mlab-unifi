# Install

mlab-unifi is a single Rust binary with no runtime dependencies. macOS and
Linux, x86_64 and arm64, from a package manager or as a tarball.

## Homebrew (macOS and Linux)

```bash
brew tap mlab-sh/mlab-unifi https://github.com/mlab-sh/mlab-unifi.git
brew install mlab-unifi
```

## Debian and Ubuntu

Download the `.deb` for your architecture from the
[releases page](https://github.com/mlab-sh/mlab-unifi/releases), then let apt
resolve it:

```bash
sudo apt install ./mlab-unifi_1.0.0_amd64.deb
```

## Fedora, RHEL and rebuilds

The same with the `.rpm`:

```bash
sudo dnf install ./mlab-unifi-1.0.0-1.x86_64.rpm
```

The payload is gzip rather than the zstd default, so rpm 4.14 (RHEL 8 and its
rebuilds) reads it too.

## Prebuilt binary

Tarballs for every target are on the same page:

```bash
tar -xzf mlab-unifi-1.0.0-aarch64-apple-darwin.tar.gz
install -m 0755 mlab-unifi-1.0.0-aarch64-apple-darwin/mlab-unifi ~/.local/bin/
```

The Linux builds are linked against glibc 2.35, so they run on Debian 12,
Ubuntu 22.04 and anything newer.

## Checking what you downloaded

Nothing is signed, so every release carries a `SHA256SUMS` file covering all of
its assets:

```bash
sha256sum -c --ignore-missing SHA256SUMS
```

## From source

```bash
git clone https://github.com/mlab-sh/mlab-unifi.git
cd mlab-unifi
cargo build --release
install -m 0755 target/release/mlab-unifi ~/.local/bin/
```

## Requirements

| | |
| --- | --- |
| Rust | 1.80 or later (2021 edition), only to build from source |
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
