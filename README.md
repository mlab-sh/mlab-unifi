# mlab-unifi

![](./.github/banner.png)

A small Rust CLI over the two key-authenticated UniFi APIs:

| mode    | base URL                                          | paging                | TLS                     |
| ------- | ------------------------------------------------- | --------------------- | ----------------------- |
| `local` | `https://<host>/proxy/network/integration/v1`      | `offset` / `limit`    | not verified by default |
| `cloud` | `https://api.ui.com` (Site Manager)                | `pageSize`/`nextToken`| always verified         |

Both authenticate with an `X-API-KEY` header, so one client covers the two.
Requires UniFi Network 9.x+ / UniFi OS 9.3.43+ on the console.

## Build

```bash
cargo build --release   # ./target/release/mlab-unifi
```

## Setup

Get an API key from the console UI (**Settings → Control Plane → Integrations**),
or from unifi.ui.com for cloud mode, then:

```bash
mlab-unifi login --name lab --host 192.168.1.1
```

It prompts for the key without echoing it, checks the connection, picks the
site, and writes `$HOME/.mlab/unify.conf` (mode 0600, in a 0700 directory).

Several profiles can live in the same file:

```bash
mlab-unifi login --name cloud --mode cloud     # Site Manager account
mlab-unifi profile list
mlab-unifi profile use lab
```

Non-interactive (CI, scripts):

```bash
UNIFI_API_KEY=... mlab-unifi login --name lab --host 192.168.1.1 --non-interactive
```

## Use

```bash
mlab-unifi ping                       # is the profile alive
mlab-unifi info                       # console version (local)
mlab-unifi sites
mlab-unifi devices list
mlab-unifi clients list --all          # every client ever seen, with an active flag
mlab-unifi devices get <id>
mlab-unifi devices restart <id>
mlab-unifi devices power-cycle <id> --port 4
mlab-unifi clients list
mlab-unifi hosts                      # cloud: consoles on the account
```

Anything not wrapped yet goes through the raw handler. `{site}` is replaced by
the resolved site id, and `--list` unwraps whichever paging envelope applies:

```bash
mlab-unifi api GET '/sites/{site}/devices' --list
mlab-unifi api GET '/s/{site}/stat/rogueap' --surface legacy --list
mlab-unifi api GET '/sites/{site}/firewall/policies' --list
mlab-unifi api POST '/sites/{site}/clients/<id>/actions' -d '{"action":"AUTHORIZE_GUEST_ACCESS"}'
mlab-unifi api POST '/sites/{site}/hotspot/vouchers' -d @voucher.json
mlab-unifi -p cloud api GET /v1/devices --list
```

## Configuration

Precedence: **flags → environment (`MLAB_UNIFI_*`, then `UNIFI_*`) → profile**.

| setting  | flag             | env                | notes                                       |
| -------- | ---------------- | ------------------ | ------------------------------------------- |
| host     | `--host`         | `UNIFI_HOST`       | hostname or `host:port`, no scheme or path  |
| api key  | `--api-key`      | `UNIFI_API_KEY`    | prefer the env var, a command line is public|
| site     | `--site`         | `UNIFI_SITE`       | id or name; resolved on use                 |
| mode     | `--mode`         | `UNIFI_MODE`       | `local` or `cloud`                          |
| TLS      | `--insecure` / `--secure` | `UNIFI_INSECURE` | local skips verification unless `--secure` |
| output   | `-o human\|json` | `UNIFI_OUTPUT`     | `human` by default                          |
| config   | —                | `MLAB_UNIFI_CONFIG`| defaults to `$HOME/.mlab/unify.conf`        |
| progress | `-q`/`--quiet`   | `MLAB_UNIFI_NO_PROGRESS` | stderr only; off when not a terminal  |

The config file:

```json
{
  "default": "lab",
  "profiles": {
    "lab": {
      "mode": "local",
      "host": "192.168.1.1",
      "api_key": "...",
      "site": "88f7af54-98f8-306a-a1c7-c9349722b1f6"
    }
  }
}
```

Local consoles serve a self-signed certificate, so verification is **off** by
default in local mode; `--secure` turns it back on. Redirects are never
followed, so the API key cannot leak to another host.

## Output

The default is a terminal render: aligned blocks, dimmed labels, a spinner on
stderr for anything that takes more than a moment. `-o json` switches every
command to raw JSON on stdout — untouched, so a pipeline sees exactly what the
API returned.

```bash
mlab-unifi devices list              # human
mlab-unifi devices list -o json | jq -r '.[].name'
mlab-unifi -q sites                  # no progress, no status lines
```

Three rules keep the two apart: progress and status go to **stderr** only,
nothing is animated unless stderr is a terminal (`CI` or
`MLAB_UNIFI_NO_PROGRESS` also turn it off), and nothing is drawn for work that
finishes in under 250 ms.
