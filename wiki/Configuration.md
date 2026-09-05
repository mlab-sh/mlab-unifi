# Configuration

Connection settings live in profiles, in one JSON file. Several profiles can
coexist: a console on the LAN, a Site Manager account, a lab box.

## The file

Default path: `$HOME/.mlab/unify.conf`, overridable with `MLAB_UNIFI_CONFIG`.
It is written with mode 0600 inside a 0700 directory, and mlab-unifi warns on
every run if those bits have loosened.

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

| Field | Meaning |
| --- | --- |
| `mode` | `local` for a console on the LAN, `cloud` for Site Manager. |
| `host` | Hostname or `host:port`. No scheme, no path. Local mode only. |
| `api_key` | The console API key. See [Secrets](Secrets) for how to treat it. |
| `site` | Site UUID, resolved once at login. A name also works. |
| `insecure` | Optional. Absent means the mode default: TLS unverified in local mode, verified in cloud mode. |
| `output` | Optional. `human` or `json`, when you want a profile to default to one. |

## Precedence

Flags beat environment variables, which beat the profile.

| Setting | Flag | Environment | Notes |
| --- | --- | --- | --- |
| host | `--host` | `UNIFI_HOST` | hostname or `host:port` |
| api key | `--api-key` | `UNIFI_API_KEY` | prefer the variable, a command line is public |
| site | `--site` | `UNIFI_SITE` | UUID or name, resolved on use |
| mode | `--mode` | `UNIFI_MODE` | `local` or `cloud` |
| TLS | `--insecure` / `--secure` | `UNIFI_INSECURE` | see below |
| output | `-o human\|json` | `UNIFI_OUTPUT` | see [Output](Output) |
| profile | `-p`, `--profile` | | which profile to use |
| config file | | `MLAB_UNIFI_CONFIG` | full path |
| progress | `-q`, `--quiet` | `MLAB_UNIFI_NO_PROGRESS` | see [Output](Output) |

Every variable is also read with an `MLAB_UNIFI_` prefix, which wins over the
bare `UNIFI_` one. That lets mlab-unifi coexist with other UniFi tooling in the
same shell.

With an API key in the flags or the environment, no config file is needed at
all:

```bash
UNIFI_HOST=192.168.1.1 UNIFI_API_KEY=... mlab-unifi sites
```

## TLS

Local consoles serve a self-signed certificate, so certificate verification is
**off by default in local mode**. `--secure` turns it back on, which will fail
against a stock console. That is the correct failure: it tells you the
certificate is not trusted.

The cloud endpoint has a real certificate and is always verified. A profile
that sets `insecure` in cloud mode is ignored rather than obeyed.

Redirects are never followed. The API key travels in a default header, which an
HTTP client would replay on a cross-host redirect; refusing the redirect keeps
the credential from reaching an unexpected origin.

## `mlab-unifi profile`

```bash
mlab-unifi profile list           # all profiles, default marked
mlab-unifi profile show [name]    # one profile, API key masked
mlab-unifi profile use <name>     # change the default
mlab-unifi profile remove <name>  # delete one
```

```
  ● lab     local  192.168.1.1  tls off
  · cloud   cloud  api.ui.com

  ● default profile
```

## `mlab-unifi config`

```bash
mlab-unifi config path   # just the path, for scripting
mlab-unifi config show   # the whole file, API keys masked
```

`config path` always prints a bare path, whatever the output format: it exists
to be pasted into another command.
