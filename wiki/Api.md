# `mlab-unifi api`

A raw request against any [surface](Surfaces). This is the lab bench: try an
endpoint here, and once it earns its place, give it a real command.

```bash
mlab-unifi api GET /sites
mlab-unifi api GET '/sites/{site}/devices' --list
mlab-unifi api GET '/s/{site}/stat/rogueap' --surface legacy --list
mlab-unifi api GET '/site/{site}/topology' --surface v2
mlab-unifi api POST '/sites/{site}/clients/ID/actions' -d '{"action":"AUTHORIZE_GUEST_ACCESS"}'
```

## Arguments

| | |
| --- | --- |
| `METHOD` | `GET`, `POST`, `PUT`, `PATCH`, `DELETE` |
| `PATH` | Relative to the chosen surface, leading slash optional |
| `--surface` | `integration` (default), `legacy`, `v2` |
| `--data`, `-d` | JSON body: inline, `@file`, or `-` for stdin |
| `--query`, `-q` | Extra query parameter, repeatable: `-q key=value` |
| `--list` | Treat the response as a collection and return the items |
| `--limit` | With `--list`, a single page of that size |

## `{site}`

`{site}` in the path is replaced by whichever identifier the chosen surface
expects: the UUID on `integration`, the short name on `legacy` and `v2`. That
resolution costs one extra request, and only happens when the placeholder is
present.

## `--list`

Without it you get the raw response, envelope and all. With it, mlab-unifi
unwraps whichever pagination the surface uses and hands you the items, then
renders them as a table with columns derived from the first row.

```bash
mlab-unifi api GET '/s/{site}/rest/portforward' --surface legacy --list
```

```
  GET /s/default/rest/portforward

  NAME   PROTO     DST_PORT  FWD_PORT  ENABLED  LOG
  web    tcp_udp   80,443    80,443    true     false

  1 item
```

The internal surfaces answer in one shot rather than paginating, so `--limit`
truncates the result client-side there.

## Bodies

```bash
mlab-unifi api POST '/sites/{site}/hotspot/vouchers' -d @voucher.json
echo '{"action":"RESTART"}' | mlab-unifi api POST '/sites/{site}/devices/ID/actions' -d -
```

`--list` and `--data` cannot be combined.

## Reproducing the exploration

Every route in [Passive security](Passive-Security) is reachable from here.
A few worth knowing:

```bash
mlab-unifi api GET '/s/{site}/stat/device'      --surface legacy --list  # firmware, EOL
mlab-unifi api GET '/s/{site}/stat/rogueap'     --surface legacy --list  # RF neighbourhood
mlab-unifi api GET '/s/{site}/rest/wlanconf'    --surface legacy --list  # wifi hardening
mlab-unifi api GET '/s/{site}/rest/networkconf' --surface legacy --list  # VLANs, isolation
mlab-unifi api GET '/s/{site}/stat/health'      --surface legacy --list  # WAN, ASN
mlab-unifi api GET '/site/{site}/firewall-policies' --surface v2 --list
mlab-unifi api GET '/site/{site}/topology'          --surface v2
```

`rest/setting` is deliberately absent from that list. It returns credentials in
clear text: see [Secrets](Secrets) before you page it to a terminal.
