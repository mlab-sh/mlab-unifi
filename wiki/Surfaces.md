# Surfaces

A UniFi console answers on three separate HTTP APIs. They accept the same
`X-API-KEY` header, so one credential reaches all three, but they differ in
every other respect: base URL, response envelope, pagination, how a site is
named, and how much they actually contain.

Knowing which surface a command uses explains most of its behaviour.

| Surface | Base | Envelope | Paging | Site identifier |
| --- | --- | --- | --- | --- |
| `integration` | `/proxy/network/integration/v1` | plain | `offset` / `limit` with `totalCount` | UUID |
| `legacy` | `/proxy/network/api` | `{meta,data}` | none, one shot | short name |
| `v2` | `/proxy/network/v2/api` | plain | none, one shot | short name |

The cloud (Site Manager) is a fourth base, `https://api.ui.com`, with cursor
pagination (`pageSize` and `nextToken`). It has no legacy or v2 surface.

## Which one to trust

`integration` is the documented, versioned API. It is the only one Ubiquiti
supports, and the only one guaranteed to survive a firmware update. It is also
by far the poorest: roughly ten routes covering sites, devices, clients,
firewall policies and vouchers.

`legacy` and `v2` are what the web app calls for itself. They carry the full
configuration, the radio neighbourhood, the historical client list and the
device fingerprint database. Nothing about them is promised. Any command built
on them states it, and is expected to report a route as unavailable rather than
to fail outright.

## The two names of a site

This trips up every raw request. The documented surface identifies a site by
UUID:

```
88f7af54-98f8-306a-a1c7-c9349722b1f6
```

The internal surfaces identify the same site by a short name:

```
default
```

The mapping lives in the legacy site list, where `external_id` holds the UUID
and `name` holds the short name. mlab-unifi resolves it for you: `{site}` in an
[`api`](Api) path is replaced by whichever identifier the chosen surface wants.

## The error shape

The legacy surface answers HTTP 200 with `rc: "error"` in its envelope when it
refuses. Checking the status code alone would let a refusal through as an empty
list, which is the worst possible outcome for a security check, so mlab-unifi
inspects the envelope and turns `rc: "error"` into a real error.

## WebSocket streams

Three event channels accept the same API key and upgrade over HTTP/1.1:

```
/proxy/network/wss/s/{site}/events
/proxy/protect/integration/v1/subscribe/devices
/proxy/protect/integration/v1/subscribe/events
```

All three return `101 Switching Protocols`. The two Protect channels then stay
open; the network one closes immediately with code 1000, which means an API key
is not what it wants. No frame has been observed on any of them. See
[`live`](Live).

## Reaching a surface by hand

```bash
mlab-unifi api GET '/sites/{site}/devices' --list
mlab-unifi api GET '/s/{site}/stat/rogueap' --surface legacy --list
mlab-unifi api GET '/site/{site}/topology' --surface v2
```

See [`api`](Api).
