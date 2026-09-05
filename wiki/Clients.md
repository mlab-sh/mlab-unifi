# `mlab-unifi clients`

What is connected to a site, and with `--all`, what ever was. Local mode only.

```bash
mlab-unifi clients list
mlab-unifi clients list --all
mlab-unifi clients list --all --allow-web
mlab-unifi clients get <id>
mlab-unifi clients authorize <id>
```

| Flag | Effect |
| --- | --- |
| `--all` | Every client ever seen, not only those connected now |
| `--allow-web` | Resolve the vendor of unnamed addresses through mlab.sh |
| `--min-score <N>` | Confidence below which a model is marked as a guess. Default 90 |
| `--no-resolve` | Skip identity resolution entirely |

The last three are covered on [Identity](Identity).

## `list`

The clients connected right now, named through [identity resolution](Identity).

```
  Clients

  NAME                VENDOR                      DEVICE                        CONF  IP              MAC                TYPE
  rpi-01 36:85        Raspberry Pi (Trading) Ltd                                      192.168.15.101  88:a2:9e:5f:36:85  WIRED
  homelab-p1 be:7c    Dell, Inc.                  Dell Laptop                   99    192.168.16.17   00:4e:01:a3:be:7c  WIRED
  Terramaster F-426   Philips Hue                 Philips Hue Bridge (Gen 2) ?  1     192.168.16.20   6c:bf:b5:04:8f:14  WIRED

  30 clients
  › 14 device(s) identified below 90% confidence, shown as reported
```

The vendor and model come from the console's fingerprint engine, which lives on
the [legacy surface](Surfaces): the documented API carries none. So the live
listing fetches that list too, unless `--no-resolve` says not to. If it is
unavailable, the listing still prints without the identity columns and says so.

With `--no-resolve` the table falls back to what the documented API alone
returns, including the integration `ID` column:

```
  NAME           IP              MAC                TYPE   ID
  rpi-01 36:85   192.168.15.101  88:a2:9e:5f:36:85  WIRED  bcbeac5b-c25a-3240-8188-6a0f392977af
```

## `list --all`, the asset inventory

Every client the console has ever seen, connected or not, with the date it
first appeared and an `ACTIVE` column saying whether it is here right now.

```
  Client inventory

  NAME             ACTIVE  VENDOR              DEVICE                CONF  IP              MAC                LAST SEEN
  db01             true    Dell Inc.                                       192.168.18.200  6c:3c:8c:4c:e5:c7  2026-09-05T11:14:59Z
  Iphone de Meg    true    Apple, Inc.         Apple iPhone 14 Pro   100   192.168.11.189  c2:34:34:6a:7c:31  2026-09-05T08:35:37Z
  Nintendo Switch  true    Nintendo Co., Ltd.  Nintendo Switch       90    192.168.31.155  bc:74:4b:11:9d:dd  2026-09-04T17:05:25Z
  iPhone 7d:2c     true    (randomized)        Netgear RN526X ?            192.168.31.226  56:6f:4b:41:7d:2c  2026-09-03T16:59:32Z

  49 clients
  › 30 connected now, 19 seen before
  › 25 device(s) identified below 90% confidence, shown as reported
  › 3 device(s) unidentified: run with --allow-web to resolve their vendor through mlab.sh
```

The identity columns come from [Identity](Identity). Without them (with
`--no-resolve`, or when the lookup table is unreachable) the table falls back to
`FIRST SEEN` and `LAST SEEN` instead.

Connected clients sort first, then by how recently each was seen. The bottom of
the list is what has drifted away.

### How it is built

The historical list only exists on the [legacy surface](Surfaces), so `--all` is
a join of two sources on the MAC address:

| Source | Surface | Gives |
| --- | --- | --- |
| `/sites/{uuid}/clients` | integration | who is connected, live IP and name |
| `/s/{name}/rest/user` | legacy | every client ever, first and last seen, fingerprint |

Rules the join follows:

- Every historical record becomes a row. `activeNow` says whether it is also in
  the live list.
- The live record wins on fields both sources carry, since it is current.
- MAC addresses are lowercased on both sides before matching, so a case
  difference between surfaces cannot split one device into two rows.
- An active client absent from the history still gets a row. A silently dropped
  device is the one bug an inventory cannot afford.
- Epoch timestamps from the legacy surface are converted to UTC ISO 8601, the
  format the documented API already uses, so the two sort together.

### JSON shape

`--all` is the one command whose JSON is not a raw API response, because it has
no single upstream. Each row:

```json
{
  "name": "db01",
  "activeNow": true,
  "ipAddress": "192.168.18.200",
  "macAddress": "6c:3c:8c:4c:e5:c7",
  "type": "WIRED",
  "network": "VLAN-18-DB",
  "uplink": "Dream Router 7",
  "guest": false,
  "firstSeen": "2026-05-06T13:13:53Z",
  "lastSeen": "2026-09-05T10:26:04Z",
  "id": "0e12a3c7-6f98-3d2c-a494-f7c5fea431c5"
}
```

`network` and `uplink` are in the JSON but not in the table, which would
otherwise be too wide to read. `id` is empty for a client that is not currently
connected: it is the integration API's identifier, and only live clients have
one.

### What it is for

A dated inventory is the base of several passive checks: a `firstSeen` newer
than your last review is unapproved hardware, and comparing two inventories
gives appearances and disappearances without any scanning. See
[Passive security](Passive-Security).

## `get`

One client in full, by MAC address or by integration id:

```bash
mlab-unifi clients get 88:a2:9e:5f:36:85
mlab-unifi clients get bcbeac5b-c25a-3240-8188-6a0f392977af
```

Six hex pairs, separated by colons or hyphens, are treated as a MAC and looked
up in the live client list; anything else is used as an id. The MAC is on every
row of the table and is the key people actually have, so prefer it.

A MAC only resolves for a client that is connected right now, since the id it
maps to is the documented API's and only live clients have one.

## `authorize`

Grants guest access to a client. This changes state on the console. There is no
confirmation prompt.
