# `mlab-unifi clients`

What is connected to a site, and with `--all`, what ever was. Local mode only.

```bash
mlab-unifi clients list
mlab-unifi clients list --all
mlab-unifi clients get <id>
mlab-unifi clients authorize <id>
```

## `list`

The clients connected right now, from the [integration surface](Surfaces).

```
  Clients

  NAME               IP              MAC                TYPE      ID
  rpi-01 36:85       192.168.15.101  88:a2:9e:5f:36:85  WIRED     bcbeac5b-...
  Terramaster F-426  192.168.16.20   6c:bf:b5:04:8f:14  WIRED     a1f86f2a-...

  30 clients
```

## `list --all`, the asset inventory

Every client the console has ever seen, connected or not, with the date it
first appeared and an `ACTIVE` column saying whether it is here right now.

```
  Client inventory

  NAME                  ACTIVE  IP              MAC                TYPE      FIRST SEEN            LAST SEEN
  db01                  true    192.168.18.200  6c:3c:8c:4c:e5:c7  WIRED     2026-05-06T13:13:53Z  2026-09-05T10:26:04Z
  Nintendo Switch       true    192.168.31.155  bc:74:4b:11:9d:dd  WIRELESS  2025-09-29T19:36:19Z  2026-09-04T17:05:25Z
  allhub                false   192.168.16.10   dc:a6:32:1e:55:6c  WIRED     2026-03-05T12:06:57Z  2026-05-15T14:21:21Z

  49 clients
  › 30 connected now, 19 seen before
```

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

One client in full, by its integration identifier (the `ID` column above, not
the MAC).

## `authorize`

Grants guest access to a client. This changes state on the console. There is no
confirmation prompt.
