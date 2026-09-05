# `mlab-unifi snapshot`

One dated, secret-free record of everything the console holds. Local mode only.

```bash
mlab-unifi snapshot                    # take one
mlab-unifi snapshot --out state.json   # somewhere specific
mlab-unifi snapshot --list             # what has been taken
mlab-unifi snapshot --resources        # what a snapshot collects, no network
```

```
  ✔ /Users/you/.mlab/unifi/snapshots/192-168-10-1/2026-09-05T133124Z.json written

  taken            2026-09-05T13:31:24Z
  resources        18 of 18
  secrets removed  20
  size             1289 KB

  › a snapshot on its own answers nothing; take a second one later and compare them with [`diff`](Diff)
```

## The point is the second file

Every other command here reads a moment. A snapshot makes moments comparable,
and that is what turns an auditor into a detector: a new client, a changed rule,
an opened port and an adopted device stop being states and become dated events.

On its own it is an archive. It becomes useful when there are two.

## Two rules decided before the first line

Both are cheap now and expensive later, because retrofitting either means
purging a history of snapshots.

**Secrets are dropped on write, never on display.** A snapshot taken naively is
a credential dump on disk, repeated at every collection. Here a secret is
replaced by its length and nothing else:

```json
"x_ssh_password": "<redacted:22>",
"x_passphrase":   "<redacted:11>"
```

A length is not a secret, and it is what a strength check needs, so a redacted
snapshot can still be audited for a short pre-shared key or counted for how much
the API key exposes. On the lab console, 20 fields were replaced and the API key
itself appears nowhere in the file.

An **empty** secret is left alone rather than marked: turning "this site has no
mesh key" into "this site has a key of length zero" would read as configured.

**A resource that could not be read is recorded as unavailable, never omitted.**

```json
"events": { "status": "unavailable", "error": "API error 404 ..." }
```

Anything comparing two snapshots must be able to tell a failed fetch from an
empty result. Without that distinction, a surface that moved would be reported
as a resource someone deleted.

## What is collected

18 resources across the three [surfaces](Surfaces), listed by
`snapshot --resources`. The catalogue lives in one table, `src/unifi/registry.rs`,
so adding a resource is a line rather than a file, and the snapshot cannot drift
from the list of what the commands read.

Resource names are stable on purpose: renaming one breaks comparison with every
snapshot already taken.

## Where they go

`$HOME/.mlab/unifi/snapshots/<host>/<timestamp>.json`, one directory per
console, mode 0600. The name sorts chronologically and carries no time zone
ambiguity.

Secrets are gone, but an inventory of a network is not public either, which is
why the file is not world readable.

## Shape

```json
{
  "version": 1,
  "takenAt": "2026-09-05T13:31:24Z",
  "console": {
    "id": "0c62493e-...",     // stable: the identity the console gives itself
    "host": "192.168.10.1",   // how we reached it today, nothing more
    "site": "88f7af54-...",
    "legacySite": "default"
  },
  "collection": {
    "resources": 18, "collected": 18,
    "unavailable": [], "secretsRedacted": 20
  },
  "resources": {
    "devices": { "status": "ok", "count": 4, "items": [ ... ] }
  }
}
```

`version` is there so a later reader can refuse a shape it does not understand
rather than misread it.

`console.id` is the identity the console reports for itself, carried separately
from `host`. An address is how we reached it today; two snapshots taken either
side of a DHCP change must still be recognisable as the same console, and
whatever compares them has to be able to refuse two snapshots that are not.

## Cost

Around 20 seconds and 1.3 MB per snapshot on a small site, collected
sequentially. Sequential is deliberate: a snapshot is not urgent, and eighteen
concurrent requests is a strange thing to do to a router you also depend on.
