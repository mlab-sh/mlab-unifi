# `mlab-unifi shadow`

What turned up on the network that nobody announced. Local mode only.

```bash
mlab-unifi shadow                        # the last 30 days
mlab-unifi shadow --days 90
mlab-unifi shadow --days 90 --include-randomized
```

It runs off `first_seen`, which the console records for every address it has
ever met, so it works today without any stored history. Once dated snapshots
exist it gains a second, sharper mode: the difference between two of them.

```
  Appeared in the last 90 days

  NAME           APPEARED              LAST SEEN             LINK      NETWORK          VENDOR                         DEVICE
  nixos          2026-08-05T19:08:22Z  2026-08-05T20:09:03Z  wireless  VLAN-31-other    Red Hat                        Linux PC
                 2026-07-14T09:06:30Z  2026-09-05T11:51:51Z  wired     VLAN-15-ProdWeb  Proxmox Server Solutions GmbH
  ubuntu-server  2026-07-11T14:52:49Z  2026-08-31T15:21:26Z  wired     VLAN-200-SECU    Dell, Inc.                     Dell Laptop
  g6-instant     2026-06-19T09:32:12Z  2026-08-31T14:17:17Z  wireless                   Ubiquiti Inc

  6 arrivals
  › 3 arrival(s) hidden because their address is randomized
  ! 4 of them arrived on a wire, which means someone reached a port
  › 2 carry a model the console is less than 90% sure of, shown as reported
  › 2 are connected right now
```

## Randomized addresses are hidden by default

This is the decision the whole command turns on. A phone that rotates its MAC
presents a new address to the console every time, and each one looks like a
brand new device. On the lab site, the **only** arrival in thirty days was
exactly that.

Mixed in, they would make the report almost entirely expected churn, which is a
report nobody reads. They are counted and announced, never silently dropped, and
`--include-randomized` shows them.

## What each line under the table means

| Line | Why it is worth a look |
| --- | --- |
| arrived on a wire | someone reached a physical port, which is a different story from joining Wi-Fi |
| could not be identified at all | neither the fingerprint engine nor a vendor lookup names it |
| model the console is unsure of | shown as reported, gated by `--min-score` |
| seen once and never came back | a visit rather than an arrival |
| connected right now | still here, so still actionable |

A **vendor** and a **model** are not weighed the same way. A vendor read off a
registry is a fact and carries no confidence; a model is an inference the
console rates. A device with a known vendor is never reported as
unidentified just because its model is a guess. Same rule as
[Identity](Identity).

Vendors come from the same cascade the inventory uses, so a device named in
`clients list --all` is named here too. The OUI cache is consulted but never
refreshed: this command does not reach the network.

## Adopted hardware

Widen the window and a second table appears: UniFi devices adopted in the same
period.

```
  UniFi hardware adopted in the same period

  NAME                 MODEL     ADOPTED               IP              MAC
  USW-SAILOR 24        USL24B    2026-04-23T18:10:06Z  192.168.10.7    6c:63:f8:88:a8:bd
```

Hardware joining the managed network is the strongest signal on the page. A
client connecting is ordinary; a switch or an access point being adopted is
someone extending the network.

## The caveat that always prints

`first_seen` is when the **console** met the address, not when the device was
built or bought. A controller rebuild makes every device look new on the same
day, and a rotated address looks like an arrival even though the phone behind it
has been on the network for a year.

So this is a list of things to look at, not a list of intruders.
