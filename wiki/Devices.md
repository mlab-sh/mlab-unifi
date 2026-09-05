# `mlab-unifi devices`

List, inspect and act on the managed hardware of a site.

```bash
mlab-unifi devices list
mlab-unifi devices list --allow-web
mlab-unifi devices get <id-or-mac>
mlab-unifi devices stats <id-or-mac>
mlab-unifi devices restart <id-or-mac>
mlab-unifi devices power-cycle <id-or-mac> --port 4
```

| Flag on `list` | Effect |
| --- | --- |
| `--allow-web` | Also list published advisories naming these models, through vuln.mlab.sh |
| `--no-resolve` | Skip the firmware posture, list only what the documented API returns |

Every subcommand taking an id also takes a MAC address: six hex pairs separated
by colons or hyphens are looked up in the device list, anything else is used as
an id.

## `list`

```
  Devices on 192.168.1.1

  NAME                 MODEL           STATE   FIRMWARE  POSTURE  SUPPORT    IP              MAC
  Office Switch        USW-Lite-8-PoE  ONLINE  7.5.10    current  supported  192.168.7.235   6c:63:f8:24:d7:07
  Dream Router 7       UDR7            ONLINE  5.1.31    current  supported  192.168.1.61    1c:0b:8b:e0:bc:67

  2 devices
  › every firmware is current, every model still supported
  › advisories not checked: run with --allow-web to list published CVEs naming these models
```

### Two columns, two questions

`POSTURE` and `SUPPORT` are separate on purpose. They answer different things,
and folding them together hides the case that matters most: a device running
the newest firmware that will ever be published for it, on hardware the vendor
has stopped fixing.

| `POSTURE` | Meaning |
| --- | --- |
| `current` | nothing newer is offered |
| `update available` | the console has a newer firmware for it |
| `below minimum` | older than the `required_version` the controller accepts |
| `unknown` | the device reported no version, so nothing is claimed |

| `SUPPORT` | Meaning |
| --- | --- |
| `supported` | the model still receives fixes |
| `end of life` | it does not, whatever its firmware says |
| `lts branch` | on the long-term support branch |
| `unsupported` | the controller will not fully manage it |

Both come from the console's own verdict on the [legacy surface](Surfaces)
(`upgradable`, `model_in_eol`, `model_in_lts`, `unsupported`,
`required_version`). The vendor is the authority here, so there is nothing to
infer and nothing that can be wrong the way a CVE match can be wrong. If the
legacy surface is unavailable, the listing falls back to the documented columns
and says so.

In cloud mode the same subcommand lists the account's devices from
`/v1/devices` instead, with a different shape and no posture.

## `--allow-web`, published advisories

With the flag, `list` pulls the vendor's CVEs from `vuln.mlab.sh` and shows
which ones **name** each model, sorted with actively exploited ones first.

```
  NAME       MODEL   STATE   FIRMWARE  POSTURE  SUPPORT    ADVISORIES
  Office AP  U6-LR   ONLINE  6.6.65    current  supported  CVE-2024-54750
```

**This is a reading list, not a verdict**, and the distinction is not
cosmetic. Two properties of the upstream data forbid anything stronger:

- The vendor's CVE records pin **exact versions**, not ranges. An entry says
  "affects 7.2.95" and says nothing about 7.2.94, so an installed version that
  does not match tells you nothing at all.
- Several recent entries carry **no product metadata**; the model appears only
  in the English prose.

So an empty `ADVISORIES` column means "no published advisory names this model".
It does not mean the model is unaffected, and the line under the table says so
every time.

The list is cached for a day at `$HOME/.mlab/unifi/advisories-ubiquiti.json`, so
later runs match against it without touching the network.

## `get`

The full record: ports with their PoE state and negotiated speed, radios with
channel and width, adoption and provisioning dates. Nested arrays are rendered
as sub-tables.

```
  Dream Router 7

  name               Dream Router 7
  model              UDR7
  state              ONLINE
  firmwareVersion    5.1.31

  interfaces

    ports
      IDX  STATE  CONNECTOR  MAXSPEEDMBPS  SPEEDMBPS
      1    DOWN   RJ45       2500          10
      3    UP     RJ45       2500          1000
```

## `stats`

Latest statistics for one device: load averages, CPU and memory, uplink rates,
uptime, per-radio transmit retries.

```
  cpuUtilizationPct      47.9%  █████·····
  memoryUtilizationPct   75.1%  ████████··
  uptimeSec             561940  (6d 12h)
```

## Actions

`restart` and `power-cycle` are the only commands in mlab-unifi that change
anything. Both take effect immediately and interrupt service:

- `restart` reboots the device.
- `power-cycle --port N` cuts and restores PoE on one port, which reboots
  whatever is plugged into it.

There is no confirmation prompt. Check the device with `get` first.

## The raw records

`list` reads a handful of fields off the legacy device records. Everything else
they carry is one command away:

```bash
mlab-unifi api GET '/s/{site}/stat/device' --surface legacy --list
```

238 fields per device, including per-port PoE state, radio configuration, SSH
host key fingerprints and adoption history. See
[Passive security](Passive-Security).
