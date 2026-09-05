# `mlab-unifi devices`

List, inspect and act on the managed hardware of a site.

```bash
mlab-unifi devices list
mlab-unifi devices get <id>
mlab-unifi devices stats <id>
mlab-unifi devices restart <id>
mlab-unifi devices power-cycle <id> --port 4
```

## `list`

```
  Devices on 192.168.1.1

  NAME                 MODEL           STATE   IP              MAC                FIRMWARE
  Office Switch        USW-Lite-8-PoE  ONLINE  192.168.7.235   6c:63:f8:24:d7:07  7.5.10
  Dream Router 7       UDR7            ONLINE  192.168.1.61    1c:0b:8b:e0:bc:67  5.1.31

  2 devices
```

In cloud mode the same subcommand lists the account's devices from
`/v1/devices` instead, with a different shape.

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

## Vulnerability material

The documented surface exposes `firmwareVersion` but not the end-of-life flags.
Those are on the [legacy surface](Surfaces), and they are what turns an
inventory into a vulnerability posture:

```bash
mlab-unifi api GET '/s/{site}/stat/device' --surface legacy --list
```

| Field | Why it matters |
| --- | --- |
| `version` | exact firmware, the join key to a CVE database |
| `required_version` | the minimum the controller will accept |
| `model_in_eol` | the model no longer receives fixes |
| `model_in_lts` | the model is on the long-term branch |
| `upgradable` | a newer firmware is already available |
| `unsupported` | the controller refuses to manage it fully |

See [Passive security](Passive-Security).
