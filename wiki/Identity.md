# Identity

Turning a MAC address into a named device, without asking the device anything.

It applies to `clients list` in both forms: the live listing and the full
`--all` inventory. Two independent sources, in order of strength. Both are cached under
`$HOME/.mlab/unifi/`, so a repeated run costs no network at all.

| Source | Answers | Where it runs |
| --- | --- | --- |
| The console fingerprint engine | model, operating system, family, vendor | local, table served by the console |
| An OUI lookup through mlab.sh | vendor only | network, opt-in, gaps only |
| The locally-administered bit | "this address is randomized" | pure computation |

## The console fingerprint engine

The console watches DHCP, HTTP and mDNS and stores what it concluded as numeric
ids on each client: `dev_id`, `dev_vendor`, `os_name`, `dev_family`, with a
`confidence` from 0 to 100.

Those ids are meaningless on their own. The lookup table that decodes them is
served by the same console on the [v2 surface](Surfaces), at
`/fingerprint_devices/0`: roughly 850 KB, 5847 device signatures, 1287 vendors,
188 families, 81 operating systems. Because the ids and the table come from the
same console, the join can never be out of step.

Nothing leaves the network for this. It is cached for 7 days at
`$HOME/.mlab/unifi/fingerprints-<host>.json`, keyed by host so two consoles
never share one table.

The table lives on an undocumented surface. If it disappears, the identity
columns disappear with it and the inventory still prints, with a line saying
resolution was incomplete.

## Registry facts and inferences are not the same thing

This distinction drives the whole display.

A **vendor from an OUI** is a registry lookup. The first three bytes of a MAC
are assigned by the IEEE; reading them is a fact, and it carries no confidence
because it needs none.

A **model or an operating system** is an inference. The engine guessed from
observed behaviour, and it says how sure it is.

`--min-score` therefore applies only to inferences. A client known solely by its
vendor is neither uncertain nor unidentified: it is simply known less precisely.
Counting it as "below 90%" would drown the real guesses in noise.

## `--min-score`, default 90

Below the threshold, the model is still shown, but marked with a trailing `?`,
and counted in a line under the table:

```
  NAME           ACTIVE  VENDOR              DEVICE                CONF  IP
  wlan0 d4:45    true    Amazon              Konyks Priska ?       3     192.168.30.131
  Iphone de Meg  true    Apple, Inc.         Apple iPhone 14 Pro   100   192.168.11.189

  49 clients
  › 25 device(s) identified below 90% confidence, shown as reported
  › 3 device(s) unidentified: run with --allow-web to resolve their vendor through mlab.sh
```

Nothing is hidden and nothing is asserted. In JSON the `device` field stays
clean and `identityCertain` carries the same fact.

Raise the threshold to see only what the console is sure of, lower it to
suppress the warning:

```bash
mlab-unifi clients list --all --min-score 100
mlab-unifi clients list --all --min-score 0
```

## `--allow-web`

Off by default: a run of mlab-unifi touches your console and nothing else.

With the flag, addresses that **nothing local could name** are resolved through
`https://mlab.sh/api/v1/scan/mac`. Three rules keep it narrow:

**Only the gaps.** Not every client, not the low-confidence ones. Only those
with no vendor from any local source. On a console of 49 clients that was 2
lookups.

**Only the OUI is sent**, with the device bytes zeroed: `88:a2:9e:00:00:00`.
A vendor lookup only reads the first three bytes, so the answer is identical
and no device identifier leaves the network.

**Never a randomized address.** A locally-administered MAC has no registration
behind it, so a lookup is a guaranteed miss, and asking would send an
identifier for nothing.

The cache is keyed by OUI, not by device, at `$HOME/.mlab/unifi/oui.json` with a
90 day life: one lookup answers for every device sharing that prefix, now and in
future runs. A failure is never fatal; the run continues and says so.

The response also flags **virtualization** prefixes (VMware, Docker, Xen). A
virtual machine on the network is worth knowing about, and the console never
reports it.

## Randomized addresses

Modern phones rotate their MAC per network. The second-least-significant bit of
the first octet marks such an address as locally administered.

mlab-unifi reports these as `(randomized)` rather than as an empty vendor. That
is not a gap in the data: the device is withholding its identity on purpose, and
saying so is more useful than a blank cell. On the lab console, 13 of 49 clients
and 42 of 92 neighbouring BSSIDs are randomized.

## What ends up in the JSON

```json
{
  "vendor": "Amazon",
  "device": "Konyks Priska",
  "os": "Others",
  "family": "Smart Device",
  "confidence": 3,
  "identityCertain": false
}
```

`os` and `family` are in the JSON but not in the table, which is already eight
columns wide.
