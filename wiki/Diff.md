# `mlab-unifi diff`

What changed between two [snapshots](Snapshot).

```bash
mlab-unifi diff                      # the two most recent for this console
mlab-unifi diff before.json after.json
mlab-unifi diff --all                # including changes with no security reading
```

```
  2026-09-05T13:41:10Z to 2026-09-12T09:00:00Z

  RESOURCE           CHANGE       ITEM               DETAIL
  device-detail      changed      Dream Router 7     version: 5.1.31.34074 -> 7.5.11.17400
  firewall-policies  disappeared  Allow All Traffic
  port-forwards      appeared     grafana
  port-forwards      changed      web prod           log: false -> true
  wlans              changed      arasaka            pmf_mode: optional -> required
  clients-known      appeared     inconnu

  6 changes
```

This is the command the rest of the tool was built for. Every other view reads a
moment; this one reads the distance between two, which is where a new device, an
opened port and an edited rule stop being states and become dated events.

## Inventory by presence, configuration by field

The distinction is what makes the output readable, and it is declared per
resource in `src/unifi/registry.rs`.

An **inventory** churns by design. A client's byte counters and a neighbour's
signal move every time anything is measured, so those resources are compared on
**who is present** and nothing else. Comparing them field by field would bury
one new device under a thousand meaningless deltas.

**Configuration** does not churn, so every field is compared and the change is
printed as `field: old -> new`.

A few resources sit between the two. A device record carries 238 fields, most of
them telemetry and a handful that matter, so it declares the ones worth
watching:

```rust
Compare::Fields {
    key: "mac",
    watch: &["version", "required_version", "model_in_eol", "upgradable", ...],
}
```

The measure of whether that tuning is right: two snapshots ten minutes apart on
a live network produced **zero** security-relevant changes, and two low-weight
ones, both clients coming and going.

## What is shown by default

Changes are ranked, and the ones with no security reading are hidden unless
`--all` is given:

| Weight | What |
| --- | --- |
| high | anything on settings, wireless, port forwards, firewall rules, networks, device firmware |
| low | a client appearing in the historical list, a new neighbouring BSSID |
| none | a live client connecting or disconnecting |

A client appearing in `clients-known` is a device the console had never met. The
same client appearing in the live `clients` list is somebody opening their
laptop. Only the first is worth a line.

## Three refusals

**Two snapshots of different consoles.**

```
  ✖ these snapshots are of different consoles (0c62493e-... and ...)
```

Compared on `console.id`, the identity the console reports for itself, not on
the address it answered at. A console that changed address is still the same
console; two different consoles that happen to share an address are not.

**A snapshot this build cannot read.**

```
  ✖ ... is a version 9 snapshot, this build reads version 1
```

Refusing an unknown shape beats misreading it. That is what the version field
is for.

**A resource that is unreadable on either side.**

```
  ! 1 resource(s) could not be compared because one side is missing or was
    unreadable, which is not the same as unchanged: wlans
```

Without this, a surface that moved between two collections would be reported as
a resource somebody deleted. Same principle as the "not evaluable" state in
[`audit`](Audit): a question that could not be asked has no answer, and an
answer is never invented for it.

## What it is for

- **Shadow IT, precisely.** [`shadow`](Shadow) works off a sliding window;
  a diff gives the exact set that appeared between two dated points.
- **Configuration drift.** A rule edited, a port opened, a setting flipped,
  each with a date and a before and after.
- **The interference case.** Sample regularly, and a neighbour BSSID appearing
  can be lined up against the airtime figures from [`wifi airtime`](Wifi).

Take snapshots on a schedule and the tool stops being an auditor.
