# `mlab-unifi blast`

What a compromised client would reach. Local mode only.

```bash
mlab-unifi blast "Nintendo Switch"
mlab-unifi blast bc:74:4b:11:9d:dd
mlab-unifi blast --zone Z-15
```

```
  What Nintendo Switch on VLAN-31-other reaches

  ZONE      REACHES                  HOSTS  NETWORKS
  External  everything               0      Internet 1, Internet 2, WireGuard
  Z-30      everything               1      VLAN-30-iot
  Z-40      everything               0      VLAN-40-Print
  Z-16      specific hosts or ports  6      VLAN-16-LabWeb

  4 zones
  › starting from Z-31, 3 zone(s) are wide open and 7 known host(s) sit in reach
```

Zones nothing can reach are left out. `REACHES` is `everything` when the pair is
open to any traffic, and `specific hosts or ports` when only a narrowed rule
gets through.

## Why this one is computable and shadowing is not

[`network policies`](Network) refuses to say a rule is shadowed, because rule
indices collide across the rule set and evaluation order cannot be established.
That is still true globally. It is **not** true inside a zone pair:

```
rules sharing an index within one source-destination pair: 0 of 255 pairs
```

A packet is only ever evaluated against the rules for its own pair, so per-pair
order is the only order that decides anything, and it is unambiguous. That is
what makes this command sound while the other check stays silent.

## The rule that looks like a block and is not

The trap this command exists to avoid. Every pair carries a rule named
`Block Invalid Traffic` at a low index:

```
Internal -> External
  idx=30000       BLOCK  Block Invalid Traffic
  idx=2147483647  ALLOW  Allow All Traffic
```

Read off the first rule, that pair is closed and most of the network would be
reported unreachable. It is not: that rule matches the `INVALID` connection
state alone. Only rules that apply to **every** connection state settle a pair.

That field, `connection_state_type`, exists on the [v2 surface](Surfaces) and
not on the documented one, which is why the matrix is built from v2 even though
zone names come from elsewhere.

## Naming zones across two identifier spaces

The documented API and v2 number zones differently and share no identifier. The
bridge runs through the networks: a network carries the documented UUID on one
side and the internal zone id on the other, so joining them names the zones.

12 of 16 zones resolve. The 4 that do not are exactly the zones holding no
network, which have no host to reach and never appear in a result.

## What the count does and does not mean

`HOSTS` counts clients the console has seen on the networks in that zone. It is
what the firewall **permits**, not what is actually exposed: a reachable host
with nothing listening is reachable and harmless, and the line under the table
says so.

Two further limits, both deliberate:

- **One hop.** This is what the starting zone reaches directly. It does not
  chain: reaching a host in Z-16 does not make what Z-16 reaches part of your
  blast radius until that host is compromised too.
- **Zone level.** A rule naming specific addresses shows as
  `specific hosts or ports` rather than being resolved down to which hosts.
  [`network policies`](Network) lists the rules themselves.
