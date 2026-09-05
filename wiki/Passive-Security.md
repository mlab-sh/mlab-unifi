# Passive security

What a read-only API key supports in defensive work, without emitting a single
packet at a target.

Passive here means strictly: no scanning, no probing, no configuration writes.
Everything starts from what the console has already observed and stored. The
console is the sensor; mlab-unifi reads it.

## The capabilities

Legend: **direct** means the data is the answer, **derived** means it has to be
joined or computed, **partial** means possible but incomplete on the consoles
tested so far.

| Capability | What it detects | Source | Status |
| --- | --- | --- | --- |
| Asset inventory | every client and device ever seen, with its first appearance | `rest/user`, integration clients | direct |
| Fingerprint identity | operating system, vendor, family and model, without querying the machine | `rest/user` joined to `fingerprint_devices` | derived |
| CVE correlation | vulnerable firmware, versions behind the required minimum | `stat/device` joined to a CVE database | derived |
| End of life | hardware past support, not adoptable, unsupported | `stat/device` | direct |
| Inbound exposure | ports reachable from the internet, UPnP, forwards with no logging | `rest/portforward`, `rest/networkconf` | direct |
| Segmentation audit | VLANs without isolation, mDNS crossing boundaries, routable guests | `rest/networkconf`, firewall zones | direct |
| Rule hygiene | permissive, disabled, unlogged or dead firewall rules | `v2 firewall-policies` | derived |
| Wi-Fi hardening | WPA2 only, transition mode, optional PMF, weak pre-shared key | `rest/wlanconf` | direct |
| RF reconnaissance | the full 802.11 neighbourhood: encryption, channel, power, vendor | `stat/rogueap` | direct |
| Evil twin | a foreign BSSID broadcasting your SSID, or a known SSID in the clear | `stat/rogueap` joined to `rest/wlanconf` | derived |
| Rogue access point | an unmanaged AP on an internal channel at strong signal | `stat/rogueap` | derived |
| Shadow IT | equipment that appeared since the last review | `rest/user`, `first_seen` | derived |
| Client anomalies | anomaly counters, reassociations, degraded channel quality | `v2 clients/active` | direct |
| Secret hygiene | what the API key exposes, pre-shared key entropy, SSH accounts | `rest/setting`, `rest/wlanconf`, `stat/device` | direct |
| Defensive posture | IPS with no active category, TLS inspection off, geo filtering off | `rest/setting` | direct |
| Logging coverage | NetFlow disabled, local syslog only, rules without logging | `rest/setting`, `rest/portforward` | direct |
| Configuration drift | any change between two dated snapshots | full snapshot, diffed | derived |
| External footprint | ASN, operator and public prefix, the start of a passive OSINT trail | `stat/health` | direct |
| Blast radius | what a compromised client reaches, following the graph and the zones | `v2 topology` joined to firewall policies | derived |
| Real-time detection | associations, state changes, Protect events as they happen | WebSocket streams | partial |
| Protect privacy | cameras with the microphone live, face and plate recognition armed | Protect integration API | direct |

## The enrichment chain

Identity resolution is entirely local, which matters: the inventory never
leaves the network.

The console stores numeric fingerprint identifiers, unreadable as they are:

```
oui: "Apple, Inc."   os_name: 24   dev_family: 9   dev_id: 4970
```

The lookup table is served by the console itself, at
`/site/{site}/../fingerprint_devices/0` on the v2 surface: 5847 device
signatures, 1287 vendors, 188 families, 81 operating systems. Joining locally
gives:

```
Apple iOS   Smartphone   confidence 99%
```

The only step that leaves the network is CVE correlation, and it carries
firmware versions, never the inventory.

## What is not available

Verified by probing, not assumed. On Network 10.5:

| Route | Result |
| --- | --- |
| `stat/event`, `stat/alarm` | 404. The historical event log no longer exists in this form. |
| `stat/ips/event`, `v2 ips/alerts` | 404. No IDS or IPS alert is readable by API. |
| `v2 system-log` | 404 on every category tested, GET and POST. |
| `stat/sitedpi`, `stat/stadpi` | 200 but empty. DPI runs, the API returns nothing. |
| `protect/api/*` (legacy) | 401. Detailed Protect events need a cookie session. |
| `access/integration/v1` | 401. Refused to a console key. |

The three WebSocket channels accept the key and stay open, but no frame arrived
during the observation windows on a quiet network, so nothing is claimed about
their payload.

## The consequence for design

Detection available today is **differential**, not event-driven. You do not read
an alarm; you compare two dated snapshots and qualify the difference. That is
slower, and harder to evade: an attacker can avoid triggering a signature, but
can hardly avoid existing in the inventory.

This is why the [roadmap](Roadmap) puts the snapshot before everything else.
