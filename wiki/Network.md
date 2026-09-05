# `mlab-unifi network`

Segmentation and inbound exposure. Local mode only.

```bash
mlab-unifi network list        # the networks and how they are cut up
mlab-unifi network get <name>  # one network in full
mlab-unifi network exposure    # what can reach the site from outside
mlab-unifi network zones       # firewall zones and their members
```

The documented API lists networks and zones but says nothing about isolation,
mDNS, UPnP or port forwards. Those live on the [legacy surface](Surfaces), so
each subcommand joins the two on the network's UUID (`id` on one side,
`external_id` on the other) and falls back to the documented columns when the
legacy surface is unavailable.

## `list`

```
  Networks

  NAME             VLAN  SUBNET            ZONE      ISOLATION  INTERNET  MDNS  UPNP
  Default          1     192.168.7.1/24    Internal             allowed   on    off
  VLAN-15-ProdWeb  15    192.168.15.1/24   Z-15      off        allowed   on    off
  VLAN-30-iot      30    192.168.30.1/24   Z-30      off        allowed   on    off

  11 networks
  › 10 network(s) with isolation off: what crosses between them is decided by firewall policy, see `network zones`
  › 11 network(s) propagate mDNS, which crosses VLAN boundaries
```

| Column | Source | Reading |
| --- | --- | --- |
| `ISOLATION` | `network_isolation_enabled` | `on` blocks all inter-VLAN traffic outright |
| `INTERNET` | `internet_access_enabled` | whether the network may leave the site at all |
| `MDNS` | `mdns_enabled` | mDNS reflection, which deliberately crosses VLANs |
| `UPNP` | `upnp_lan_enabled` | whether hosts may open their own inbound ports |

`purpose`, `dhcp`, `dhcpGuard` and the network id are in the JSON.

The lines under the table are **observations, not verdicts**. Isolation being
off is normal on a site that segments with firewall policy instead, so the tool
says where to look rather than calling it a finding. UPnP is the one that gets a
warning: it lets any host on the network publish itself inbound without asking
anyone.

## `get`

By name, VLAN id, or network id, whichever you have:

```bash
mlab-unifi network get VLAN-30-iot
mlab-unifi network get 30
```

An unknown name lists the ones that exist rather than returning nothing.

## `exposure`

The way in, in one screen.

```
  Inbound exposure

  asn         12322
  isp         Free SAS
  status      ok
  wanIp       192.168.1.61
  wanIpScope  private

  NAME       PROTO    WAN PORT  TO                     ENABLED  LOG  SOURCE
  web prod   tcp_udp  80,443    192.168.15.150:80,443  true     off  any
  plex       tcp_udp  32400     192.168.16.16:32400    true     off  any

  2 port forwards
  › the WAN address 192.168.1.61 is private: this console sits behind another router, so a forward here only publishes anything if that router forwards to it too
  ! 2 active forward(s) with logging off: traffic accepted through them leaves no trace to investigate later
  ! 2 active forward(s) accept any source address
```

Three things it checks, all of which change what a rule actually means:

**Is the WAN address routable.** An address in RFC 1918 or the carrier-grade NAT
range means the console sits behind another router. Every forward below is then
conditional on that router forwarding too, which is worth knowing before you
treat the list as your exposure.

**Does an accepted connection leave a trace.** `log: off` on a forward means
traffic accepted through it is never recorded. After an incident there is
nothing to go back to.

**Who may use it.** Without `src_limiting_enabled` a rule accepts the whole
internet. That is the default, and rarely what was intended.

Disabled rules are counted separately and never mixed into the findings.

## `zones`

```
  ZONE      ORIGIN          NETWORKS
  External  SYSTEM_DEFINED  Internet 1, Internet 2, WireGuard
  Z-15      USER_DEFINED    VLAN-15-ProdWeb
  Internal  SYSTEM_DEFINED  Default, VLAN-200-SECU

  16 zones
  › 4 zone(s) hold no network: Gateway, Hotspot, Dmz, Z-200
```

Zone membership is where inter-VLAN traffic is actually decided when
`ISOLATION` is off, so this is the companion to `list`. Member names are
resolved from both surfaces, since the documented network list covers LAN
networks only and would otherwise leave WAN and VPN members as bare UUIDs.

An empty zone is not a fault: a zone defined ahead of the network that will
join it is normal. It is reported because a zone that stayed empty by accident
looks exactly the same.

## What is not here yet

The firewall policies themselves. They exist at
`/site/{site}/firewall-policies` on the v2 surface, roughly 300 KB of rules, and
they are the other half of the segmentation story:

```bash
mlab-unifi api GET '/site/{site}/firewall-policies' --surface v2 --list
```

Turning that into rule hygiene (permissive, disabled, unlogged, dead rules) is
on the [Roadmap](Roadmap).
