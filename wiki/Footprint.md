# `mlab-unifi footprint`

What this site looks like from the outside. Local mode only.

```bash
mlab-unifi footprint
mlab-unifi footprint --allow-web
mlab-unifi footprint --allow-web --public-ip 81.250.4.1
```

```
  Uplink

  address         192.168.1.61 (private)
  gateway         192.168.1.254
  operator        Free SAS
  network number  AS12322
  resolvers       none reported
  link            ok

  How reachable this console is

  hosted by the vendor    no
  vendor sign-in          yes
  wifiman                 yes
  remote vpn              yes
  ssh on every interface  no
  management port         8443

  › 3 active port forward(s) publish a service inbound, listed by `network exposure`
  › the console has no routable address of its own, so nothing here can describe your
    public footprint; pass --public-ip with the address you know to enrich it
```

## The console does not always know its own address

This is the point the command is built around. When the WAN address is in
RFC 1918 or the carrier-grade NAT range, the console sits behind another router
and **has no idea what its public address is**. Printing the private address as
an external footprint would be exactly backwards.

Note what survives anyway: the operator and the network number are still
reported. The console learns those from its own outbound reachability checks,
not from the address on its WAN interface, so they remain true even behind a
second router. The command says where they came from rather than letting them
look like properties of the address above them.

## The two halves

**Local, always.** The uplink, and how reachable the console is: whether it is
hosted by the vendor, whether vendor sign-in and WiFiman are on, whether the
remote VPN is enabled, whether SSH binds to every interface, and which port
management answers on. Plus a count of what is published inbound, which
[`network exposure`](Network) lists in full, and any dynamic DNS entry, which is
a permanent public name pointing here.

**Outside, on request.** With `--allow-web` the public address is looked up
through mlab.sh, which adds the prefix, the reverse name, the autonomous system,
the country, the abuse contact from the registry, and whether the address is
known as hosting or proxy infrastructure.

```
  The public address, seen from outside

  abuseContact      helpdesk@apnic.net
  autonomousSystem  AS13335 Cloudflare, Inc.
  prefix            1.1.1.0/24
  hosting           true

  reverseName
    name               one.one.one.one
    forward_confirmed  true
```

That call necessarily tells the service which address you asked about, which is
the whole point of asking, and is why it is opt-in.

`--public-ip` supplies the address when the console cannot. Without it, and
behind a second router, the command says so rather than guessing.

## Why the abuse contact is in there

It is the field you need at the worst possible moment and never have to hand:
the registry contact for the block your address sits in. Reading it while
nothing is wrong is cheap.
