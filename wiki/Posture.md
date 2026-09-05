# `mlab-unifi posture`

What the site's own settings say it is defending, and with what. Local mode
only.

```bash
mlab-unifi posture
```

One legacy route, `rest/setting`, turned into checks across six areas: threats,
inspection, access, logging, upkeep, secrets.

```
  AREA        CHECK                          STATE  DETAIL
  threats     intrusion prevention           weak   no signature category is selected, so nothing is inspected
  threats     ad blocking                    ok
  inspection  deep packet inspection         ok     with fingerprinting
  inspection  TLS inspection                 off
  access      device SSH                     weak   enabled with no key, so password only
  access      guest portal                   weak   open, anyone reaching it is admitted
  access      802.1X on switch ports         off    a device plugged into a port joins without authenticating
  access      default posture between zones  weak   ALLOW_ALL, so a zone pair with no rule is permitted
  logging     syslog                         weak   kept on the console only, nothing is forwarded
  logging     statistics retention           ok     24h at 5 minutes, 7d hourly, 90d daily
  secrets     readable by this API key       weak   8 field(s) come back in clear text

  22 checks
  ! intrusion prevention: no signature category is selected, so nothing is inspected
  ! device SSH: enabled with no key, so password only
  › 7 control(s) simply off, which is usually a decision rather than an oversight
```

## Off and weak are not the same thing

This distinction is the whole command, and conflating the two is how a posture
report turns into noise nobody reads.

| State | Meaning | Treatment |
| --- | --- | --- |
| `ok` | doing what its name says | listed |
| `off` | not enabled | listed without comment |
| `weak` | **reads as protection without being one** | raised under the table |
| `unknown` | the section was not returned | listed, never counted as a pass |

Nobody enables TLS inspection or a NetFlow collector by accident, so `off` is
almost always a decision and the command does not argue with it. An intrusion
prevention engine that is switched on with no signature category selected is a
different matter: the interface says protected, and nothing is inspected.

`unknown` exists for the same reason it exists in
[Devices](Devices) and [Network](Network). A check that could not run must never
report success.

## What each area covers

**threats** intrusion prevention and its selected categories, ad blocking, DNS
filtering per network, advanced filtering, geo IP filtering.

**inspection** deep packet inspection and fingerprinting, TLS inspection, DNS
over HTTPS.

**access** device SSH and whether a key is installed, the guest portal and its
authentication, remote VPN, 802.1X on switch ports, UPnP on the gateway, and the
default security posture between firewall zones.

**logging** syslog and whether anything is forwarded off the console, flow
export, mail alerting, and how long statistics are kept.

**upkeep** automatic backup, automatic firmware upgrade, usage analytics.

**secrets** how many fields come back in clear text through the API key you are
holding. See [Secrets](Secrets).

## Two checks worth explaining

**A DNS filter set to `none`.** The entry exists and is attached to a network,
so the configuration reads as done. It filters nothing. That is exactly the
shape this command exists to catch.

**Syslog kept on the console.** Logging is enabled, which looks right, but
nothing is forwarded anywhere. Logs that live only on the console disappear with
the console, which is precisely the case an investigation needs them for.

## What it reads together with the rest

Three findings only mean something next to another command's:

- `802.1X off` next to [`shadow`](Shadow) reporting arrivals on a wire: nothing
  authenticates a device plugged into a port.
- `default posture ALLOW_ALL` next to [`network policies`](Network): a zone pair
  with no rule is permitted, so the rule set is an allow list on top of an
  allow-all default.
- `secrets readable` next to [Secrets](Secrets): the SSH password the `device
  SSH` check calls password-only is itself readable through this API.

## Counting secrets

The field names are an explicit list, not a substring rule. Every settings
section carries `key` as its own name, and matching on "key" reports all 38
sections as credentials. That mistake was made once during exploration and the
list exists so it cannot come back.
