# `mlab-unifi wifi`

The radio side. Local mode only.

```bash
mlab-unifi wifi              # SSID hardening, the default
mlab-unifi wifi neighbours   # every access point the radios can hear
mlab-unifi wifi rogue        # impostor SSIDs and access points on your network
mlab-unifi wifi airtime      # who is using the air, and how much of it is not you
```

## The limit that shapes three of these

**The console does not sweep the spectrum.** An access point reports what it
overhears while sitting on its own operating channel; it does not scan. On the
lab console, all 88 neighbours report one of exactly two channels, 11 and 36,
which are the channels its own radios use. The 6 GHz radio reports nothing at
all.

So the neighbour list is a floor, never a survey, and any "nothing found" in
`neighbours` or `rogue` means "nothing on my channels". Every view built on it
repeats that under the table rather than leaving it implicit.

## `wifi`, hardening

```
  SSID     SECURITY   WPA3        PMF       PSK             ISOLATION  GUEST  ON
  arasaka  wpa2/ccmp  transition  optional  11 ch, 3 class  off        false  true

  1 SSID
  ! arasaka: WPA3 is in transition mode, so a client can still negotiate WPA2
  ! arasaka: management frames are not protected (optional), which is what makes deauthentication work
  ! arasaka: the pre-shared key is short enough to be worth attacking offline once a handshake is captured
  › arasaka: the group key is never rotated
  › arasaka: one key shared by every device, so changing it means reprovisioning all of them
```

| Reported | Why |
| --- | --- |
| `WPA3: transition` | a client may still negotiate WPA2, so none of WPA3's guarantees hold in practice |
| `PMF` other than `required` | unprotected management frames are what makes deauthentication work |
| `PSK` shape | length and character classes, flagged under 12 characters |
| group rekey `0` | the group key is never rotated |
| private keys off | one secret for every device, so rotating it means reprovisioning all of them |

The `PSK` column carries the **shape of the key, never the key**: its length and
how many character classes it draws on. That is everything a strength check
needs, and all it is entitled to. See [Secrets](Secrets).

Two settings are reported but never credited as protections: a hidden SSID and
MAC filtering. Both are trivially defeated, and a tool that lists them as
hardening misleads whoever reads it.

## `wifi neighbours`

Every access point in range, closest first, since signal is what decides
whether a neighbour matters at all.

```
  SSID           BSSID              GHZ  CH  WIDTH  SECURITY                  DBM  VENDOR
  Bbox-72613B7F  d0:5a:00:95:90:b2  5    36  160    WPA2-Personal (AES/CCMP)  -76  Vantiva USA LLC
  Freebox-3F6728 70:fc:8f:3f:67:29  2.4  11  20     WPA2-Personal (AES/CCMP)  -83  Freebox Sas

  88 access points
  › 4 open network(s) in range
  › 10 network(s) still accepting TKIP
  › strongest neighbour at -76 dBm, all of them far enough to be background noise
```

There is deliberately **no channel congestion analysis** here. Every neighbour
is on one of your channels by construction, so counting them per channel would
present an artefact of the measurement as an observation. The real congestion
figure is in `airtime`.

## `wifi rogue`

Two questions, answered by three checks.

**Is something impersonating me.** A neighbouring BSSID broadcasting one of your
SSIDs, particularly with weaker security: the client joins the copy without
noticing.

**Is something bridging my network.** Two independent paths:

- *By radio*: a bridged access point usually carries its wired address within a
  few units of the BSSID it broadcasts, under the same vendor prefix.
- *By fingerprint*: a **wired** client the console fingerprinted into a family
  that bridges networks (`Wireless Access Point`, `Wireless Router`, `Router`,
  `Firewall`, `Network Equipment`, `Smart Gateway`), gated by `--min-score` so
  a low-confidence guess is not presented as a discovery.

The fingerprint path matters because it does **not** depend on the radio, so it
is not limited to your own channels. It is the stronger of the two.

The command says one more thing under a clean result, because the silence is
misleading otherwise: an impostor has every reason to sit on a channel yours
does not use, so a clean radio result is weak evidence.

## `wifi airtime`

What the radios measure about their own channel.

```
  DEVICE          GHZ  CH  WIDTH  CLIENTS  BUSY%  SELF%  OTHERS%  RETRIES%  DBM
  Dream Router 7  2.4  11  20     4        21     6      15       6.1       15
  Dream Router 7  5    36  80     8        22     3      19       8.8       16
  Dream Router 7  6    37  320    1        2      2      0        20.0      17

  3 radios
  › 5 GHz on channel 36 carries the most traffic that is not yours: 19% of the air
  › 6 GHz is carrying nothing but your own traffic, so moving capable clients there
    sidesteps the congestion instead of chasing a quieter channel
```

`OTHERS%` is `cu_total` minus the radio's own transmit and receive share. That
is the interference figure: airtime consumed by something that is not you.

### Interference is not intent

The number says the air is busy. It does not say why, and a neighbour whose
access point picks its own channel automatically produces exactly the same
trace as one doing it deliberately. The command measures interference and never
claims malice.

### Congestion and deauthentication look different

Worth knowing, because the remedy differs:

- **Congestion**: `OTHERS%` climbs, throughput drops, clients stay associated.
- **Deauthentication**: several clients reassociate *in the same moment*. That
  signature is in the client records (`assoc_time`, `disconnect_timestamp`), not
  in airtime.

The API exposes neither deauthentication frames nor IDS events, so the second
case is visible only through its symptom. Sampling airtime over time and
correlating it with simultaneous reassociations is what separates the two, and
that needs the dated snapshot on the [Roadmap](Roadmap).

### Countermeasures that do not mean changing channel

Ordered by what actually helps:

1. **PMF `required`**, and leaving WPA3 transition mode. This is the only item
   that addresses deauthentication at its cause rather than its effect.
2. **Move capable clients to a clean band.** On the lab console 6 GHz carries
   0% foreign traffic; its shorter range, normally a drawback, keeps neighbours
   out.
3. **Narrow the channel** in 2.4 GHz. 20 MHz tolerates partial overlap better,
   and 40 MHz buys almost nothing there.
4. **Minimum RSSI and minimum data rate.** A distant client negotiating at
   1 Mbit/s holds the medium and amplifies any congestion.

Raising transmit power is the common reflex and it does not help: what matters
is the signal to noise ratio at the client, and more power degrades everyone's.

mlab-unifi reads; these changes are made in the console.
