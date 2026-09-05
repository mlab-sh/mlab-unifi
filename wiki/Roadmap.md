# Roadmap

The order is deliberate: each step is usable on its own, and each one makes the
next cheaper.

## Done

**The core CLI.** Profiles with precedence, the HTTP handler across three
[surfaces](Surfaces) plus the cloud, both pagination styles, typed API errors,
the human render and the JSON passthrough, progress that never pollutes a pipe.

**Asset inventory.** `clients list --all` joins the live client list to the
historical one on the MAC address and reports `activeNow` per device. See
[Clients](Clients).

**Raw access to every surface.** `api --surface legacy|v2` makes the whole
exploration reproducible from the CLI. See [Api](Api).

**Fingerprint resolution.** `clients list --all` names devices from the
console's own fingerprint table, with `--min-score` separating facts from
guesses and an opt-in `--allow-web` vendor lookup for the gaps. See
[Identity](Identity).

**Firmware posture.** `devices list` reports firmware freshness and model
support as two separate columns, from the console's own verdict, with an
opt-in `--allow-web` advisory listing. See [Devices](Devices).

**Segmentation and exposure.** `network list`, `get`, `exposure` and `zones`
join the documented network list to the legacy segmentation fields and report
port forwards with their logging and source restrictions. See
[Network](Network).

**Firewall rule hygiene.** `network policies` reports unlogged, duplicate, dead
and over-broad rules across the three origin classes, and states plainly that
ordering is not analysed. See [Network](Network).

**The radio side.** `wifi` covers SSID hardening, the audible neighbourhood,
impostor and bridged access points, and airtime occupancy, each stating the
channel limit that bounds it. See [Wifi](Wifi).

**Shadow IT.** `shadow` reports arrivals from `first_seen`, separating rotated
addresses from genuine ones and flagging wired arrivals and adopted hardware.
See [Shadow](Shadow).

**Security posture.** `posture` turns the 38 settings sections into checks,
keeping "off" apart from "reads as protection without being one". See
[Posture](Posture).

## Next

**1. A dated snapshot.** One command that pulls the useful routes into a single
dated file, with secrets dropped at write time rather than at display time. It
is the base of everything after it: without a photograph there is nothing to
compare.

The design point that has to land here, not later: a resource registry, one
table mapping a name to its route, its surface and its secret policy. Commands
and the snapshot both consume it, so adding a resource is a line rather than a
file. And an unavailable route is recorded as unavailable, never as absent
data, because a check that could not run must not report success.

**2. The diff.** Compare two snapshots and qualify the differences: a new
client, a changed rule, an opened port, a firmware change, a neighbouring BSSID
that appeared. This is where passive detection becomes real.

**3. The posture audit.** Deterministic checks over one snapshot: a port
forward without logging, optional PMF, an IPS with no active category, a VLAN
without isolation, a short pre-shared key. Output graded by severity, with a
third state next to pass and fail: **not evaluable**, for when the route was
unavailable.

**4. The real-time collector.** Hold the three WebSocket channels open and log
what arrives, first to document the message format, then to detect on it.

## Also wanted

- Protect routing through the CLI, so `/proxy/protect/integration/v1` is
  reachable without a direct HTTP call.
- Shell completions and a man page.
- A `--dry-run` on the two commands that change state.
