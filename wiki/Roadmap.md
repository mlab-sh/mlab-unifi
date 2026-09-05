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

**External footprint.** `footprint` reports the uplink and the console's own
reachability, and enriches the public address on request. See
[Footprint](Footprint).

**Blast radius.** `blast` computes what a client's zone reaches, from a rule
matrix that is sound because per-pair ordering is unambiguous. See
[Blast](Blast).

**The live streams.** `live` attaches to the event channels, records frames and
reports what each channel actually does. See [Live](Live).

**One graded report.** `audit` runs every check in one pass and grades it, with
the rules kept apart from the collection so each one is testable. See
[Audit](Audit).

**The dated snapshot.** `snapshot` collects every catalogued resource into one
file, secrets removed on write and unreadable resources recorded as such. See
[Snapshot](Snapshot).

## Next

**1. The diff.** Compare two snapshots and qualify the differences: a new
client, a changed rule, an opened port, a firmware change, a neighbouring BSSID
that appeared. This is where passive detection becomes real.

## Also wanted

- Protect routing through the CLI, so `/proxy/protect/integration/v1` is
  reachable without a direct HTTP call.
- Shell completions and a man page.
- A `--dry-run` on the two commands that change state.
