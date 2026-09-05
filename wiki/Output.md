# Output

Two formats. A terminal render by default, raw JSON with `-o json`.

```bash
mlab-unifi devices list                          # human
mlab-unifi devices list -o json | jq -r '.[].name'
```

## The human render

Aligned blocks, dimmed labels, one blank line around each section. It is
generic rather than hand-written per command: any JSON object becomes a
key/value block, any array of objects becomes a table, nested arrays of objects
become sub-tables, and columns with no data on this console are dropped.

```
  Devices on 192.168.1.1

  NAME            MODEL           STATE   IP             FIRMWARE
  Office Switch   USW-Lite-8-PoE  ONLINE  192.168.7.235  7.5.10
  Dream Router 7  UDR7            ONLINE  192.168.1.61   5.1.31

  2 devices
```

Three unit conversions are applied, and only to unambiguously named fields:
a key ending in `Pct` gets a bar, one ending in `Bps` a bit rate, one ending in
`Sec` a duration.

```
  cpuUtilizationPct      47.9%  █████·····
  uptimeSec             561940  (6d 12h)
```

Status values are coloured by meaning: `ONLINE`, `UP` and `true` in green,
`OFFLINE`, `DOWN` and `DISCONNECTED` in red. `false` is left neutral, because an
absence is not a fault: an inventory of disconnected clients must not read as a
wall of errors.

## JSON

`-o json` prints exactly what the API returned, pretty-printed, with no unit
conversion and no colour. It is the format to script against, and the only one
that never loses information.

The one exception is [`clients list --all`](Clients), which has no single
upstream response: it is a join of two surfaces, so its JSON is the joined
shape, documented on that page.

## Progress

Three rules keep progress from ever polluting a pipeline:

1. **Progress goes to stderr.** stdout carries the result, so `-o json | jq`
   stays parsable while a spinner is running.
2. **Nothing is animated unless stderr is a terminal.** Pipes, CI logs and test
   harnesses get clean output with no escape sequences. `CI` and
   `MLAB_UNIFI_NO_PROGRESS` also turn animation off.
3. **Nothing is drawn for fast work.** The spinner appears only once a call has
   run past 250 ms, so a console answering in 20 ms produces no flicker.

`-q` (`--quiet`) silences status lines as well as the spinner.

## Exit codes

`0` on success, `1` on any error. Errors go to stderr, prefixed with a red
cross, and carry a hint when the cause is a known one:

```
  ✖ GET https://192.168.1.1/... : invalid peer certificate: UnknownIssuer
hint: consoles serve a self-signed certificate; drop --secure, or pass --insecure
```
