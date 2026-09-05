# `mlab-unifi live`

Attach to a console event stream and print what arrives. Local mode only.

```bash
mlab-unifi live                                   # the network stream
mlab-unifi live --channel protect-events
mlab-unifi live --channel protect-devices --for-seconds 60 --record frames.jsonl
mlab-unifi live --raw
```

| Flag | Effect |
| --- | --- |
| `--channel` | `network` (default), `protect-devices`, `protect-events` |
| `--for-seconds` | stop after a while instead of running until interrupted |
| `--max` | stop after this many frames |
| `--raw` | print each frame exactly as it arrived |
| `--record` | append every frame to a file, one JSON object per line |

Ctrl-C stops it. The command closes the stream politely rather than dropping the
socket, prints the summary it would have printed anyway, restores the terminal,
and exits 0: you asked it to stop and it did, so a shell chain after it still
runs. Without a `--for-seconds` or `--max` limit, that is the normal way to end
a session.

## The format is unknown, and the command says so

No frame was ever observed during development, on any channel. So nothing here
decodes a schema it cannot confirm. Frames are rendered generically, unparsable
payloads are printed rather than dropped, and `--record` exists so a real event
can be captured and studied.

When the shape is known, decoding it properly is a change to one function.

## What each channel actually does

Measured, not assumed:

| Channel | Upgrade | Then |
| --- | --- | --- |
| `protect-devices` | 101 | stays open, silent on a quiet site |
| `protect-events` | 101 | stays open, silent on a quiet site |
| `network` | 101 | **closes immediately**, code 1000, nothing sent |

The network stream closing straight away is the useful finding. The upgrade is
accepted at the proxy, and the application behind it hangs up in under a tenth
of a second with a normal closure and no reason. That is the same pattern as the
legacy Protect API, which refuses an API key and wants a session cookie.

An earlier note in this project claimed all three channels stayed open. That was
wrong: the test used to check it ignored close frames, so a stream that hung up
looked identical to one that was merely quiet. The command reports the close
code for exactly this reason.

So today: **the two Protect channels are usable, the network one is not.**

## Silence is not failure

The channels push nothing until something happens on the site. An empty run
means the network was quiet, and the command says that rather than leaving you
to guess. It is the same principle as everywhere else here: absence of a signal
is reported as absence of a signal, never as a clean result.

## JSON is one object per line

`-o json` emits JSONL, one frame per line, because a stream has no end and
cannot be a JSON array. That is deliberately different from every other command
here, all of which print a single pretty document.

```bash
mlab-unifi live --channel protect-events -o json | jq -c 'select(.type)'
```

## TLS

The stream honours the profile the same way every other request does: a
self-signed console certificate is accepted in local mode, and `--secure`
refuses it. The WebSocket library needs a TLS configuration rather than a flag,
so that posture is expressed against rustls directly in this one place.
