# `mlab-unifi ping`

Check that the current profile reaches its API, and report what is on the other
end.

```bash
mlab-unifi ping
mlab-unifi -p cloud ping
```

```
  ✔ answered in 23ms

  profile   lab (local)
  endpoint  https://192.168.1.1/proxy/network/integration/v1
  console   UniFi Network 10.5.67
  site      88f7af54-98f8-306a-a1c7-c9349722b1f6
  tls       not verified

```

In local mode it fetches `/info`. In cloud mode it asks for one host, which is
the cheapest call that proves the key is accepted.

This is the command to run first when something else misbehaves: it separates a
network problem from a credential problem from a mode problem, and it names the
exact endpoint being used, which is often the surprise.

## JSON

```bash
mlab-unifi ping -o json
```

```json
{
  "applicationVersion": "10.5.67",
  "elapsed": "112ms",
  "endpoint": "https://192.168.1.1/proxy/network/integration/v1",
  "mode": "local",
  "profile": "lab",
  "site": "88f7af54-98f8-306a-a1c7-c9349722b1f6",
  "tlsVerified": false
}
```

Suitable for a health check: exit code 0 and a parsable body, or exit code 1 and
a message on stderr.
