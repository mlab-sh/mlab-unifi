# `mlab-unifi info`

The console's own version information. Local mode only.

```bash
mlab-unifi info
```

```
  Console 192.168.1.1

  applicationVersion  10.5.67
```

The documented API reports only the Network application version here. Firmware
versions live on the devices themselves: see [`devices`](Devices), whose records
carry `version`, `required_version` and the end-of-life flags that matter for
vulnerability work.

The console also runs other applications with their own versions. Protect, when
installed, answers on a base that mlab-unifi does not route yet:

```
/proxy/protect/integration/v1/meta/info
```

It accepts the same API key. Reaching it from the CLI is on the
[Roadmap](Roadmap); until then it takes a direct HTTP call.
