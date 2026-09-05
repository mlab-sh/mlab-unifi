# `mlab-unifi login`

Create or update a profile, prove the credentials work, and save them.

```bash
mlab-unifi login --name lab --host 192.168.1.1
mlab-unifi login --name cloud --mode cloud
```

Aliases: `configure`, `setup`.

The wizard asks only for what it does not already have. It reads the API key
without echoing it, tests the connection before writing anything, resolves the
site, and saves to [the config file](Configuration) with mode 0600.

```
  API key (console: Settings -> Control Plane -> Integrations):
  ✔ connected to UniFi Network 10.5.67
  › site Default (88f7af54-98f8-306a-a1c7-c9349722b1f6)
  ! TLS certificate verification is off for this profile
  ✔ saved profile "lab" to /Users/you/.mlab/unify.conf
```

## Flags

| Flag | Effect |
| --- | --- |
| `--name`, `-n` | Profile to create or update. Default `default`. |
| `--set-default` | Make this the default profile. Automatic for the first one. |
| `--no-test` | Save without checking the credentials. |
| `--non-interactive` | Never prompt; fail on anything missing. |

The global flags apply too: `--host`, `--api-key`, `--site`, `--mode`,
`--insecure` / `--secure`. Anything given on the command line is not asked for.

## Updating a profile

Running `login` again on an existing name keeps what you do not override,
including the stored API key:

```bash
mlab-unifi login --name lab --host 192.168.1.50
```

```
  › keeping the stored API key (****_GJR)
```

## Site selection

In local mode the wizard lists the console's sites after connecting. One site
is chosen automatically. Several, and it asks:

```
    [1] Default (88f7af54-98f8-306a-a1c7-c9349722b1f6)
    [2] Warehouse (0f2c1a44-...)

  site number [1]:
```

Pass `--site` with a name or a UUID to skip the question. Non-interactive runs
with several sites fail rather than guess.

## Non-interactive

```bash
UNIFI_API_KEY=... mlab-unifi login --name lab --host 192.168.1.1 --non-interactive
```

Fails with a clear message if the host or the key is missing, or if the console
has more than one site and `--site` was not given.
