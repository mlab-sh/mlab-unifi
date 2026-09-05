# Secrets

**A UniFi API key is an administrator credential, not a read-only token.**

The [legacy surface](Surfaces) returns configuration sections without masking
their sensitive fields. A key created to read an inventory therefore also
returns, in clear text, enough to open an SSH session on the gateway and to
join the wireless network.

This was verified on a console running Network 10.5.67, with a key of role
`admin`, using GET requests only.

## What comes back in clear

From `rest/setting` on the legacy surface:

| Field | Contents |
| --- | --- |
| `x_ssh_password` | SSH password for the managed devices |
| `x_ssh_username` | the matching account name |
| `x_ssh_sha512passwd` | a `$6$` crypt hash of the same password |
| `x_api_token` | an API token from the management section |
| `x_mgmt_key` | management key |
| `x_private_key` | WireGuard private key, site to site |
| `x_mesh_psk` | wireless mesh pre-shared key |
| `x_element_psk` | element adoption pre-shared key |
| `x_pregenerated_dh_key` | OpenVPN Diffie-Hellman parameters |

From `rest/wlanconf`:

| Field | Contents |
| --- | --- |
| `x_passphrase` | the wireless network pre-shared key |
| `x_iapp_key` | inter-access-point protocol key |

From `stat/device`, per device:

| Field | Contents |
| --- | --- |
| `x_authkey`, `x_inform_authkey` | adoption keys |
| `syslog_key` | logging key |
| `x_vwirekey` | wireless uplink key |

Note that `key` in a `rest/setting` record is **not** a secret: it is the name
of the configuration section (`mgmt`, `ips`, `ntp`). A naive search for field
names containing "key" flags all 38 sections.

## What this means in practice

**Store and revoke the key as an admin credential.** Not in a shell history,
not in a command line where every process on the machine can read it, not in a
repository. mlab-unifi writes it to `$HOME/.mlab/unify.conf` with mode 0600
inside a 0700 directory, and warns on every run if those bits loosen.

**Anything that collects the legacy surface handles secrets.** They must be
dropped when the data is written, not when it is displayed. A snapshot taken
naively is a credential dump on disk, repeated at every collection. Fixing that
after the fact means purging a history of snapshots, so it is a rule for the
first version, not a later hardening pass.

**Derived verdicts are safe, values are not.** Checking the entropy of a
pre-shared key or spotting a default password is legitimate defensive work and
does not require keeping the value. Keep the length, the character classes and
the verdict; discard the secret.

## Rotation

If a key has been exposed, in a log, a terminal recording, a shared transcript
or a screenshot, rotate both:

1. The API key, in the console UI: Settings, Control Plane, Integrations.
2. The device SSH password, in the same UI under the management settings, since
   the key exposed it.

Rotating the API key alone is not enough. What leaked through it is still
valid.
