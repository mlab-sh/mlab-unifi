# `mlab-unifi audit`

Every graded check in one report. Local mode only.

```bash
mlab-unifi audit
mlab-unifi audit --min-severity high
mlab-unifi audit --fixes            # remediation for every finding, not only the severe ones
mlab-unifi audit -o json | jq '.[] | select(.severity=="critical")'
```

```
  SEVERITY  AREA          FINDING
  critical  credentials   device SSH accepts a password and no key
  high      credentials   the API key reads secrets in clear text
  high      detection     intrusion prevention inspects nothing
  high      segmentation  zones permit each other by default
  high      segmentation  a rule you wrote matches nothing
  high      wireless      arasaka: management frames are unprotected
  medium    exposure      inbound traffic is accepted without a trace
  ...

  15 findings
  › 1 critical, 5 high, 7 medium, 2 low

  CRITICAL · device SSH accepts a password and no key
    the password is returned in clear text by the same API key that reads this
    configuration, so holding the key is holding root on every device
    fix: install an SSH key and disable password authentication, or turn device SSH off
```

The detail and the remediation print for critical and high findings; `--fixes`
prints them for all.

## Why the checks live apart from the command

`src/audit.rs` holds the rules as pure functions over data that has already been
fetched. `src/commands/audit.rs` only collects and renders.

That split is not tidiness. A security check that cannot be tested without a
console in the loop is a check nobody verifies, so every rule here has a test
against a fixture, including the ones that must **not** fire.

## What earns a finding

**Severity is about what it costs, not how it looks.** A control that is simply
switched off is usually a decision and stays out of the report: nobody enables
TLS inspection by accident. A control that reads as protection without being one
is exactly what belongs in it.

Two findings show why that line matters:

- *intrusion prevention inspects nothing* is high, because the interface says
  protected and no signature category is selected.
- *no alert leaves the console* is low, because not configuring mail is a
  choice, not a mistake.

**A finding is only critical when two ordinary facts combine.** SSH accepting a
password is ordinary. The API key reading configuration is ordinary. Together
they mean holding the key is holding root on every device, and that is the only
critical this rule set can produce.

## A check that could not run is never a pass

Each group of data is fetched independently, and a surface that has moved costs
the checks that needed it, not the report. Those checks produce nothing, and the
count is stated:

```
  ! 2 check group(s) could not run and are not counted either way: firewall policies, ...
```

Without that line an incomplete audit reads as a clean one, which is the worst
possible failure for a tool like this.

## The finding worth explaining

*a rule you wrote matches nothing* catches the case nobody spots by reading the
rule list. A rule pointing at a zone that holds no network can never match. The
rule still expresses an intent, and that intent is **not in force**: whatever it
meant to restrict is decided by some other rule.

On the lab console, a rule named `ALICE TO SECU` restricts one VLAN to port 22
on a zone that holds nothing, while the network it was aimed at sits in a zone
another rule opens completely. The restriction is written and absent.
[`blast`](Blast) shows the consequence.

## Where the numbers come from

| Area | Reads |
| --- | --- |
| credentials | site settings: SSH, installed keys, readable secrets |
| wireless | every SSID: protected management frames, WPA3 mode, key shape |
| segmentation | default posture, 802.1X, firewall policies and zones |
| exposure | port forwards, UPnP on the gateway |
| detection | intrusion prevention categories, syslog forwarding, alerting |
| inventory | device firmware, end of support, minimum accepted version |

Each of those is also a command of its own, where the same data is shown in full
with the context this report has no room for.

## No overall score

There is a count per severity and no aggregate figure. A single number would
imply a precision this data does not support, and would let a report improve by
suppressing findings rather than fixing them.
