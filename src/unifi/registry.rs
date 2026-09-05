//! The catalogue of everything worth collecting, in one table.
//!
//! A resource is a name, a surface and a path. Adding one is a line here
//! rather than a file somewhere, and the snapshot walks the table instead of
//! carrying its own list, so the two cannot drift apart.
//!
//! `{site}` in a path is the documented UUID, `{legacy}` the short name the
//! internal surfaces use. Which one a surface wants is not a choice.

use crate::unifi::Surface;

/// How two collections of this resource are compared.
///
/// The distinction is what keeps a diff readable. An inventory churns by
/// design: a client's byte counters and a neighbour's signal change every time
/// anything is measured, and comparing them field by field would bury a new
/// device under a thousand meaningless deltas. Configuration does not churn,
/// so there every field is worth watching.
pub enum Compare {
    /// Only who is present. Field changes are ignored entirely.
    Presence { key: &'static str },
    /// Field by field. An empty `watch` means every field, which is only safe
    /// on a resource that is pure configuration.
    Fields {
        key: &'static str,
        watch: &'static [&'static str],
    },
    /// Telemetry, or a duplicate of another resource. Not compared.
    Skip,
}

pub struct Resource {
    /// How the snapshot and the diff refer to it. Stable: renaming one breaks
    /// comparison with every snapshot already taken.
    pub name: &'static str,
    pub surface: Surface,
    pub path: &'static str,
    /// One line on what it is for, shown by `snapshot --resources`.
    pub about: &'static str,
    pub compare: Compare,
}

/// Everything the commands read, and therefore everything a snapshot holds.
pub const RESOURCES: &[Resource] = &[
    // The documented surface.
    Resource {
        name: "sites",
        surface: Surface::Integration,
        path: "/sites",
        about: "the sites on this console",
        compare: Compare::Fields {
            key: "id",
            watch: &[],
        },
    },
    Resource {
        name: "devices",
        surface: Surface::Integration,
        path: "/sites/{site}/devices",
        about: "managed hardware, as the documented API sees it",
        compare: Compare::Fields {
            key: "id",
            watch: &["name", "model", "state", "ipAddress", "firmwareVersion"],
        },
    },
    Resource {
        name: "clients",
        surface: Surface::Integration,
        path: "/sites/{site}/clients",
        about: "clients connected at the moment of the snapshot",
        compare: Compare::Presence { key: "macAddress" },
    },
    Resource {
        name: "networks",
        surface: Surface::Integration,
        path: "/sites/{site}/networks",
        about: "networks with their VLAN and firewall zone",
        compare: Compare::Fields {
            key: "id",
            watch: &[],
        },
    },
    Resource {
        name: "firewall-policies",
        surface: Surface::Integration,
        path: "/sites/{site}/firewall/policies",
        about: "every rule, with its origin class",
        compare: Compare::Fields {
            key: "id",
            watch: &[],
        },
    },
    Resource {
        name: "firewall-zones",
        surface: Surface::Integration,
        path: "/sites/{site}/firewall/zones",
        about: "zones and the networks in them",
        compare: Compare::Fields {
            key: "id",
            watch: &[],
        },
    },
    Resource {
        name: "traffic-matching-lists",
        surface: Surface::Integration,
        path: "/sites/{site}/traffic-matching-lists",
        about: "named port and address lists used by rules",
        compare: Compare::Fields {
            key: "id",
            watch: &[],
        },
    },
    // The legacy surface: where the configuration actually lives.
    Resource {
        name: "device-detail",
        surface: Surface::Legacy,
        path: "/s/{legacy}/stat/device",
        about: "the full device records, with firmware and support state",
        compare: Compare::Fields {
            key: "mac",
            watch: &[
                "name",
                "version",
                "required_version",
                "model_in_eol",
                "model_in_lts",
                "unsupported",
                "upgradable",
                "adopted",
                "ip",
            ],
        },
    },
    Resource {
        name: "clients-known",
        surface: Surface::Legacy,
        path: "/s/{legacy}/rest/user",
        about: "every client ever seen, with first and last sighting",
        compare: Compare::Presence { key: "mac" },
    },
    Resource {
        name: "settings",
        surface: Surface::Legacy,
        path: "/s/{legacy}/rest/setting",
        about: "the site configuration, secrets removed on write",
        compare: Compare::Fields {
            key: "key",
            watch: &[],
        },
    },
    Resource {
        name: "wlans",
        surface: Surface::Legacy,
        path: "/s/{legacy}/rest/wlanconf",
        about: "wireless networks and their hardening",
        compare: Compare::Fields {
            key: "_id",
            watch: &[],
        },
    },
    Resource {
        name: "network-detail",
        surface: Surface::Legacy,
        path: "/s/{legacy}/rest/networkconf",
        about: "networks with isolation, DHCP and mDNS",
        compare: Compare::Fields {
            key: "_id",
            watch: &[],
        },
    },
    Resource {
        name: "port-forwards",
        surface: Surface::Legacy,
        path: "/s/{legacy}/rest/portforward",
        about: "what is published inbound",
        compare: Compare::Fields {
            key: "_id",
            watch: &[],
        },
    },
    Resource {
        name: "health",
        surface: Surface::Legacy,
        path: "/s/{legacy}/stat/health",
        about: "the uplink and per-subsystem counters",
        compare: Compare::Skip,
    },
    Resource {
        name: "sysinfo",
        surface: Surface::Legacy,
        path: "/s/{legacy}/stat/sysinfo",
        about: "versions, ports and retention",
        compare: Compare::Fields {
            key: "hostname",
            watch: &[
                "version",
                "build",
                "update_available",
                "udm_version",
                "timezone",
            ],
        },
    },
    Resource {
        name: "neighbours",
        surface: Surface::Legacy,
        path: "/s/{legacy}/stat/rogueap",
        about: "access points the radios can hear",
        compare: Compare::Presence { key: "bssid" },
    },
    // The v2 surface: the only one carrying connection state on a rule.
    Resource {
        name: "firewall-policies-v2",
        surface: Surface::V2,
        path: "/site/{legacy}/firewall-policies",
        about: "the same rules with their connection state, needed for reachability",
        compare: Compare::Skip,
    },
    Resource {
        name: "topology",
        surface: Surface::V2,
        path: "/site/{legacy}/topology",
        about: "how devices and clients are linked",
        compare: Compare::Skip,
    },
];

impl Resource {
    /// The path with both site identifiers filled in.
    pub fn path_for(&self, site: &str, legacy: &str) -> String {
        self.path
            .replace("{site}", site)
            .replace("{legacy}", legacy)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn names_are_unique_because_a_snapshot_keys_on_them() {
        let mut seen = HashSet::new();
        for r in RESOURCES {
            assert!(seen.insert(r.name), "duplicate resource name: {}", r.name);
        }
    }

    #[test]
    fn each_surface_gets_the_site_identifier_it_understands() {
        for r in RESOURCES {
            match r.surface {
                Surface::Integration => assert!(
                    !r.path.contains("{legacy}"),
                    "{} takes the documented UUID, not the short name",
                    r.name
                ),
                _ => assert!(
                    !r.path.contains("{site}"),
                    "{} takes the short name, not the documented UUID",
                    r.name
                ),
            }
        }
    }

    #[test]
    fn a_path_is_filled_with_the_right_identifier() {
        let dev = RESOURCES.iter().find(|r| r.name == "devices").unwrap();
        assert_eq!(dev.path_for("uuid-1", "default"), "/sites/uuid-1/devices");

        let legacy = RESOURCES.iter().find(|r| r.name == "settings").unwrap();
        assert_eq!(
            legacy.path_for("uuid-1", "default"),
            "/s/default/rest/setting"
        );
    }
}
