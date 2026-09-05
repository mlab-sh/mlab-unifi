//! The fields that must never be written to disk, and how to remove them.
//!
//! One list, used by everything that reads the legacy surface, so a field
//! cannot be redacted in one place and stored in another.

use serde_json::Value;

/// Field names holding an actual secret.
///
/// Deliberately an explicit list rather than a substring rule. Every settings
/// section carries `key` as its own name, so matching on "key" flags all 38 of
/// them, and a redactor that noisy quickly gets switched off.
pub const SECRET_FIELDS: [&str; 14] = [
    "x_ssh_password",
    "x_ssh_sha512passwd",
    "x_passphrase",
    "x_api_token",
    "x_mgmt_key",
    "x_private_key",
    "x_mesh_psk",
    "x_element_psk",
    "x_pregenerated_dh_key",
    "x_iapp_key",
    "x_authkey",
    "x_inform_authkey",
    "syslog_key",
    "x_vwirekey",
];

/// What replaces a secret: its length, and nothing else.
///
/// A length is not a secret and it is what a strength check needs, so a
/// redacted snapshot can still be audited for a short pre-shared key or counted
/// for how much the API key exposes. The value itself never reaches the disk.
pub fn marker(len: usize) -> String {
    format!("<redacted:{len}>")
}

/// Replace every secret in a document, at any depth.
///
/// Returns how many were replaced, which is itself worth recording: it is the
/// measure of what an API key hands over.
pub fn redact(v: &mut Value) -> usize {
    match v {
        Value::Object(map) => {
            let mut n = 0;
            for (k, val) in map.iter_mut() {
                if SECRET_FIELDS.contains(&k.as_str()) {
                    if let Some(s) = val.as_str() {
                        if !s.is_empty() {
                            *val = Value::String(marker(s.chars().count()));
                            n += 1;
                            continue;
                        }
                    }
                }
                n += redact(val);
            }
            n
        }
        Value::Array(items) => items.iter_mut().map(redact).sum(),
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_secret_is_replaced_by_its_length_and_nothing_else() {
        let mut v = json!({"x_ssh_password": "hunter2!"});
        assert_eq!(redact(&mut v), 1);
        assert_eq!(v["x_ssh_password"], json!("<redacted:8>"));
    }

    #[test]
    fn secrets_are_found_however_deeply_they_sit() {
        let mut v = json!({"a": [{"b": {"x_passphrase": "abcdef"}}]});
        assert_eq!(redact(&mut v), 1);
        assert_eq!(v["a"][0]["b"]["x_passphrase"], json!("<redacted:6>"));
    }

    #[test]
    fn a_section_name_is_not_a_secret() {
        // `key` is what every settings section calls itself; a substring rule
        // on it would redact the whole file into uselessness.
        let mut v = json!({"key": "mgmt", "x_ssh_keys": []});
        assert_eq!(redact(&mut v), 0);
        assert_eq!(v["key"], json!("mgmt"));
    }

    #[test]
    fn an_empty_secret_is_left_alone_rather_than_marked() {
        // Marking it would turn "this site has no mesh key" into "this site has
        // a mesh key of length zero", which reads as configured.
        let mut v = json!({"x_mesh_psk": ""});
        assert_eq!(redact(&mut v), 0);
        assert_eq!(v["x_mesh_psk"], json!(""));
    }

    #[test]
    fn everything_else_survives_untouched() {
        let mut v = json!({"name": "arasaka", "pmf_mode": "optional", "vlan": 30});
        assert_eq!(redact(&mut v), 0);
        assert_eq!(v["name"], json!("arasaka"));
        assert_eq!(v["vlan"], json!(30));
    }
}
