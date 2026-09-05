//! Firmware posture, entirely from what the console already decided.
//!
//! The vendor is the authority on whether a firmware is behind, out of support
//! or refused, and the console carries that verdict per device. No external
//! data, no version guessing, nothing that can be wrong in the way a CVE match
//! can be wrong.

use std::cmp::Ordering;

use serde_json::Value;

/// What the console says about one device's firmware.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct Posture {
    pub version: String,
    pub required: String,
    pub upgradable: bool,
    pub eol: bool,
    pub lts: bool,
    pub unsupported: bool,
    pub unsupported_reason: Option<String>,
    /// The installed version is older than the minimum the controller accepts.
    pub below_minimum: bool,
}

impl Posture {
    /// How fresh the installed firmware is.
    ///
    /// Deliberately separate from [`support`](Self::support): a device can run
    /// the newest firmware ever published for it and still be a model that
    /// receives no further fixes. Folding both into one column hides exactly
    /// the case that matters.
    pub fn label(&self) -> &'static str {
        match self {
            // No version means the record said nothing, and "current" would be
            // an assertion we cannot make.
            _ if self.version.is_empty() => "unknown",
            _ if self.below_minimum => "below minimum",
            _ if self.upgradable => "update available",
            _ => "current",
        }
    }

    /// Whether the model itself is still supported by the vendor.
    pub fn support(&self) -> &'static str {
        match self {
            _ if self.unsupported => "unsupported",
            _ if self.eol => "end of life",
            _ if self.lts => "lts branch",
            _ => "supported",
        }
    }

    /// Whether anything here deserves attention.
    pub fn needs_action(&self) -> bool {
        self.unsupported || self.eol || self.below_minimum || self.upgradable
    }
}

/// Read the posture off a legacy `stat/device` record.
pub fn assess(rec: &Value) -> Posture {
    let text = |k: &str| {
        rec.get(k)
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string()
    };
    let flag = |k: &str| rec.get(k).and_then(Value::as_bool).unwrap_or(false);

    let version = text("version");
    let required = text("required_version");
    let below_minimum = !version.is_empty()
        && !required.is_empty()
        && compare(&version, &required) == Ordering::Less;

    Posture {
        upgradable: flag("upgradable"),
        eol: flag("model_in_eol"),
        lts: flag("model_in_lts"),
        unsupported: flag("unsupported"),
        unsupported_reason: rec
            .get("unsupported_reason")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .map(str::to_string),
        below_minimum,
        version,
        required,
    }
}

/// Compare two dotted version strings component by component.
///
/// UniFi versions carry a build number (`7.5.10.17129`) and occasionally a
/// suffix, so components are compared numerically where both sides are numeric
/// and lexically otherwise. A missing component counts as zero, which makes
/// `7.5` older than `7.5.1` rather than equal to it.
pub fn compare(a: &str, b: &str) -> Ordering {
    let parts = |s: &str| -> Vec<String> { s.split(['.', '-', '+']).map(str::to_string).collect() };
    let (av, bv) = (parts(a), parts(b));

    for i in 0..av.len().max(bv.len()) {
        let x = av.get(i).map(String::as_str).unwrap_or("0");
        let y = bv.get(i).map(String::as_str).unwrap_or("0");
        let ord = match (x.parse::<u64>(), y.parse::<u64>()) {
            (Ok(m), Ok(n)) => m.cmp(&n),
            _ => x.cmp(y),
        };
        if ord != Ordering::Equal {
            return ord;
        }
    }
    Ordering::Equal
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn versions_compare_numerically_not_lexically() {
        assert_eq!(compare("7.5.10.17129", "6.3.10"), Ordering::Greater);
        // The bug a string comparison makes: "10" sorts before "9".
        assert_eq!(compare("7.10.0", "7.9.0"), Ordering::Greater);
        assert_eq!(compare("2.1.8.971", "1.1.7"), Ordering::Greater);
        assert_eq!(compare("5.1.31.34074", "5.1.31.34074"), Ordering::Equal);
    }

    #[test]
    fn a_missing_component_counts_as_zero() {
        assert_eq!(compare("7.5", "7.5.0"), Ordering::Equal);
        assert_eq!(compare("7.5", "7.5.1"), Ordering::Less);
    }

    #[test]
    fn firmware_freshness_and_model_support_are_separate_axes() {
        // The case a single column would hide: newest firmware there will ever
        // be, on hardware that receives no more fixes.
        let stranded = assess(&json!({
            "version": "4.3.20", "required_version": "4.0.0",
            "upgradable": false, "model_in_eol": true
        }));
        assert_eq!(
            stranded.label(),
            "current",
            "the firmware really is up to date"
        );
        assert_eq!(
            stranded.support(),
            "end of life",
            "and the model is still stranded"
        );
        assert!(stranded.needs_action());
    }

    #[test]
    fn the_console_verdict_is_read_as_given() {
        let up_to_date = assess(&json!({
            "version": "7.5.10.17129", "required_version": "6.3.10",
            "upgradable": false, "model_in_eol": false, "model_in_lts": false, "unsupported": false
        }));
        assert_eq!(up_to_date.label(), "current");
        assert_eq!(up_to_date.support(), "supported");
        assert!(!up_to_date.needs_action());
        assert!(!up_to_date.below_minimum);
    }

    #[test]
    fn the_worst_finding_is_the_one_that_shows() {
        let bad = assess(&json!({
            "version": "1.0.0", "required_version": "6.3.10",
            "upgradable": true, "model_in_eol": true, "unsupported": true
        }));
        assert_eq!(
            bad.label(),
            "below minimum",
            "the worst firmware finding wins its column"
        );
        assert_eq!(
            bad.support(),
            "unsupported",
            "and the worst support finding wins its own"
        );
        assert!(
            bad.eol && bad.below_minimum && bad.upgradable,
            "the rest stays in the data"
        );
    }

    #[test]
    fn being_behind_the_minimum_is_detected_from_the_versions() {
        let stale = assess(&json!({"version": "6.0.0", "required_version": "6.3.10"}));
        assert!(stale.below_minimum);
        assert_eq!(stale.label(), "below minimum");
    }

    #[test]
    fn a_record_with_no_versions_claims_nothing() {
        let empty = assess(&json!({}));
        assert!(!empty.below_minimum, "absent data is not a finding");
        assert_eq!(
            empty.label(),
            "unknown",
            "and absent data is not a clean bill either"
        );
        assert!(!empty.needs_action());
    }
}
