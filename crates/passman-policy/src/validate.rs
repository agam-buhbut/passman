//! Import validation for user-supplied passwords (`architecture.md` §8.7).
//!
//! [`validate`] reports — never enforces — where an imported password falls
//! short of an [`EntryPolicy`]'s class minimums, charset, and length. It is a
//! warning list so the UI can surface advice without blocking the import.

use crate::policy::{EntryPolicy, GenerationRequest, MAX_LENGTH, MIN_LENGTH};

/// A non-blocking report on how an imported password compares to a policy.
///
/// `ok` is `true` only when `issues` is empty. Issues are human-readable
/// strings intended for direct display; they are advisory and never prevent an
/// import.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationReport {
    /// Whether the password fully satisfies the policy (no issues).
    pub ok: bool,
    /// Human-readable shortfalls; empty when `ok`.
    pub issues: Vec<String>,
}

impl ValidationReport {
    fn from_issues(issues: Vec<String>) -> Self {
        Self {
            ok: issues.is_empty(),
            issues,
        }
    }
}

/// Validate `password` against `policy`, resolved over the vault default.
///
/// Checks performed (each only emits an issue, never an error):
/// - length below [`MIN_LENGTH`] or above [`MAX_LENGTH`];
/// - characters present that the resolved charset disallows or does not select;
/// - each non-zero class minimum not met by the password's character counts.
///
/// The effective policy is `policy` resolved over [`GenerationRequest::default_vault`],
/// matching how generation interprets an [`EntryPolicy`].
#[must_use]
pub fn validate(password: &str, policy: &EntryPolicy) -> ValidationReport {
    let req: GenerationRequest = policy.resolve_over(&GenerationRequest::default_vault());
    let charset = req.charset();

    let mut issues = Vec::new();

    // Length.
    let len = password.chars().count();
    if len < MIN_LENGTH as usize {
        issues.push(format!(
            "password length {len} is below the recommended minimum of {MIN_LENGTH}"
        ));
    } else if len > MAX_LENGTH as usize {
        issues.push(format!(
            "password length {len} exceeds the maximum of {MAX_LENGTH}"
        ));
    }

    // Characters outside the effective set. Report at most one summary issue so
    // a long off-charset password does not produce a wall of messages.
    let allowed: std::collections::BTreeSet<char> = charset.effective_set().into_iter().collect();
    let mut offending: std::collections::BTreeSet<char> = std::collections::BTreeSet::new();
    for c in password.chars() {
        if !allowed.contains(&c) {
            offending.insert(c);
        }
    }
    if !offending.is_empty() {
        let listed: String = offending.iter().collect();
        issues.push(format!(
            "password contains characters not permitted by the policy charset: {listed}"
        ));
    }

    // Class minimums.
    let mut lo = 0u32;
    let mut up = 0u32;
    let mut di = 0u32;
    let mut sy = 0u32;
    for c in password.chars() {
        if c.is_ascii_lowercase() {
            lo += 1;
        } else if c.is_ascii_uppercase() {
            up += 1;
        } else if c.is_ascii_digit() {
            di += 1;
        } else if c.is_ascii_punctuation() {
            sy += 1;
        }
    }
    let classes = req.required_classes();
    check_class(&mut issues, "lowercase", lo, classes.min_lowercase);
    check_class(&mut issues, "uppercase", up, classes.min_uppercase);
    check_class(&mut issues, "digit", di, classes.min_digits);
    check_class(&mut issues, "symbol", sy, classes.min_symbols);

    ValidationReport::from_issues(issues)
}

fn check_class(issues: &mut Vec<String>, name: &str, have: u32, want: u8) {
    let want = u32::from(want);
    if have < want {
        issues.push(format!(
            "password has {have} {name} character(s); policy requires at least {want}"
        ));
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;
    use crate::charset::{Charset, SymbolSet};
    use crate::policy::RequiredClasses;

    #[test]
    fn compliant_password_passes() {
        // Default vault policy: 40 long, one of each class, full symbols.
        let policy = EntryPolicy::default();
        let pw = "Abcdefghijklmnopqrstuvwxyz0123456789!@#$";
        let report = validate(pw, &policy);
        assert!(report.ok, "issues: {:?}", report.issues);
        assert!(report.issues.is_empty());
    }

    #[test]
    fn short_password_flagged_not_blocked() {
        let policy = EntryPolicy::default();
        let report = validate("Ab1!", &policy);
        assert!(!report.ok);
        assert!(report.issues.iter().any(|i| i.contains("below")));
    }

    #[test]
    fn missing_class_flagged() {
        // Require symbols but supply an all-alphanumeric password of good length.
        let report = validate(
            "Abcdefghijklmnopqrstuvwxyz0123456789ABCD",
            &EntryPolicy::default(),
        );
        assert!(!report.ok);
        assert!(report
            .issues
            .iter()
            .any(|i| i.contains("symbol") && i.contains("requires")));
    }

    #[test]
    fn off_charset_characters_flagged() {
        // Policy disallows symbols; password includes one.
        let charset = Charset::new(true, true, true, SymbolSet::None, BTreeSet::new());
        let policy = EntryPolicy::default()
            .with_charset(charset)
            .with_required_classes(RequiredClasses::none());
        let report = validate("Abcdefghij0123456789KLMNOPQRST!", &policy);
        assert!(!report.ok);
        assert!(report.issues.iter().any(|i| i.contains("not permitted")));
    }

    #[test]
    fn validation_never_panics_on_empty() {
        let report = validate("", &EntryPolicy::default());
        // Empty password: too short + missing every required class, but it must
        // return a report rather than error or panic.
        assert!(!report.ok);
    }
}
