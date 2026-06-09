//! Integration tests against the public `passman-policy` API: policy merging,
//! end-to-end generation through a resolved request, and the export-gate
//! classifier. These exercise only the crate's public surface.

use std::collections::BTreeSet;

use passman_policy::{
    classify, generate, generated_entropy_bits, Charset, EntryPolicy, GenerationRequest,
    RequiredClasses, StrengthTier, SymbolSet, DEFAULT_LENGTH,
};

#[test]
fn empty_policy_resolves_to_vault_default() {
    let default = GenerationRequest::default_vault();
    let resolved = EntryPolicy::default().resolve_over(&default);
    assert_eq!(resolved, default);
    assert_eq!(resolved.length(), DEFAULT_LENGTH);
}

#[test]
fn length_override_only_changes_length() {
    let default = GenerationRequest::default_vault();
    let policy = EntryPolicy::default().with_length(20);
    let resolved = policy.resolve_over(&default);

    assert_eq!(resolved.length(), 20);
    // Charset and class minimums are inherited unchanged.
    assert_eq!(resolved.charset(), default.charset());
    assert_eq!(resolved.required_classes(), default.required_classes());
}

#[test]
fn charset_and_classes_override_compose() {
    let default = GenerationRequest::default_vault();
    let mut disallow = BTreeSet::new();
    disallow.insert('O');
    disallow.insert('0');
    let charset = Charset::new(true, true, true, SymbolSet::Basic, disallow);
    let classes = RequiredClasses {
        min_lowercase: 3,
        min_uppercase: 0,
        min_digits: 1,
        min_symbols: 0,
    };
    let policy = EntryPolicy::default()
        .with_length(24)
        .with_charset(charset.clone())
        .with_required_classes(classes);

    let resolved = policy.resolve_over(&default);
    assert_eq!(resolved.length(), 24);
    assert_eq!(resolved.charset(), &charset);
    assert_eq!(resolved.required_classes(), classes);
}

#[test]
fn generate_from_resolved_override_respects_constraints() {
    let default = GenerationRequest::default_vault();
    let mut disallow = BTreeSet::new();
    for c in ['O', '0', 'l', '1'] {
        disallow.insert(c);
    }
    let charset = Charset::new(true, true, true, SymbolSet::Basic, disallow.clone());
    let policy = EntryPolicy::default()
        .with_length(28)
        .with_charset(charset)
        .with_required_classes(RequiredClasses {
            min_lowercase: 2,
            min_uppercase: 2,
            min_digits: 2,
            min_symbols: 2,
        });

    let resolved = policy.resolve_over(&default);
    let pw = generate(&resolved).expect("resolved override must generate");
    let s = pw.expose();

    assert_eq!(s.chars().count(), 28);
    assert!(!s.chars().any(|c| disallow.contains(&c)));

    let lo = s.chars().filter(char::is_ascii_lowercase).count();
    let up = s.chars().filter(char::is_ascii_uppercase).count();
    let di = s.chars().filter(char::is_ascii_digit).count();
    let sy = s.chars().filter(char::is_ascii_punctuation).count();
    assert!(lo >= 2 && up >= 2 && di >= 2 && sy >= 2);
}

#[test]
fn default_vault_generates_and_meets_entropy_floor() {
    let req = GenerationRequest::default_vault();
    let pw = generate(&req).expect("default vault must generate");
    assert_eq!(pw.expose().chars().count(), DEFAULT_LENGTH as usize);

    // The default charset has 94 distinct chars; entropy must clear Excellent.
    let bits = generated_entropy_bits(94, DEFAULT_LENGTH);
    assert!(bits > 85.0);
    assert_eq!(classify(bits), StrengthTier::Excellent);
}

#[test]
fn user_note_is_metadata_and_ignored_in_resolution() {
    let default = GenerationRequest::default_vault();
    let with_note = EntryPolicy::default().with_user_note("max length 12 on this site".to_owned());
    // The note must not affect the resolved request.
    assert_eq!(with_note.resolve_over(&default), default);
    assert_eq!(with_note.user_note(), Some("max length 12 on this site"));
}
