//! Password generation: unbiased sampling from `OsRng` + Fisher-Yates shuffle.
//!
//! Implements `architecture.md` §8.1. All randomness is the OS CSPRNG
//! ([`OsRng`]); there is no seeded or userspace PRNG anywhere. Uniform sampling
//! uses rejection sampling to avoid the modulo bias a naive `% range` would
//! introduce (threat #24).

use passman_crypto::SecretString;
use rand::rngs::OsRng;
use rand::RngCore;

use crate::error::PolicyError;
use crate::policy::{GenerationRequest, MAX_LENGTH, MIN_LENGTH};

/// Uniformly select one element of `pool` using rejection sampling on `OsRng`.
///
/// # Why rejection sampling
///
/// Reducing a raw 32-bit RNG output modulo `n` over-weights the first
/// `2^32 mod n` values whenever `n` does not divide `2^32` (modulo bias). We
/// instead reject any draw at or above the largest multiple of `n` that fits in
/// `u32`, so every accepted value maps to exactly one element. The expected
/// number of draws is < 2 for any `n`, so this terminates quickly.
///
/// # Panics
///
/// Panics if `pool` is empty; callers guarantee non-empty pools (the effective
/// set is validated to have ≥ 2 chars, and each required class is checked to be
/// non-empty before sampling). Panics only if `OsRng` fails irrecoverably
/// (its documented behaviour — see `passman-crypto::rng`).
fn uniform_from(pool: &[char], rng: &mut OsRng) -> char {
    // Pools are tiny (a character class, <= 94 elements), so `try_from` cannot
    // realistically fail; saturate on the impossible overflow rather than panic.
    let n = u32::try_from(pool.len()).unwrap_or(u32::MAX);
    debug_assert!(n > 0, "uniform_from called with an empty pool");
    // Largest multiple of `n` representable in u32; draws >= this are rejected.
    let zone = u32::MAX - (u32::MAX % n);
    loop {
        let r = rng.next_u32();
        if r < zone {
            return pool[(r % n) as usize];
        }
    }
}

/// Fisher-Yates (Durstenfeld) in-place shuffle using `OsRng`, so the
/// required-class characters placed first are not positionally predictable.
///
/// Uses the same rejection-sampling helper to pick each swap index without
/// modulo bias.
fn shuffle(buf: &mut [char], rng: &mut OsRng) {
    if buf.len() < 2 {
        return;
    }
    // i from len-1 down to 1; pick j uniformly in 0..=i, then swap.
    for i in (1..buf.len()).rev() {
        // `i + 1 <= buf.len()`, which for any real password fits in u32;
        // saturate on the impossible overflow rather than panic.
        let bound = u32::try_from(i + 1).unwrap_or(u32::MAX);
        let zone = u32::MAX - (u32::MAX % bound);
        let j = loop {
            let r = rng.next_u32();
            if r < zone {
                break (r % bound) as usize;
            }
        };
        buf.swap(i, j);
    }
}

/// Generate a password satisfying `req`.
///
/// Algorithm (`architecture.md` §8.1):
/// 1. Build the effective set = selected classes − `disallow`; reject if it has
///    fewer than 2 characters or if `Σ minimums > length`.
/// 2. Enforce the 16..=256 length bound.
/// 3. Place each required-class minimum (sampled from that class ∩ effective
///    set), then fill the remainder from the full effective set.
/// 4. Fisher-Yates shuffle so required characters are not positionally fixed.
/// 5. Return as a zeroizing [`SecretString`].
///
/// # Zeroization
///
/// The password is assembled in a `Vec<char>` working buffer, collected into
/// the final `String`, and that `String` is moved into the [`SecretString`]
/// (which zeroizes on drop). The `Vec<char>` working buffer is explicitly
/// overwritten and dropped before returning so no un-zeroized copy of the
/// password outlives this call. (`char`s are not individually secret, but the
/// assembled sequence is, so we scrub it.)
///
/// # Errors
///
/// - [`PolicyError::LengthOutOfRange`] if `length` is outside 16..=256.
/// - [`PolicyError::EmptyCharset`] if the effective set has fewer than 2 chars.
/// - [`PolicyError::ImpossibleConstraints`] if `Σ minimums > length`.
/// - [`PolicyError::RequiredClassUnavailable`] if a class has a non-zero
///   minimum but no characters survive in the effective set.
pub fn generate(req: &GenerationRequest) -> Result<SecretString, PolicyError> {
    let length = req.length();
    if !(MIN_LENGTH..=MAX_LENGTH).contains(&length) {
        return Err(PolicyError::LengthOutOfRange { length });
    }

    let charset = req.charset();
    let effective = charset.effective_set();
    if effective.len() < 2 {
        return Err(PolicyError::EmptyCharset);
    }

    let classes = req.required_classes();
    let required_total = classes.total();
    if required_total > u32::from(length) {
        return Err(PolicyError::ImpossibleConstraints {
            required: required_total,
            length,
        });
    }

    // Per-class pools (each already filtered by `disallow`). A class with a
    // non-zero minimum but an empty pool is unsatisfiable.
    let class_pools: [(&'static str, u8, Vec<char>); 4] = [
        (
            "lowercase",
            classes.min_lowercase,
            charset.effective_lowercase(),
        ),
        (
            "uppercase",
            classes.min_uppercase,
            charset.effective_uppercase(),
        ),
        ("digits", classes.min_digits, charset.effective_digits()),
        ("symbols", classes.min_symbols, charset.effective_symbols()),
    ];
    for (class, minimum, pool) in &class_pools {
        if *minimum > 0 && pool.is_empty() {
            return Err(PolicyError::RequiredClassUnavailable {
                class,
                minimum: *minimum,
            });
        }
    }

    let mut rng = OsRng;
    let mut buf: Vec<char> = Vec::with_capacity(length as usize);

    // 3a. Required-class minimums first.
    for (_, minimum, pool) in &class_pools {
        for _ in 0..*minimum {
            buf.push(uniform_from(pool, &mut rng));
        }
    }

    // 3b. Fill the remainder from the full effective set.
    while buf.len() < length as usize {
        buf.push(uniform_from(&effective, &mut rng));
    }

    // 4. Shuffle so the required chars are not in fixed leading positions.
    shuffle(&mut buf, &mut rng);

    // 5. Collect into the final String, then scrub the working buffer.
    let password: String = buf.iter().collect();
    buf.fill('\0');
    buf.clear();
    drop(buf);

    Ok(SecretString::new(password))
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeSet, HashSet};

    use super::*;
    use crate::charset::{Charset, SymbolSet, DIGITS, FULL_SYMBOLS, LOWERCASE, UPPERCASE};
    use crate::policy::RequiredClasses;

    fn class_counts(pw: &str) -> (usize, usize, usize, usize) {
        let mut lo = 0;
        let mut up = 0;
        let mut di = 0;
        let mut sy = 0;
        for c in pw.chars() {
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
        (lo, up, di, sy)
    }

    #[test]
    fn default_policy_length_and_alphabet() {
        let req = GenerationRequest::default_vault();
        let pw = generate(&req).expect("default policy must generate");
        let s = pw.expose();
        assert_eq!(s.chars().count(), 40);

        let allowed: HashSet<char> = LOWERCASE
            .iter()
            .chain(UPPERCASE)
            .chain(DIGITS)
            .chain(FULL_SYMBOLS)
            .copied()
            .collect();
        assert!(s.chars().all(|c| allowed.contains(&c)));

        let (lo, up, di, sy) = class_counts(s);
        assert!(lo >= 1 && up >= 1 && di >= 1 && sy >= 1);
    }

    #[test]
    fn two_generations_differ() {
        let req = GenerationRequest::default_vault();
        let a = generate(&req).expect("gen a");
        let b = generate(&req).expect("gen b");
        // Collision probability for two 40-char draws over 94 symbols is
        // astronomically small; a match indicates a broken RNG path.
        assert_ne!(a.expose(), b.expose());
    }

    #[test]
    fn respects_disallow_and_no_symbols() {
        let mut disallow = BTreeSet::new();
        for c in ['O', '0', 'l', '1', 'I'] {
            disallow.insert(c);
        }
        let charset = Charset::new(true, true, true, SymbolSet::None, disallow.clone());
        let classes = RequiredClasses {
            min_lowercase: 2,
            min_uppercase: 2,
            min_digits: 2,
            min_symbols: 0,
        };
        let req = GenerationRequest::new(32, charset, classes);
        let pw = generate(&req).expect("constrained policy must generate");
        let s = pw.expose();

        assert_eq!(s.chars().count(), 32);
        assert!(!s.chars().any(|c| disallow.contains(&c)));
        // No symbols selected: every char is alphanumeric.
        assert!(s.chars().all(|c| c.is_ascii_alphanumeric()));
        let (lo, up, di, sy) = class_counts(s);
        assert!(lo >= 2 && up >= 2 && di >= 2);
        assert_eq!(sy, 0);
    }

    #[test]
    fn impossible_constraints_rejected() {
        let classes = RequiredClasses {
            min_lowercase: 10,
            min_uppercase: 10,
            min_digits: 0,
            min_symbols: 0,
        };
        let req = GenerationRequest::new(16, Charset::default_vault(), classes);
        assert_eq!(
            generate(&req),
            Err(PolicyError::ImpossibleConstraints {
                required: 20,
                length: 16
            })
        );
    }

    #[test]
    fn empty_charset_rejected() {
        // No classes enabled at all -> effective set is empty.
        let charset = Charset::new(false, false, false, SymbolSet::None, BTreeSet::new());
        let req = GenerationRequest::new(16, charset, RequiredClasses::none());
        assert_eq!(generate(&req), Err(PolicyError::EmptyCharset));
    }

    #[test]
    fn single_char_effective_set_rejected() {
        // Only digits enabled, all but one digit disallowed -> 1-char set.
        let mut disallow: BTreeSet<char> = DIGITS.iter().copied().collect();
        disallow.remove(&'7');
        let charset = Charset::new(false, false, true, SymbolSet::None, disallow);
        let req = GenerationRequest::new(16, charset, RequiredClasses::none());
        assert_eq!(generate(&req), Err(PolicyError::EmptyCharset));
    }

    #[test]
    fn length_out_of_range_rejected() {
        let too_short =
            GenerationRequest::new(15, Charset::default_vault(), RequiredClasses::none());
        assert_eq!(
            generate(&too_short),
            Err(PolicyError::LengthOutOfRange { length: 15 })
        );
        let too_long =
            GenerationRequest::new(257, Charset::default_vault(), RequiredClasses::none());
        assert_eq!(
            generate(&too_long),
            Err(PolicyError::LengthOutOfRange { length: 257 })
        );
    }

    #[test]
    fn required_class_unavailable_rejected() {
        // Require a symbol but select SymbolSet::None.
        let charset = Charset::new(true, true, true, SymbolSet::None, BTreeSet::new());
        let classes = RequiredClasses {
            min_lowercase: 0,
            min_uppercase: 0,
            min_digits: 0,
            min_symbols: 1,
        };
        let req = GenerationRequest::new(16, charset, classes);
        assert_eq!(
            generate(&req),
            Err(PolicyError::RequiredClassUnavailable {
                class: "symbols",
                minimum: 1
            })
        );
    }

    #[test]
    fn boundary_lengths_accepted() {
        for len in [MIN_LENGTH, MAX_LENGTH] {
            let req = GenerationRequest::new(
                len,
                Charset::default_vault(),
                RequiredClasses::one_of_each(),
            );
            let pw = generate(&req).expect("boundary length must generate");
            assert_eq!(pw.expose().chars().count(), len as usize);
        }
    }

    #[test]
    fn uniform_from_covers_pool() {
        // Sanity: sampling a 2-element pool many times hits both elements.
        let mut rng = OsRng;
        let pool = ['a', 'b'];
        let mut seen_a = false;
        let mut seen_b = false;
        for _ in 0..256 {
            match uniform_from(&pool, &mut rng) {
                'a' => seen_a = true,
                'b' => seen_b = true,
                other => panic!("unexpected char {other}"),
            }
        }
        assert!(seen_a && seen_b);
    }

    #[test]
    fn shuffle_preserves_multiset() {
        let mut rng = OsRng;
        let mut buf: Vec<char> = "abcdefghij0123456789".chars().collect();
        let before: BTreeSet<char> = buf.iter().copied().collect();
        let original_len = buf.len();
        shuffle(&mut buf, &mut rng);
        assert_eq!(buf.len(), original_len);
        let after: BTreeSet<char> = buf.iter().copied().collect();
        assert_eq!(before, after);
    }
}
