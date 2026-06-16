//! Role-typed key newtypes (`architecture.md` §2.3, §4.2).
//!
//! [`MasterKey`] and [`EntryKey`] are transparent newtypes over
//! [`SecretArray<32>`] that name a key's role at function signatures, so a
//! 32-byte key for one purpose (e.g. `K_hsm`) cannot be silently passed where
//! `K_master` is expected. They [`Deref`] to the inner [`SecretArray<32>`], so
//! they still feed the crypto primitives ([`crate::hkdf_expand`],
//! [`crate::aead`]) unchanged via deref coercion.
//!
//! - `MasterKey` is the root vault key `K_master` (§4.2): the HKDF PRK from
//!   which `K_index` and every `K_entry` are expanded.
//! - `EntryKey` is a per-entry key `K_entry(id)` (§4.4), an ephemeral key that
//!   encrypts exactly one entry envelope.
//!
//! Both keep [`SecretArray`]'s guarantees: zeroized on drop, no `Clone`/`Copy`,
//! redacted `Debug`, constant-time equality.

use core::fmt;
use core::ops::Deref;

use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::secret::SecretArray;

macro_rules! define_key_newtype {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Zeroize, ZeroizeOnDrop)]
        pub struct $name(SecretArray<32>);

        impl $name {
            #[doc = concat!("Wrap a 32-byte key as a [`", stringify!($name), "`].")]
            #[must_use]
            pub fn new(key: SecretArray<32>) -> Self {
                Self(key)
            }
        }

        /// Derefs to the inner [`SecretArray<32>`] so the key still feeds the
        /// crypto primitives directly via deref coercion.
        impl Deref for $name {
            type Target = SecretArray<32>;
            fn deref(&self) -> &SecretArray<32> {
                &self.0
            }
        }

        /// Constant-time equality, delegated to the inner [`SecretArray`].
        impl PartialEq for $name {
            fn eq(&self, other: &Self) -> bool {
                self.0 == other.0
            }
        }

        impl Eq for $name {}

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(concat!(stringify!($name), "(***)"))
            }
        }
    };
}

define_key_newtype! {
    /// The root vault key `K_master` (`architecture.md` §4.2): the HKDF PRK from
    /// which `K_index` and every per-entry `K_entry` are expanded.
    MasterKey
}

define_key_newtype! {
    /// A per-entry key `K_entry(id)` (`architecture.md` §4.4): an ephemeral
    /// 256-bit key that encrypts exactly one entry envelope.
    EntryKey
}

#[cfg(test)]
mod tests {
    use super::{EntryKey, MasterKey};
    use crate::secret::SecretArray;
    use zeroize::{Zeroize, ZeroizeOnDrop};

    fn assert_zeroizing<T: Zeroize + ZeroizeOnDrop>() {}

    #[test]
    fn key_newtypes_zeroize_on_drop() {
        assert_zeroizing::<MasterKey>();
        assert_zeroizing::<EntryKey>();
    }

    #[test]
    fn deref_exposes_inner_array() {
        let m = MasterKey::new(SecretArray::new([7u8; 32]));
        // Deref coercion: a &MasterKey is usable as &SecretArray<32>.
        assert_eq!(m.expose(), &[7u8; 32]);
        assert_eq!(m.len(), 32);

        let e = EntryKey::new(SecretArray::new([9u8; 32]));
        assert_eq!(e.expose(), &[9u8; 32]);
    }

    #[test]
    fn debug_is_redacted() {
        let m = MasterKey::new(SecretArray::new([1u8; 32]));
        assert_eq!(format!("{m:?}"), "MasterKey(***)");
        let e = EntryKey::new(SecretArray::new([1u8; 32]));
        assert_eq!(format!("{e:?}"), "EntryKey(***)");
    }

    #[test]
    fn constant_time_eq() {
        assert_eq!(
            MasterKey::new(SecretArray::new([3u8; 32])),
            MasterKey::new(SecretArray::new([3u8; 32]))
        );
        assert_ne!(
            MasterKey::new(SecretArray::new([3u8; 32])),
            MasterKey::new(SecretArray::new([4u8; 32]))
        );
    }
}
