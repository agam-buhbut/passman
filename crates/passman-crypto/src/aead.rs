//! XChaCha20-Poly1305 authenticated encryption.
//!
//! A 192-bit (24-byte) nonce and a 128-bit (16-byte) Poly1305 tag. The tag is
//! **appended** to the ciphertext (combined form): [`encrypt`] returns
//! `ciphertext ‖ tag` and [`decrypt`] expects that same layout.
//!
//! The 192-bit nonce is large enough to be generated randomly per message
//! without a practical collision risk, which is how the rest of the system
//! uses it (a fresh [`crate::rng::random_nonce`] per encryption).

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};

use crate::error::CryptoError;
use crate::secret::{SecretArray, SecretBytes};

/// Size of the appended Poly1305 authentication tag, in bytes.
pub const TAG_LEN: usize = 16;

/// Size of the XChaCha20-Poly1305 nonce, in bytes.
pub const NONCE_LEN: usize = 24;

/// Encrypt `plaintext` under `key`, authenticating `aad`.
///
/// Returns the ciphertext with the 16-byte Poly1305 tag appended (combined
/// form), so the returned vector is `plaintext.len() + 16` bytes long.
///
/// The caller must supply a nonce that is unique under this key. The system
/// uses a fresh random 192-bit nonce per message.
///
/// # Errors
///
/// Returns [`CryptoError::AeadAuth`] if the underlying AEAD reports an error
/// (e.g. the message exceeds the cipher's length bound). It carries no detail.
pub fn encrypt(
    key: &SecretArray<32>,
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key.expose_bytes()));
    let xnonce = XNonce::from_slice(nonce);
    cipher
        .encrypt(
            xnonce,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| CryptoError::AeadAuth)
}

/// Decrypt `ciphertext_and_tag` under `key`, verifying `aad`.
///
/// `ciphertext_and_tag` must be the combined output of [`encrypt`]: the
/// ciphertext followed by its 16-byte tag.
///
/// On success the recovered plaintext is returned inside a zeroizing
/// [`SecretBytes`]. On any authentication failure — tampered ciphertext,
/// tampered tag, tampered AAD, or wrong key — this returns
/// [`CryptoError::AeadAuth`] and never yields partial plaintext.
///
/// # Errors
///
/// - [`CryptoError::InvalidLength`] if the input is shorter than the tag
///   (i.e. it cannot possibly contain a tag).
/// - [`CryptoError::AeadAuth`] on any authentication/verification failure.
pub fn decrypt(
    key: &SecretArray<32>,
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    ciphertext_and_tag: &[u8],
) -> Result<SecretBytes, CryptoError> {
    if ciphertext_and_tag.len() < TAG_LEN {
        return Err(CryptoError::InvalidLength {
            what: "ciphertext_and_tag",
            expected: TAG_LEN,
            got: ciphertext_and_tag.len(),
        });
    }

    let cipher = XChaCha20Poly1305::new(Key::from_slice(key.expose_bytes()));
    let xnonce = XNonce::from_slice(nonce);
    let plaintext = cipher
        .decrypt(
            xnonce,
            Payload {
                msg: ciphertext_and_tag,
                aad,
            },
        )
        .map_err(|_| CryptoError::AeadAuth)?;

    Ok(SecretBytes::new(plaintext))
}
