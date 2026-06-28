//! The vault container: binary layout, sealed index, per-entry envelopes, and
//! the crypto operations over a caller-supplied `K_master`.
//!
//! `Vault` is pure: it parses from and serializes to `&[u8]`/`Vec<u8>` and
//! performs no I/O (`architecture.md` §2.3). It does not derive the master key;
//! it receives `K_master: &MasterKey` and derives `K_index` and per-entry
//! `K_entry` from it via [`passman_crypto::hkdf_expand`] (`architecture.md`
//! §4.2). The binary format follows the offset table in `architecture.md` §4.7
//! byte-for-byte.

use passman_crypto::{
    aead, ct_eq, hkdf_expand, random_nonce, EntryKey, KdfParams, MasterKey, SecretBytes,
    KDF_PARAMS_LEN,
};
use passman_policy::EntryPolicy;

use crate::error::VaultError;
use crate::id::{EntryId, ENTRY_ID_LEN};
use crate::index::{entry_info, Index, IndexEntry, INDEX_INFO};
use crate::reader::Reader;
use crate::record::EntryRecord;

/// The vault format version this build produces (`architecture.md` §4.7 /
/// §4.10).
///
/// `0x02` introduced bucket padding of the sealed index (the per-envelope
/// bodies were already padded). The only on-disk difference from `0x01` is the
/// sealed-index *plaintext* encoding: under `0x02` it is `true_len(u32-LE) ‖
/// postcard ‖ zero-pad` to a [`INDEX_BUCKET`] multiple, so the
/// `sealed_index_ct_len` field no longer leaks the sum of label/policy byte
/// lengths (threat #18 / §4.5). The version is AD-bound into every AEAD, so the
/// index decrypt path keys its plaintext decoding off the stored version.
pub const FORMAT_VERSION: u8 = 0x02;

/// The previous vault format version, still accepted on read for backward
/// compatibility. Its sealed index is unpadded raw postcard (`architecture.md`
/// §4.10: "mismatch aborts loudly" applies to *unknown* versions only — a known
/// prior version is read with its own rules).
const FORMAT_VERSION_LEGACY_V1: u8 = 0x01;

/// `kdf_algorithm_id` for Argon2id (`architecture.md` §4.7).
pub const KDF_ALGORITHM_ARGON2ID: u8 = 0x00;

/// The fixed probe plaintext. Decrypting `probe_ct` under the correct
/// `K_master` and probe AD must recover exactly these 16 bytes
/// (`architecture.md` §4.3 step 7).
pub const PROBE_PLAINTEXT: &[u8; 16] = b"PASSMAN_VAULT_v0";

/// Domain-separation tag appended to the probe associated data.
const PROBE_AD_TAG: &[u8] = b"probe-v0";

/// Nonce length (XChaCha20-Poly1305), re-exported size for header fields.
const NONCE_LEN: usize = aead::NONCE_LEN;

/// Length of the encrypted probe (`16-byte payload + 16-byte tag`).
const PROBE_CT_LEN: usize = 32;

/// Length of the vault salt.
const SALT_LEN: usize = 32;

/// Plaintext vault metadata (`architecture.md` §4.7).
///
/// Timestamps are Unix seconds. `last_export_at` is present only when an export
/// has occurred; its on-disk encoding is a present-flag byte followed by an
/// `i64-LE` (the value is `0` when absent).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VaultMetadata {
    /// Unix seconds of the last master-password change.
    pub last_password_change: i64,
    /// Unix seconds of the last recovery export, if any.
    pub last_export_at: Option<i64>,
}

impl VaultMetadata {
    /// Metadata for a freshly-created vault: password just set, never exported.
    #[must_use]
    pub fn new(last_password_change: i64) -> Self {
        Self {
            last_password_change,
            last_export_at: None,
        }
    }
}

/// One on-disk per-entry envelope (`architecture.md` §4.7).
///
/// `ct_len` is the on-disk (padded) ciphertext+tag length; the true plaintext
/// length is recovered from inside the authenticated plaintext after decryption
/// (see [`crate::record`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntryEnvelope {
    /// Identity of the entry this envelope holds.
    pub id: EntryId,
    /// Fresh per-encryption 192-bit nonce.
    pub nonce: [u8; NONCE_LEN],
    /// On-disk padded ciphertext+tag length (equals `ciphertext_and_tag.len()`).
    pub ct_len: u32,
    /// XChaCha20-Poly1305 ciphertext with the appended 16-byte tag.
    pub ciphertext_and_tag: Vec<u8>,
}

/// A parsed vault.
///
/// Holds every field of the §4.7 layout. Construction goes through
/// [`Vault::create`] (which builds the probe and an empty sealed index) or
/// [`Vault::from_bytes`] (parsing). Mutation methods keep the on-disk form
/// internally consistent: the sealed index is re-sealed and the index↔envelope
/// id sets stay equal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Vault {
    format_version: u8,
    kdf_algorithm_id: u8,
    kdf_params: KdfParams,
    // Named `salt` (not `vault_salt`) to avoid the struct-name prefix; the
    // public accessor and the §4.7 wire field are still `vault_salt`.
    salt: [u8; SALT_LEN],
    probe_nonce: [u8; NONCE_LEN],
    probe_ct: [u8; PROBE_CT_LEN],
    k_hsm_wrap_blob: Vec<u8>,
    totp_seed_wrap_blob: Vec<u8>,
    rl_counter: u64,
    rl_last_failure: i64,
    metadata: VaultMetadata,
    sealed_index_nonce: [u8; NONCE_LEN],
    sealed_index_ct: Vec<u8>,
    envelopes: Vec<EntryEnvelope>,
}

impl Vault {
    // ----- Accessors (non-secret header fields are public; secrets are not) ---

    /// The format version byte.
    #[must_use]
    pub fn format_version(&self) -> u8 {
        self.format_version
    }

    /// The KDF algorithm id byte.
    #[must_use]
    pub fn kdf_algorithm_id(&self) -> u8 {
        self.kdf_algorithm_id
    }

    /// The Argon2id parameters from the header.
    #[must_use]
    pub fn kdf_params(&self) -> KdfParams {
        self.kdf_params
    }

    /// The 32-byte vault salt.
    #[must_use]
    pub fn vault_salt(&self) -> &[u8; SALT_LEN] {
        &self.salt
    }

    /// The opaque `VaultKey` HSM wrap blob.
    #[must_use]
    pub fn k_hsm_wrap_blob(&self) -> &[u8] {
        &self.k_hsm_wrap_blob
    }

    /// The opaque `TotpSeed` HSM wrap blob.
    #[must_use]
    pub fn totp_seed_wrap_blob(&self) -> &[u8] {
        &self.totp_seed_wrap_blob
    }

    /// The advisory rate-limit counter (`architecture.md` §4.9; not a security
    /// boundary).
    #[must_use]
    pub fn rl_counter(&self) -> u64 {
        self.rl_counter
    }

    /// The advisory last-failure timestamp (Unix seconds; `0` = none).
    #[must_use]
    pub fn rl_last_failure(&self) -> i64 {
        self.rl_last_failure
    }

    /// The plaintext metadata.
    #[must_use]
    pub fn metadata(&self) -> VaultMetadata {
        self.metadata
    }

    /// The per-entry envelopes (read-only; mutate via the mutation API).
    #[must_use]
    pub fn envelopes(&self) -> &[EntryEnvelope] {
        &self.envelopes
    }

    /// Number of entries (== envelope count == sealed-index row count).
    #[must_use]
    pub fn len(&self) -> usize {
        self.envelopes.len()
    }

    /// Whether the vault holds no entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.envelopes.is_empty()
    }

    // ----- Construction --------------------------------------------------------

    /// Create a fresh, empty vault.
    ///
    /// Builds `probe_ct` (so a later [`Vault::verify_probe`] under the same
    /// `K_master` succeeds) and seals an empty index. The caller supplies the
    /// KDF parameters, salt, and the two opaque HSM wrap blobs; `K_master` is
    /// derived by the caller (`architecture.md` §4.2) and passed in.
    ///
    /// The advisory rate-limit fields start at zero.
    ///
    /// # Errors
    ///
    /// - [`VaultError::BlobTooLarge`] if either HSM wrap blob exceeds the `u16`
    ///   on-disk length bound ([`MAX_HSM_BLOB_LEN`]).
    /// - [`VaultError::Crypto`] if the probe or index AEAD encryption fails (does
    ///   not happen for well-formed inputs).
    pub fn create(
        kdf_params: KdfParams,
        vault_salt: [u8; SALT_LEN],
        k_hsm_wrap_blob: Vec<u8>,
        totp_seed_wrap_blob: Vec<u8>,
        metadata: VaultMetadata,
        k_master: &MasterKey,
    ) -> Result<Self, VaultError> {
        // Enforce the u16 on-disk bound up front so `to_bytes` can never clamp a
        // blob length and emit a corrupt, unparseable vault.
        check_blob_len(&k_hsm_wrap_blob, "k_hsm_wrap_blob")?;
        check_blob_len(&totp_seed_wrap_blob, "totp_seed_wrap_blob")?;

        let probe_nonce = random_nonce();
        let probe_ad = probe_associated_data(
            FORMAT_VERSION,
            KDF_ALGORITHM_ARGON2ID,
            &kdf_params,
            &vault_salt,
        );
        let probe_ct_vec = aead::encrypt(k_master, &probe_nonce, &probe_ad, PROBE_PLAINTEXT)?;
        // The probe plaintext is a fixed 16 bytes; with the 16-byte tag the
        // ciphertext is exactly 32. This is unreachable for the real cipher, but
        // is surfaced rather than unwrapped to honour the no-panic contract.
        let probe_ct =
            into_fixed::<PROBE_CT_LEN>(&probe_ct_vec).ok_or(VaultError::MalformedRecord {
                reason: "probe ciphertext was not 32 bytes",
            })?;

        let (sealed_index_nonce, sealed_index_ct) =
            seal_index(&Index::new(), FORMAT_VERSION, k_master)?;

        Ok(Self {
            format_version: FORMAT_VERSION,
            kdf_algorithm_id: KDF_ALGORITHM_ARGON2ID,
            kdf_params,
            salt: vault_salt,
            probe_nonce,
            probe_ct,
            k_hsm_wrap_blob,
            totp_seed_wrap_blob,
            rl_counter: 0,
            rl_last_failure: 0,
            metadata,
            sealed_index_nonce,
            sealed_index_ct,
            envelopes: Vec::new(),
        })
    }

    // ----- Crypto operations ---------------------------------------------------

    /// Verify the probe under `k_master`.
    ///
    /// Decrypts `probe_ct` with `K_master` and the probe associated data (which
    /// binds the version, KDF id, KDF params, and salt — `architecture.md`
    /// §4.3/§4.10), then constant-time-compares the recovered plaintext to
    /// [`PROBE_PLAINTEXT`]. A wrong key or any tampered AD-bound header field
    /// makes the AEAD fail; an authenticated-but-wrong plaintext (not reachable
    /// with a correct cipher) fails the constant-time compare.
    ///
    /// # Errors
    ///
    /// [`VaultError::Crypto`] on AEAD authentication failure (wrong creds or a
    /// tampered probe-AD-bound field).
    pub fn verify_probe(&self, k_master: &MasterKey) -> Result<(), VaultError> {
        let ad = probe_associated_data(
            self.format_version,
            self.kdf_algorithm_id,
            &self.kdf_params,
            &self.salt,
        );
        let recovered = aead::decrypt(k_master, &self.probe_nonce, &ad, &self.probe_ct)
            .map_err(auth_failure)?;
        if ct_eq(recovered.expose(), PROBE_PLAINTEXT) {
            Ok(())
        } else {
            // Authenticated but not the expected constant — treat as an auth
            // failure (detail-free), never reveal the recovered bytes.
            Err(VaultError::Crypto(passman_crypto::CryptoError::AeadAuth))
        }
    }

    /// Decrypt and return the sealed index, enforcing the index↔envelope-set
    /// check.
    ///
    /// Derives `K_index = HKDF-Expand(K_master, "index-v0")`, AEAD-decrypts the
    /// sealed index with `ad = [format_version]`, deserializes the
    /// `Vec<IndexEntry>`, then requires that the set of index ids exactly equals
    /// the set of envelope ids (`architecture.md` §4.3 step 9 / §4.5). Any
    /// missing, extra, or duplicate id fails closed with
    /// [`VaultError::IndexMismatch`].
    ///
    /// # Errors
    ///
    /// - [`VaultError::Crypto`] if the index AEAD fails (wrong key / tamper).
    /// - [`VaultError::MalformedRecord`] if the decrypted index is not valid
    ///   postcard.
    /// - [`VaultError::IndexMismatch`] if the id sets differ.
    pub fn open_index(&self, k_master: &MasterKey) -> Result<Index, VaultError> {
        let index = self.decrypt_index(k_master)?;
        self.check_index_envelope_sets(&index)?;
        Ok(index)
    }

    /// Decrypt a single entry by id.
    ///
    /// Derives `K_entry(id) = HKDF-Expand(K_master, "entry-v0:" ‖ id)`,
    /// AEAD-decrypts the envelope with `ad = format_version ‖ id`, then strips
    /// the authenticated bucket padding via the in-plaintext true-length prefix
    /// and parses the four secret fields into a zeroizing [`EntryRecord`]
    /// (`architecture.md` §4.4).
    ///
    /// Key-from-id plus id-in-AD binds the envelope to exactly one id, so an
    /// envelope relocated to another id's slot fails authentication.
    ///
    /// # Errors
    ///
    /// - [`VaultError::EntryNotFound`] if no envelope has `id`.
    /// - [`VaultError::Crypto`] on AEAD authentication failure.
    /// - [`VaultError::MalformedRecord`] if the (authenticated) plaintext is
    ///   structurally invalid.
    pub fn decrypt_entry(
        &self,
        k_master: &MasterKey,
        id: &EntryId,
    ) -> Result<EntryRecord, VaultError> {
        let envelope = self
            .envelopes
            .iter()
            .find(|e| &e.id == id)
            .ok_or(VaultError::EntryNotFound)?;

        let key = EntryKey::new(hkdf_expand(k_master, &entry_info(id)));
        let ad = entry_associated_data(self.format_version, id);
        let plaintext = aead::decrypt(&key, &envelope.nonce, &ad, &envelope.ciphertext_and_tag)
            .map_err(auth_failure)?;
        EntryRecord::decode(&plaintext)
    }

    // ----- Mutation API (caller serializes + writes bytes afterwards) ----------

    /// Insert a new entry or update the existing entry with the same id.
    ///
    /// Encrypts `record` under a fresh nonce and `K_entry(id)`, replaces (or
    /// appends) the matching envelope, then rebuilds and re-seals the index so
    /// the index↔envelope id sets stay equal. The on-disk form remains
    /// consistent after this returns.
    ///
    /// # Errors
    ///
    /// [`VaultError::Crypto`] if encryption fails (not expected for valid
    /// inputs).
    pub fn add_or_update_entry(
        &mut self,
        k_master: &MasterKey,
        id: EntryId,
        label: String,
        policy: EntryPolicy,
        record: &EntryRecord,
    ) -> Result<(), VaultError> {
        let envelope = encrypt_entry(k_master, self.format_version, id, record)?;

        if let Some(slot) = self.envelopes.iter_mut().find(|e| e.id == id) {
            *slot = envelope;
        } else {
            self.envelopes.push(envelope);
        }

        // Re-seal the index with the updated row.
        let mut index = self.decrypt_index(k_master)?;
        index.upsert(IndexEntry::new(id, label, policy));
        self.reseal_index(&index, k_master)
    }

    /// Remove the entry with `id` (envelope and index row), failing closed if
    /// no such entry exists.
    ///
    /// Rebuilds and re-seals the index so the on-disk form stays consistent.
    ///
    /// # Errors
    ///
    /// - [`VaultError::EntryNotFound`] if no entry has `id`.
    /// - [`VaultError::Crypto`] / [`VaultError::MalformedRecord`] if re-sealing
    ///   the index fails.
    pub fn remove_entry(&mut self, k_master: &MasterKey, id: &EntryId) -> Result<(), VaultError> {
        let before = self.envelopes.len();
        self.envelopes.retain(|e| &e.id != id);
        if self.envelopes.len() == before {
            return Err(VaultError::EntryNotFound);
        }

        let mut index = self.decrypt_index(k_master)?;
        index.remove(id);
        self.reseal_index(&index, k_master)
    }

    /// Replace the plaintext metadata.
    pub fn set_metadata(&mut self, metadata: VaultMetadata) {
        self.metadata = metadata;
    }

    /// Set the advisory rate-limit bytes (`architecture.md` §4.9). These are
    /// plaintext and explicitly not a security boundary.
    pub fn set_rate_limit(&mut self, counter: u64, last_failure: i64) {
        self.rl_counter = counter;
        self.rl_last_failure = last_failure;
    }

    /// Replace the two opaque HSM wrap blobs (e.g. after HSM re-enrollment,
    /// `architecture.md` §6.6). The blobs are opaque to this crate.
    ///
    /// # Errors
    ///
    /// [`VaultError::BlobTooLarge`] if either blob exceeds the `u16` on-disk
    /// length bound ([`MAX_HSM_BLOB_LEN`]); the vault is left unchanged in that
    /// case (both blobs are validated before either is stored).
    pub fn set_hsm_blobs(
        &mut self,
        k_hsm_wrap_blob: Vec<u8>,
        totp_seed_wrap_blob: Vec<u8>,
    ) -> Result<(), VaultError> {
        check_blob_len(&k_hsm_wrap_blob, "k_hsm_wrap_blob")?;
        check_blob_len(&totp_seed_wrap_blob, "totp_seed_wrap_blob")?;
        self.k_hsm_wrap_blob = k_hsm_wrap_blob;
        self.totp_seed_wrap_blob = totp_seed_wrap_blob;
        Ok(())
    }

    // ----- Internal index helpers ---------------------------------------------

    /// Decrypt the sealed index without the envelope-set check (internal: the
    /// mutation path needs the rows but rebuilds the set itself).
    ///
    /// The decrypted plaintext encoding depends on the stored format version,
    /// which is bound into the AEAD AD: a `0x02` index is bucket-padded
    /// (`true_len(u32-LE) ‖ postcard ‖ zero-pad`) and the padding is stripped
    /// here; a legacy `0x01` index is raw postcard and parsed directly. The
    /// padding strip rejects a `true_len` exceeding the (authenticated) buffer
    /// (it cannot be reached without an AEAD-tag forgery, but is surfaced rather
    /// than trusted).
    fn decrypt_index(&self, k_master: &MasterKey) -> Result<Index, VaultError> {
        let key = hkdf_expand(k_master, INDEX_INFO);
        let ad = [self.format_version];
        let plaintext = aead::decrypt(&key, &self.sealed_index_nonce, &ad, &self.sealed_index_ct)
            .map_err(auth_failure)?;
        let postcard_bytes = if self.format_version == FORMAT_VERSION_LEGACY_V1 {
            // Legacy: the plaintext is raw postcard with no padding.
            plaintext.expose()
        } else {
            // Current: strip the authenticated bucket padding via the in-plaintext
            // true-length prefix.
            strip_index_padding(plaintext.expose())?
        };
        let rows: Vec<IndexEntry> =
            postcard::from_bytes(postcard_bytes).map_err(|_| VaultError::MalformedRecord {
                reason: "sealed index is not valid postcard",
            })?;
        Ok(Index::from_vec(rows))
    }

    /// Re-encrypt `index` under a fresh nonce and store it, using this vault's
    /// own stored `format_version` so a loaded legacy v1 vault is re-sealed under
    /// v1 rules (raw postcard, `ad=[0x01]`) rather than v2 — which would corrupt
    /// its index on the next open (`architecture.md` §4.10).
    fn reseal_index(&mut self, index: &Index, k_master: &MasterKey) -> Result<(), VaultError> {
        let (nonce, ct) = seal_index(index, self.format_version, k_master)?;
        self.sealed_index_nonce = nonce;
        self.sealed_index_ct = ct;
        Ok(())
    }

    /// Enforce that the index id set exactly equals the envelope id set
    /// (missing/extra/duplicate → mismatch). Uses sorted vectors so duplicates
    /// on either side are detected and the comparison is allocation-bounded by
    /// the entry count.
    fn check_index_envelope_sets(&self, index: &Index) -> Result<(), VaultError> {
        let mut index_ids: Vec<EntryId> = index.entries().iter().map(|e| e.id).collect();
        let mut env_ids: Vec<EntryId> = self.envelopes.iter().map(|e| e.id).collect();

        if index_ids.len() != env_ids.len() {
            return Err(VaultError::IndexMismatch);
        }
        index_ids.sort_unstable();
        env_ids.sort_unstable();

        // Detect duplicates within the index (a duplicate would otherwise mask a
        // missing id once lengths match). Envelope duplicates are likewise
        // caught: a duplicate envelope id makes the sorted sequences differ from
        // a duplicate-free index, or trips the dup check here.
        for window in index_ids.windows(2) {
            if window[0] == window[1] {
                return Err(VaultError::IndexMismatch);
            }
        }
        for window in env_ids.windows(2) {
            if window[0] == window[1] {
                return Err(VaultError::IndexMismatch);
            }
        }
        if index_ids != env_ids {
            return Err(VaultError::IndexMismatch);
        }
        Ok(())
    }

    // ----- Binary (de)serialization (§4.7) ------------------------------------

    /// Serialize the vault to its on-disk byte layout (`architecture.md` §4.7).
    ///
    /// Round-trips with [`Vault::from_bytes`]. Performs no I/O.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(self.format_version);
        out.push(self.kdf_algorithm_id);
        out.extend_from_slice(&self.kdf_params.m_kib.to_le_bytes());
        out.extend_from_slice(&self.kdf_params.t.to_le_bytes());
        out.push(self.kdf_params.p);
        out.extend_from_slice(&self.salt);
        out.extend_from_slice(&self.probe_nonce);
        out.extend_from_slice(&self.probe_ct);

        push_u16_prefixed(&mut out, &self.k_hsm_wrap_blob);
        push_u16_prefixed(&mut out, &self.totp_seed_wrap_blob);

        out.extend_from_slice(&self.rl_counter.to_le_bytes());
        out.extend_from_slice(&self.rl_last_failure.to_le_bytes());
        out.extend_from_slice(&self.metadata.last_password_change.to_le_bytes());

        // present-flag byte (0x01/0x00) then the i64-LE timestamp (0 when absent).
        let (present, export_ts) = match self.metadata.last_export_at {
            Some(ts) => (0x01u8, ts),
            None => (0x00u8, 0i64),
        };
        out.push(present);
        out.extend_from_slice(&export_ts.to_le_bytes());

        out.extend_from_slice(&self.sealed_index_nonce);
        push_u32_prefixed(&mut out, &self.sealed_index_ct);

        // entries_count then the envelopes.
        let count = u32::try_from(self.envelopes.len()).unwrap_or(u32::MAX);
        out.extend_from_slice(&count.to_le_bytes());
        for env in &self.envelopes {
            out.extend_from_slice(env.id.as_bytes());
            out.extend_from_slice(&env.nonce);
            // ct_len mirrors the actual ciphertext length on disk.
            let ct_len = u32::try_from(env.ciphertext_and_tag.len()).unwrap_or(u32::MAX);
            out.extend_from_slice(&ct_len.to_le_bytes());
            out.extend_from_slice(&env.ciphertext_and_tag);
        }
        out
    }

    /// Parse a vault from its on-disk byte layout (`architecture.md` §4.7).
    ///
    /// This is the crate's fuzz target: it consumes attacker-controlled bytes.
    /// Every length prefix is validated against the remaining buffer before any
    /// slice or allocation (via [`Reader`]); truncation, an oversized length, a
    /// bad version/flag, or trailing bytes return a [`VaultError`] and never
    /// panic, never index out of bounds, never over-allocate, and never
    /// integer-overflow on offset math.
    ///
    /// Decryption is *not* performed here (that needs `K_master`); this is a
    /// pure structural parse.
    ///
    /// # Errors
    ///
    /// A [`VaultError`] describing the structural failure (kind + offset only,
    /// never file content). See [`VaultError`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, VaultError> {
        let mut r = Reader::new(bytes);

        let format_version = r.read_u8("format_version")?;
        // Accept the current version and the one prior version. The stored
        // version drives the sealed-index decode (padded vs unpadded) in
        // `decrypt_index`; both are AD-bound so a tampered version byte fails
        // the AEAD on the probe/index/entry paths.
        if format_version != FORMAT_VERSION && format_version != FORMAT_VERSION_LEGACY_V1 {
            return Err(VaultError::UnsupportedVersion {
                got: format_version,
                expected: FORMAT_VERSION,
            });
        }
        let kdf_algorithm_id = r.read_u8("kdf_algorithm_id")?;
        if kdf_algorithm_id != KDF_ALGORITHM_ARGON2ID {
            return Err(VaultError::UnsupportedKdfAlgorithm {
                got: kdf_algorithm_id,
            });
        }

        // KdfParams: reuse crypto's canonical 9-byte decoder so the encoding
        // stays in lock-step with the header it is bound into.
        let kdf_bytes: [u8; KDF_PARAMS_LEN] = r.take_array("kdf_params")?;
        let kdf_params = KdfParams::from_bytes(kdf_bytes);

        let vault_salt: [u8; SALT_LEN] = r.take_array("vault_salt")?;
        let probe_nonce: [u8; NONCE_LEN] = r.take_array("probe_nonce")?;
        let probe_ct: [u8; PROBE_CT_LEN] = r.take_array("probe_ct")?;

        let k_hsm_wrap_blob = r.read_u16_prefixed_vec("k_hsm_wrap_blob")?;
        let totp_seed_wrap_blob = r.read_u16_prefixed_vec("totp_seed_wrap_blob")?;

        let rl_counter = r.read_u64_le("rl_counter")?;
        let rl_last_failure = r.read_i64_le("rl_last_failure")?;
        let last_password_change = r.read_i64_le("meta.last_password_change")?;

        let export_present = r.read_u8("meta.last_export_present")?;
        let last_export_raw = r.read_i64_le("meta.last_export_at")?;
        let last_export_at = match export_present {
            0x00 => None,
            0x01 => Some(last_export_raw),
            other => {
                return Err(VaultError::InvalidFlag {
                    field: "meta.last_export_present",
                    got: other,
                })
            }
        };
        let metadata = VaultMetadata {
            last_password_change,
            last_export_at,
        };

        let sealed_index_nonce: [u8; NONCE_LEN] = r.take_array("sealed_index_nonce")?;
        let sealed_index_ct = r.read_u32_prefixed_vec("sealed_index_ct")?;

        let entries_count = r.read_u32_le("entries_count")?;
        // Do NOT pre-allocate `entries_count` capacity: it is attacker-supplied.
        // Push as each envelope is fully read and bounds-checked; an inflated
        // count simply runs out of buffer and errors on the next envelope.
        let mut envelopes: Vec<EntryEnvelope> = Vec::new();
        for _ in 0..entries_count {
            let id_bytes: [u8; ENTRY_ID_LEN] = r.take_array("entry.id")?;
            let nonce: [u8; NONCE_LEN] = r.take_array("entry.nonce")?;
            let ct_len = r.read_u32_le("entry.ct_len")?;
            // The body length is validated by `take` before allocation.
            let ciphertext_and_tag = r.take(ct_len as usize, "entry.ciphertext")?.to_vec();
            envelopes.push(EntryEnvelope {
                id: EntryId::from_bytes(id_bytes),
                nonce,
                ct_len,
                ciphertext_and_tag,
            });
        }

        // Trailing bytes after the last envelope are a hard format error.
        r.expect_eof()?;

        Ok(Self {
            format_version,
            kdf_algorithm_id,
            kdf_params,
            salt: vault_salt,
            probe_nonce,
            probe_ct,
            k_hsm_wrap_blob,
            totp_seed_wrap_blob,
            rl_counter,
            rl_last_failure,
            metadata,
            sealed_index_nonce,
            sealed_index_ct,
            envelopes,
        })
    }
}

// ----- Free helpers -----------------------------------------------------------

/// Build the probe associated data:
/// `format_version ‖ kdf_algorithm_id ‖ KdfParams.to_bytes() ‖ vault_salt ‖
/// "probe-v0"` (`architecture.md` §4.3 step 7).
fn probe_associated_data(
    format_version: u8,
    kdf_algorithm_id: u8,
    kdf_params: &KdfParams,
    vault_salt: &[u8; SALT_LEN],
) -> Vec<u8> {
    let mut ad = Vec::with_capacity(2 + KDF_PARAMS_LEN + SALT_LEN + PROBE_AD_TAG.len());
    ad.push(format_version);
    ad.push(kdf_algorithm_id);
    ad.extend_from_slice(&kdf_params.to_bytes());
    ad.extend_from_slice(vault_salt);
    ad.extend_from_slice(PROBE_AD_TAG);
    ad
}

/// Build the per-entry associated data: `format_version ‖ id`
/// (`architecture.md` §4.4).
fn entry_associated_data(format_version: u8, id: &EntryId) -> [u8; 1 + ENTRY_ID_LEN] {
    let mut ad = [0u8; 1 + ENTRY_ID_LEN];
    ad[0] = format_version;
    ad[1..].copy_from_slice(id.as_bytes());
    ad
}

/// Index padding bucket. The sealed index is bucket-padded exactly as the
/// per-entry envelopes are (see [`crate::record::BUCKET`]); reusing that
/// constant keeps both quantizations identical, so the sealed-index ciphertext
/// length reveals only a 256-byte size class instead of the exact sum of
/// label/policy byte lengths (threat #18 / §4.5).
const INDEX_BUCKET: usize = crate::record::BUCKET;

/// Seal an index under `format_version`: postcard-serialize the rows, wrap them
/// in the version-appropriate authenticated-plaintext encoding, then AEAD-encrypt
/// under `K_index` with `ad = [format_version]` and a fresh nonce. Returns
/// `(nonce, ct)`.
///
/// The plaintext encoding is version-specific and MUST match the vault's own
/// stored `format_version`:
/// - v2 (`FORMAT_VERSION`): bucket-padded `true_len(u32-LE) ‖ postcard ‖
///   zero-pad` to an [`INDEX_BUCKET`] multiple. `true_len` lives inside the AEAD,
///   so the tag covers it and the padding is authenticated; the on-disk
///   `sealed_index_ct_len` is therefore a bucket-quantized size class.
/// - v1 (`FORMAT_VERSION_LEGACY_V1`): raw, unpadded postcard.
///
/// Sealing a loaded v1 vault under the v2 rules (or vice versa) would make
/// [`Vault::decrypt_index`] fail on the next open — the AD-bound version and the
/// padding rule must agree — so callers pass the vault's stored version, not the
/// build's `FORMAT_VERSION`.
fn seal_index(
    index: &Index,
    format_version: u8,
    k_master: &MasterKey,
) -> Result<([u8; NONCE_LEN], Vec<u8>), VaultError> {
    let key = hkdf_expand(k_master, INDEX_INFO);
    let postcard_bytes =
        postcard::to_stdvec(index.as_rows()).map_err(|_| VaultError::MalformedRecord {
            reason: "failed to serialize sealed index",
        })?;
    let plaintext = if format_version == FORMAT_VERSION_LEGACY_V1 {
        postcard_bytes
    } else {
        pad_index_plaintext(&postcard_bytes)
    };
    let nonce = random_nonce();
    let ad = [format_version];
    let ct = aead::encrypt(&key, &nonce, &ad, &plaintext)?;
    Ok((nonce, ct))
}

/// Wrap index postcard bytes in the v2 padded authenticated-plaintext encoding:
/// `true_len(u32-LE) ‖ postcard ‖ zero-pad` up to an [`INDEX_BUCKET`] multiple.
///
/// Mirrors [`crate::record::EntryRecord::encode_padded`]; a `true_len` larger
/// than `u32::MAX` (unreachable for any realistic index) is clamped in the
/// prefix rather than truncating the data — the postcard bytes are still copied
/// in full and the strip-side bound is the buffer length, not the prefix.
fn pad_index_plaintext(postcard_bytes: &[u8]) -> Vec<u8> {
    let true_len = u32::try_from(postcard_bytes.len()).unwrap_or(u32::MAX);
    let unpadded = 4 + postcard_bytes.len();
    let padded = unpadded.div_ceil(INDEX_BUCKET) * INDEX_BUCKET;
    let mut buf = vec![0u8; padded];
    buf[0..4].copy_from_slice(&true_len.to_le_bytes());
    buf[4..4 + postcard_bytes.len()].copy_from_slice(postcard_bytes);
    // `buf[unpadded..padded]` stays zero (the padding).
    buf
}

/// Strip the v2 index padding: read the `true_len(u32-LE)` prefix and return the
/// `true_len` postcard bytes that follow, rejecting a length that overruns the
/// (de-padded) plaintext.
///
/// The plaintext is already AEAD-authenticated when this runs, so an
/// out-of-range `true_len` implies a logic/version mismatch rather than
/// attacker input; it is surfaced as [`VaultError::MalformedRecord`], never
/// panicked. Mirrors the bound check in [`crate::record::EntryRecord::decode`].
fn strip_index_padding(plaintext: &[u8]) -> Result<&[u8], VaultError> {
    if plaintext.len() < 4 {
        return Err(VaultError::MalformedRecord {
            reason: "sealed index missing true-length prefix",
        });
    }
    let true_len = u32::from_le_bytes([plaintext[0], plaintext[1], plaintext[2], plaintext[3]]);
    let end = 4usize
        .checked_add(true_len as usize)
        .ok_or(VaultError::MalformedRecord {
            reason: "sealed index length overflows",
        })?;
    if end > plaintext.len() {
        return Err(VaultError::MalformedRecord {
            reason: "sealed index length exceeds plaintext",
        });
    }
    Ok(&plaintext[4..end])
}

/// Encrypt one entry record into an [`EntryEnvelope`] under `K_entry(id)` with a
/// fresh nonce and `ad = format_version ‖ id`. The plaintext is bucket-padded
/// before encryption (the true length is authenticated inside it).
fn encrypt_entry(
    k_master: &MasterKey,
    format_version: u8,
    id: EntryId,
    record: &EntryRecord,
) -> Result<EntryEnvelope, VaultError> {
    let key = EntryKey::new(hkdf_expand(k_master, &entry_info(&id)));
    let padded: SecretBytes = record.encode_padded();
    let nonce = random_nonce();
    let ad = entry_associated_data(format_version, &id);
    let ct = aead::encrypt(&key, &nonce, &ad, padded.expose())?;
    let ct_len = u32::try_from(ct.len()).unwrap_or(u32::MAX);
    Ok(EntryEnvelope {
        id,
        nonce,
        ct_len,
        ciphertext_and_tag: ct,
    })
}

/// The maximum length of an opaque HSM wrap blob the on-disk format can encode:
/// the §4.7 layout length-prefixes each blob with a `u16`. The §6.3 blobs sit
/// far below this in practice; the bound is enforced at every mutation boundary
/// ([`Vault::create`], [`Vault::set_hsm_blobs`]) so the `u16` length field in
/// [`Vault::to_bytes`] can never silently clamp.
const MAX_HSM_BLOB_LEN: usize = u16::MAX as usize;

/// Reject an HSM wrap blob whose length would not fit the `u16` on-disk length
/// prefix (see [`MAX_HSM_BLOB_LEN`]).
fn check_blob_len(blob: &[u8], which: &'static str) -> Result<(), VaultError> {
    if blob.len() > MAX_HSM_BLOB_LEN {
        return Err(VaultError::BlobTooLarge { which });
    }
    Ok(())
}

/// Append `blob` to `out` as `u16-LE length ‖ blob`.
///
/// A blob longer than `u16::MAX` would clamp the length field and desync the
/// stream, but that is **unreachable**: every blob entering the vault is bounded
/// by [`check_blob_len`] at construction/mutation, so the clamp here is only a
/// last-resort defensive backstop for the otherwise-impossible case.
fn push_u16_prefixed(out: &mut Vec<u8>, blob: &[u8]) {
    let len = u16::try_from(blob.len()).unwrap_or(u16::MAX);
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(blob);
}

/// Append `blob` to `out` as `u32-LE length ‖ blob`.
fn push_u32_prefixed(out: &mut Vec<u8>, blob: &[u8]) {
    let len = u32::try_from(blob.len()).unwrap_or(u32::MAX);
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(blob);
}

/// Copy a slice into an owned `[u8; N]` if its length is exactly `N`.
fn into_fixed<const N: usize>(slice: &[u8]) -> Option<[u8; N]> {
    if slice.len() == N {
        let mut out = [0u8; N];
        out.copy_from_slice(slice);
        Some(out)
    } else {
        None
    }
}

/// Fold an AEAD decrypt error into a uniformly detail-free form.
///
/// A ciphertext shorter than the tag surfaces from `aead::decrypt` as
/// [`passman_crypto::CryptoError::InvalidLength`]; everything else (wrong key,
/// tamper) is [`passman_crypto::CryptoError::AeadAuth`]. On the decrypt paths
/// the input length is attacker-controlled, so collapsing the too-short case
/// into `AeadAuth` keeps the failure detail-free — a decrypt never reveals
/// *why* it failed (`architecture.md` §4.4). Mirrors the same fold in
/// `passman_recovery::import`.
fn auth_failure(e: passman_crypto::CryptoError) -> VaultError {
    match e {
        passman_crypto::CryptoError::InvalidLength { .. } => {
            VaultError::Crypto(passman_crypto::CryptoError::AeadAuth)
        }
        other => VaultError::Crypto(other),
    }
}
