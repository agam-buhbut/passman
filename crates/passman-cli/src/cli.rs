//! Command-line surface (clap).

use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};
use passman_crypto::KdfParams;
use passman_policy::DEFAULT_LENGTH;
use passman_recovery::RecoveryPreset;
use passman_vault::EntryRecord;

/// Local-only, hardware-backed password manager.
#[derive(Debug, Parser)]
#[command(name = "passman", version, about, long_about = None)]
pub struct Cli {
    /// Use the keyring (`SecretService`) fallback when no TPM is present. The
    /// keyring has no hardware dictionary-attack lockout — weaker (§6.2).
    #[arg(long, global = true)]
    pub allow_software_hsm: bool,

    /// Override the vault directory (default: the per-platform location, §1.5).
    #[arg(long, global = true, value_name = "DIR")]
    pub vault_dir: Option<PathBuf>,

    #[command(subcommand)]
    pub command: Command,
}

/// The subcommands.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Create a new vault (prints the TOTP provisioning URI to add to your
    /// authenticator).
    Init {
        /// Argon2id cost preset for the master-key derivation.
        #[arg(long, value_enum, default_value_t = Preset::Medium)]
        preset: Preset,
    },

    /// List entry labels.
    List,

    /// Add a new entry.
    Add {
        /// The entry label (e.g. a site name).
        label: String,
        /// Generate the password instead of prompting for it.
        #[arg(long)]
        generate: bool,
        /// Generated-password length (with `--generate`).
        #[arg(long, value_name = "N")]
        length: Option<u16>,
    },

    /// Reveal or copy an entry's field.
    Get {
        /// The entry label.
        label: String,
        /// Print the field to stdout instead of copying it to the clipboard.
        #[arg(long)]
        show: bool,
        /// Which field to reveal/copy.
        #[arg(long, value_enum, default_value_t = Field::Password)]
        field: Field,
    },

    /// Remove an entry.
    Rm {
        /// The entry label.
        label: String,
    },

    /// Generate a password (no vault required).
    Gen {
        /// Length (default: the vault policy's 40).
        #[arg(long, value_name = "N")]
        length: Option<u16>,
    },

    /// Write an encrypted single-factor recovery export.
    Export {
        /// Output file path.
        file: PathBuf,
        /// Recovery Argon2id preset (Floor is the minimum the format allows).
        #[arg(long, value_enum, default_value_t = RecPreset::Floor)]
        preset: RecPreset,
    },

    /// Create a vault from a recovery export.
    Import {
        /// The recovery file to import.
        file: PathBuf,
        /// Argon2id cost preset for the new vault's master-key derivation.
        #[arg(long, value_enum, default_value_t = Preset::Medium)]
        preset: Preset,
    },

    /// Change the master password.
    Passwd {
        /// Argon2id cost preset for the new derivation.
        #[arg(long, value_enum, default_value_t = Preset::Medium)]
        preset: Preset,
    },
}

/// Argon2id cost preset (`architecture.md` §4.8).
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Preset {
    /// 256 MiB / t=4 (~0.6 s) — the floor.
    Low,
    /// 1 GiB / t=4 (~2.5 s) — the default.
    Medium,
    /// 4 GiB / t=6 (~12 s).
    High,
}

impl Preset {
    /// The [`KdfParams`] for this preset.
    #[must_use]
    pub fn params(self) -> KdfParams {
        match self {
            Self::Low => KdfParams::LOW,
            Self::Medium => KdfParams::MEDIUM,
            Self::High => KdfParams::HIGH,
        }
    }
}

/// Recovery export Argon2id preset (`architecture.md` §7.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum RecPreset {
    /// 1 GiB / t=4 — the minimum the format permits.
    Floor,
    /// 4 GiB / t=8 — the default.
    Default,
    /// 8 GiB / t=12.
    Paranoid,
}

impl From<RecPreset> for RecoveryPreset {
    fn from(p: RecPreset) -> Self {
        match p {
            RecPreset::Floor => RecoveryPreset::Floor,
            RecPreset::Default => RecoveryPreset::Default,
            RecPreset::Paranoid => RecoveryPreset::Paranoid,
        }
    }
}

/// Which entry field to reveal/copy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Field {
    /// The username.
    Username,
    /// The password (default).
    Password,
    /// The URL.
    Url,
    /// The free-form notes.
    Notes,
}

impl From<Field> for passman_core::RevealField {
    fn from(f: Field) -> Self {
        match f {
            Field::Username => passman_core::RevealField::Username,
            Field::Password => passman_core::RevealField::Password,
            Field::Url => passman_core::RevealField::Url,
            Field::Notes => passman_core::RevealField::Notes,
        }
    }
}

/// Default generated-password length when `--length` is omitted (the §8.6 vault
/// default).
#[must_use]
pub fn default_length() -> u16 {
    DEFAULT_LENGTH
}

/// Read the four entry fields the `EntryRecord` needs. Kept here so the command
/// module and tests share one constructor.
#[must_use]
pub fn entry_record(
    username: passman_crypto::SecretString,
    password: passman_crypto::SecretString,
    url: passman_crypto::SecretString,
    notes: passman_crypto::SecretString,
) -> EntryRecord {
    EntryRecord::new(username, password, url, notes)
}
