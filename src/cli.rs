use anyhow::anyhow;
use clap::{
    builder::{NonEmptyStringValueParser, TypedValueParser, ValueParserFactory},
    ArgAction, Args, Parser, Subcommand,
};
use std::{num, str::FromStr};

/// Helper that allows Git and shell scripts to use KeePassXC as credential store
#[derive(Parser)]
#[clap(author, version, about, long_about = None)]
#[clap(propagate_version = true)]
pub struct MainArgs {
    /// Specify configuration JSON file path
    #[clap(short, long)]
    pub config: Option<String>,
    /// Specify KeePassXC socket path (environment variable: KEEPASSXC_BROWSER_SOCKET_PATH)
    #[clap(short, long)]
    pub socket: Option<String>,
    /// Try unlocking database. Applies to get, totp, and store only.
    /// Takes one argument in the format of [<MAX_RETRIES>[,<INTERVAL_MS>]]. Use 0 to retry indefinitely. The default interval is 1000ms.
    #[clap(long, verbatim_doc_comment)]
    pub unlock: Option<UnlockOptions>,
    /// Group(s) to get credentials from
    #[clap(long)]
    pub group: Vec<String>,
    /// Get credentials from the dedicated group created by 'configure' subcommand
    #[clap(long)]
    pub git_groups: bool,
    /// Do not filter out entries with advanced field 'KPH: git' set to false
    #[clap(long)]
    pub no_filter: bool,
    /// Sets the level of verbosity (-v: WARNING; -vv: INFO; -vvv: DEBUG in debug builds)
    #[clap(short, action(ArgAction::Count))]
    pub verbose: u8,
    #[clap(subcommand)]
    pub command: Subcommands,
}

impl HasEntryFilters for MainArgs {
    fn entry_filters(&self) -> EntryFilters {
        EntryFilters {
            kph: !self.no_filter,
            groups: self.group.clone(),
            git_groups: self.git_groups,
        }
    }
}

#[derive(Subcommand)]
pub enum Subcommands {
    Get(SubGetArgs),
    Totp(SubTotpArgs),
    Store(SubStoreArgs),
    Erase(SubEraseArgs),
    Lock(SubLockArgs),
    GeneratePassword(SubGeneratePasswordArgs),
    Configure(SubConfigureArgs),
    Caller(SubCallerArgs),
    Edit(SubEditArgs),
    Encrypt(SubEncryptArgs),
    Decrypt(SubDecryptArgs),
}

impl Subcommands {
    pub fn name(&self) -> &'static str {
        match self {
            Self::Get(_) => "get",
            Self::Totp(_) => "totp",
            Self::Store(_) => "store",
            Self::Erase(_) => "erase",
            Self::Lock(_) => "lock",
            Self::GeneratePassword(_) => "generate-password",
            Self::Configure(_) => "configure",
            Self::Caller(_) => "caller",
            Self::Edit(_) => "edit",
            Self::Encrypt(_) => "encrypt",
            Self::Decrypt(_) => "decrypt",
        }
    }
}

pub trait GetOperation {
    fn get_mode(&self) -> GetMode;
    fn advanced_fields(&self) -> bool;
    fn json(&self) -> bool;
    fn raw(&self) -> bool;
}

/// Get credential (used by Git)
#[derive(Args)]
pub struct SubGetArgs {
    /// Try getting TOTP
    #[clap(long, conflicts_with = "raw")]
    pub totp: bool,
    /// Group(s) to get credentials from
    #[clap(long, conflicts_with = "raw")]
    pub group: Vec<String>,
    /// Get credentials from the dedicated group created by 'configure' subcommand
    #[clap(long, conflicts_with = "raw")]
    pub git_groups: bool,
    /// Do not filter out entries with advanced field 'KPH: git' set to false
    #[clap(long, conflicts_with = "raw")]
    pub no_filter: bool,
    /// Print advanced fields
    #[clap(long, conflicts_with = "raw")]
    pub advanced_fields: bool,
    /// Print JSON
    #[clap(long, conflicts_with = "raw")]
    pub json: bool,
    /// Show raw output from KeePassXC
    #[clap(long)]
    pub raw: bool,
}

impl HasEntryFilters for SubGetArgs {
    fn entry_filters(&self) -> EntryFilters {
        EntryFilters {
            kph: !self.no_filter,
            groups: self.group.clone(),
            git_groups: self.git_groups,
        }
    }
}

impl HasLocalEntryFilters for SubGetArgs {}

impl GetOperation for SubGetArgs {
    fn get_mode(&self) -> GetMode {
        if self.totp {
            GetMode::PasswordAndTotp
        } else {
            GetMode::PasswordOnly
        }
    }

    fn advanced_fields(&self) -> bool {
        self.advanced_fields
    }

    fn json(&self) -> bool {
        self.json
    }

    fn raw(&self) -> bool {
        self.raw
    }
}

/// Get TOTP
#[derive(Args)]
pub struct SubTotpArgs {
    /// Group(s) to get credentials from
    #[clap(long)]
    pub group: Vec<String>,
    /// Get credentials from the dedicated group created by 'configure' subcommand
    #[clap(long)]
    pub git_groups: bool,
    /// Do not filter out entries with advanced field 'KPH: git' set to false
    #[clap(long)]
    pub no_filter: bool,
    /// Print JSON
    #[clap(long, conflicts_with = "raw")]
    pub json: bool,
    /// Show raw output from KeePassXC with entry UUIDs
    #[clap(long)]
    pub raw: bool,
}

impl GetOperation for SubTotpArgs {
    fn get_mode(&self) -> GetMode {
        GetMode::TotpOnly
    }

    fn advanced_fields(&self) -> bool {
        false
    }

    fn json(&self) -> bool {
        self.json
    }

    fn raw(&self) -> bool {
        self.raw
    }
}

impl HasEntryFilters for SubTotpArgs {
    fn entry_filters(&self) -> EntryFilters {
        EntryFilters {
            kph: !self.no_filter,
            groups: self.group.clone(),
            git_groups: self.git_groups,
        }
    }
}

impl HasLocalEntryFilters for SubTotpArgs {}

/// Store credential (used by Git)
#[derive(Args)]
pub struct SubStoreArgs {
    /// Create new entries in specified group instead of the one created by 'configure' subcommand
    #[clap(long)]
    pub create_in: Option<String>,
    /// Group(s) to get credentials from
    #[clap(long)]
    pub group: Vec<String>,
    /// Get credentials from the dedicated group created by 'configure' subcommand
    #[clap(long)]
    pub git_groups: bool,
    /// Do not filter out entries with advanced field 'KPH: git' set to false
    #[clap(long)]
    pub no_filter: bool,
}

impl HasEntryFilters for SubStoreArgs {
    fn entry_filters(&self) -> EntryFilters {
        EntryFilters {
            kph: !self.no_filter,
            groups: self.group.clone(),
            git_groups: self.git_groups,
        }
    }
}

impl HasLocalEntryFilters for SubStoreArgs {}

/// [Not implemented] Erase credential (used by Git)
#[derive(Args)]
pub struct SubEraseArgs {}

/// Lock KeePassXC database
#[derive(Args)]
pub struct SubLockArgs {}

/// Generate a password
#[derive(Args)]
pub struct SubGeneratePasswordArgs {
    /// Print JSON
    #[clap(long)]
    pub json: bool,
}

/// Associate git-credential-keepassxc with KeePassXC and configure preferences
#[derive(Args)]
pub struct SubConfigureArgs {
    /// Name of group where new credentials are stored
    #[clap(long, default_value_t = String::from("Git"))]
    pub group: String,
    /// Encrypt KeePassXC database profiles.
    /// Only YubiKey challenge-response is supported at the moment (challenge-response[:SLOT[:CHALLENGE]], by default Slot 2 is used with a randomly generated challenge).
    /// Leave empty ("") to use existing encryption profile in configuration file.
    #[clap(long, verbatim_doc_comment)]
    pub encrypt: Option<String>,
}

/// Open configuration file in editor
#[derive(Args)]
pub struct SubEditArgs {}

/// Encrypt existing database and caller profile(s)
#[derive(Args)]
pub struct SubEncryptArgs {
    /// Encrypt KeePassXC database profiles.
    /// Only YubiKey challenge-response is supported at the moment (challenge-response[:SLOT[:CHALLENGE]], by default Slot 2 is used with a randomly generated challenge).
    #[clap(value_parser, verbatim_doc_comment)]
    pub encryption_profile: Option<String>,
}

/// Decrypt existing database and caller profile(s)
#[derive(Args)]
pub struct SubDecryptArgs {}

/// Limit caller process
#[derive(Args)]
pub struct SubCallerArgs {
    #[clap(subcommand)]
    pub command: CallerSubcommands,
}

#[derive(Subcommand)]
pub enum CallerSubcommands {
    Add(SubCallerAddArgs),
    Me(SubCallerMeArgs),
    Clear(SubCallerClearArgs),
}

/// Add a new allowed caller
#[derive(Args)]
pub struct SubCallerAddArgs {
    /// Absolute path of the caller executable
    #[clap(value_parser)]
    pub path: String,
    #[clap(long)]
    /// UID of the caller process (ignored under Windows)
    pub uid: Option<u32>,
    /// GID of the caller process (ignored under Windows)
    #[clap(long)]
    pub gid: Option<u32>,
    /// Additionally compare canonical caller paths during verification
    #[clap(long)]
    pub canonicalize: bool,
    /// Encrypt caller profiles.
    /// Only YubiKey challenge-response is supported at the moment (challenge-response[:SLOT[:CHALLENGE]], by default Slot 2 is used with a randomly generated challenge).
    /// Leave empty ("") to use existing encryption profile in configuration file.
    #[clap(long, verbatim_doc_comment)]
    pub encrypt: Option<String>,
}

/// Show current caller and optionally add it to allowed callers list
#[derive(Args)]
pub struct SubCallerMeArgs {
    /// Do not save UID in the caller profile
    #[clap(long)]
    pub no_uid: bool,
    /// Do not save GID in the caller profile
    #[clap(long)]
    pub no_gid: bool,
    /// Additionally compare canonical caller paths during verification
    #[clap(long)]
    pub canonicalize: bool,
    /// Encrypt caller profiles.
    /// Only YubiKey challenge-response is supported at the moment (challenge-response[:SLOT[:CHALLENGE]], by default Slot 2 is used with a randomly generated challenge).
    /// Leave empty ("") to use existing encryption profile in configuration file.
    #[clap(long, verbatim_doc_comment)]
    pub encrypt: Option<String>,
}

/// Clear the allowed callers list
#[derive(Args)]
pub struct SubCallerClearArgs {}

#[derive(Copy, Clone, Debug)]
pub struct UnlockOptions {
    pub max_retries: usize,
    pub interval: u64,
}

impl ValueParserFactory for UnlockOptions {
    type Parser = UnlockOptionsValueParser;

    fn value_parser() -> Self::Parser {
        UnlockOptionsValueParser
    }
}

#[derive(Clone, Debug)]
pub struct UnlockOptionsValueParser;

impl TypedValueParser for UnlockOptionsValueParser {
    type Value = UnlockOptions;

    fn parse_ref(
        &self,
        cmd: &clap::Command,
        arg: Option<&clap::Arg>,
        value: &std::ffi::OsStr,
    ) -> Result<Self::Value, clap::Error> {
        let inner = NonEmptyStringValueParser::new();
        let val = inner.parse_ref(cmd, arg, value)?;
        UnlockOptions::from_str(&val)
            .map_err(|e| clap::Error::raw(clap::error::ErrorKind::InvalidValue, e.to_string()))
    }
}

impl FromStr for UnlockOptions {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.is_empty() {
            return Ok(Self {
                max_retries: 0,
                interval: 1000,
            });
        }
        let error_map_func =
            |e: num::ParseIntError| anyhow!("Failed to parse --unlock option: {}\n", e);
        let options: Vec<_> = s.split(',').collect();
        let max_retries = usize::from_str(options[0]).map_err(error_map_func)?;
        let options = if options.len() == 1 {
            Self {
                max_retries,
                interval: 1000,
            }
        } else {
            let interval = u64::from_str(options[1]).map_err(error_map_func)?;
            Self {
                max_retries,
                interval,
            }
        };
        Ok(options)
    }
}

#[derive(PartialEq, Eq, Debug)]
pub enum GetMode {
    PasswordOnly,
    PasswordAndTotp,
    TotpOnly,
}

pub struct EntryFilters {
    pub kph: bool,
    pub groups: Vec<String>,
    pub git_groups: bool,
}

impl EntryFilters {
    pub fn has_non_default(&self) -> bool {
        !self.kph || !self.groups.is_empty() || self.git_groups
    }
}

impl Default for EntryFilters {
    fn default() -> Self {
        Self {
            kph: true,
            groups: vec![],
            git_groups: false,
        }
    }
}

pub trait HasEntryFilters {
    fn entry_filters(&self) -> EntryFilters;
}

pub trait HasLocalEntryFilters: HasEntryFilters {
    fn local_entry_filters(&self, main_entry_filters: EntryFilters) -> EntryFilters {
        let local_filters = self.entry_filters();
        let mut effective_groups = main_entry_filters.groups;
        effective_groups.extend_from_slice(&local_filters.groups);
        EntryFilters {
            kph: main_entry_filters.kph && local_filters.kph,
            groups: effective_groups,
            git_groups: main_entry_filters.git_groups || local_filters.git_groups,
        }
    }
}
