use anyhow::Error;
use clap::{Args, Parser, Subcommand};
use std::str::FromStr;

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
    /// Try unlocking database, applies to get, store and erase only.
    /// Takes one argument in the format of [<MAX_RETRIES>[,<INTERVAL_MS>]]. Use 0 to retry indefinitely. The default interval is 1000ms.
    #[clap(long, verbatim_doc_comment)]
    pub unlock: Option<String>,
    /// Sets the level of verbosity (-v: WARNING; -vv: INFO; -vvv: DEBUG in debug builds)
    #[clap(short, parse(from_occurrences))]
    pub verbose: usize,
    #[clap(subcommand)]
    pub command: Subcommands,
}

#[derive(Subcommand)]
pub enum Subcommands {
    Get(SubGetArgs),
    Totp(SubTOTPArgs),
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

/// Get credential (used by Git)
#[derive(Args)]
pub struct SubGetArgs {
    /// Try getting TOTP
    #[clap(long)]
    pub totp: bool,
    /// Do not filter out entries with advanced field 'KPH: git' set to false
    #[clap(long)]
    pub no_filter: bool,
    /// Print advanced fields
    #[clap(long)]
    pub advanced_fields: bool,
    /// Print JSON
    #[clap(long)]
    pub json: bool,
}

/// Get TOTP
#[derive(Args)]
pub struct SubTOTPArgs {
    /// Print JSON
    #[clap(long)]
    pub json: bool,
}

/// Store credential (used by Git)
#[derive(Args)]
pub struct SubStoreArgs {
    /// Do not filter out entries with advanced field 'KPH: git' set to false
    #[clap(long)]
    pub no_filter: bool,
}

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
    #[clap(verbatim_doc_comment)]
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

#[derive(Debug)]
pub struct UnlockOptions {
    pub max_retries: usize,
    pub interval: u64,
}

impl FromStr for UnlockOptions {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.is_empty() {
            return Ok(Self {
                max_retries: 0,
                interval: 1000,
            });
        }
        let options: Vec<_> = s.split(',').collect();
        let max_retries = usize::from_str(options[0])?;
        let options = if options.len() == 1 {
            Self {
                max_retries,
                interval: 1000,
            }
        } else {
            let interval = u64::from_str(options[1])?;
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
