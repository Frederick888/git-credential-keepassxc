mod config;
mod git;
mod keepassxc;
mod utils;

use anyhow::{anyhow, Result};
use clap::{App, ArgMatches};
use config::{Config, Database};
use keepassxc::{messages::*, Group};
use once_cell::sync::OnceCell;
use slog::*;
use std::fmt;
use std::path::{Path, PathBuf};
use utils::*;

static LOGGER: OnceCell<Logger> = OnceCell::new();

#[derive(Debug)]
struct GenericError(String);
impl fmt::Display for GenericError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}
impl std::error::Error for GenericError {}

fn configure<T: AsRef<Path>>(config_path: T, args: &ArgMatches) -> Result<()> {
    // generate keys for encrypting current session
    let session_seckey = generate_secret_key();
    let session_pubkey = session_seckey.public_key();

    // temporary client id
    let (_, client_id) = generate_nonce();

    // exchange public keys
    let cpr_req = ChangePublicKeysRequest::new(&client_id, &session_pubkey);
    let cpr_resp = cpr_req.send()?;
    let host_pubkey = cpr_resp
        .get_public_key()
        .expect("Failed to retrieve host public key");

    // generate permanent client key for future authentication
    let id_seckey = generate_secret_key();
    let id_seckey_b64 = base64::encode(id_seckey.to_bytes());
    let id_pubkey = id_seckey.public_key();

    let _ = get_client_box(Some(host_pubkey), Some(session_seckey));

    let aso_req = AssociateRequest::new(&session_pubkey, &id_pubkey);
    let aso_resp = aso_req.send(&client_id)?;
    let database_id = aso_resp
        .id
        .ok_or_else(|| GenericError("Association failed".to_owned()))?;

    // try to create a new group even if it already exists, KeePassXC will do the deduplication
    let group_name = args
        .subcommand_matches("configure")
        .and_then(|m| m.value_of("group"))
        .expect("Group name not specified (there's a default one though, bug?)");
    let cng_req = CreateNewGroupRequest::new(group_name);
    let cng_resp = cng_req.send(&client_id)?;
    let group = Group::new(cng_resp.name, cng_resp.uuid);

    // read existing or create new config
    let mut config_file = if let Ok(config_file) = Config::read_from(&config_path) {
        config_file
    } else {
        Config::new()
    };

    // save new config
    info!(
        LOGGER.get().unwrap(),
        "Saving configuration to {}",
        config_path.as_ref().to_string_lossy()
    );
    config_file.databases.push(Database {
        id: database_id,
        key: id_seckey_b64,
        group: group.name,
        group_uuid: group.uuid,
        only_group: args.is_present("only-group"),
    });
    config_file.write_to(&config_path)?;

    Ok(())
}

fn real_main() -> Result<()> {
    if cfg!(unix) && !cfg!(debug_assertions) {
        prctl::set_dumpable(false)
            .or_else(|c| Err(GenericError(format!("Failed to disable dump, code: {}", c))))?;
    }

    let yaml = clap::load_yaml!("cli.yml");
    let args = App::from_yaml(yaml)
        .author(clap::crate_authors!(", "))
        .version(clap::crate_version!())
        .get_matches();

    let level =
        Level::from_usize(args.occurrences_of("verbose") as usize + 2).unwrap_or(Level::Error);
    let decorator = slog_term::TermDecorator::new().build();
    let drain = slog_term::FullFormat::new(decorator)
        .build()
        .filter_level(level)
        .fuse();
    let drain = std::sync::Mutex::new(drain).fuse();
    let logger = Logger::root(drain, o!());
    LOGGER
        .set(logger)
        .map_err(|_| GenericError("Failed to initialise logger".to_owned()))?;

    let config_path = {
        if let Some(path) = args.value_of("config") {
            PathBuf::from(path)
        } else {
            let xdg = xdg::BaseDirectories::new()?;
            xdg.place_config_file(clap::crate_name!())?
        }
    };

    let subcommand = args
        .subcommand_name()
        .ok_or_else(|| GenericError("No subcommand selected".to_owned()))?;
    match subcommand {
        "configure" => configure(config_path, &args),
        _ => Err(anyhow!(GenericError("Unrecognised subcommand".to_owned()))),
    }
}

fn main() {
    if let Err(ref e) = real_main() {
        error!(
            crate::LOGGER.get().unwrap(),
            "{}, Caused by: {}, Message: {}",
            e.root_cause(),
            e.source()
                .map(|s| s.to_string())
                .unwrap_or_else(|| "N/A".to_string()),
            e
        );
    }
}
