mod config;
mod git;
mod keepassxc;
mod utils;

use anyhow::{anyhow, Result};
use clap::{App, ArgMatches};
use config::{Config, Database};
use crypto_box::{PublicKey, SecretKey};
use git::GitCredentialMessage;
use keepassxc::{messages::*, Group};
use once_cell::sync::OnceCell;
use slog::*;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use utils::*;

static LOGGER: OnceCell<Logger> = OnceCell::new();

fn exchange_keys<T: AsRef<str>>(client_id: T, session_pubkey: &PublicKey) -> Result<PublicKey> {
    // exchange public keys
    let cpr_req = ChangePublicKeysRequest::new(client_id.as_ref(), session_pubkey);
    let cpr_resp = cpr_req.send()?;
    Ok(cpr_resp
        .get_public_key()
        .ok_or_else(|| anyhow!("Failed to retrieve host public key"))?)
}

fn start_session() -> Result<(String, SecretKey, PublicKey)> {
    // generate keys for encrypting current session
    let session_seckey = generate_secret_key();
    let session_pubkey = session_seckey.public_key();

    // temporary client id
    let (_, client_id) = generate_nonce();

    // exchange public keys
    let host_pubkey = exchange_keys(&client_id, &session_pubkey)?;

    // initialise crypto_box
    let _ = get_client_box(Some(&host_pubkey), Some(&session_seckey));

    Ok((client_id, session_seckey, host_pubkey))
}

fn associated_databases<T: AsRef<str>>(client_id: T, config: &Config) -> Result<Vec<&Database>> {
    let databases: Vec<_> = config
        .databases
        .iter()
        .filter(|ref db| {
            let taso_req = TestAssociateRequest::new(db.id.as_str(), db.pkey.as_str());
            if let Ok(taso_resp) = taso_req.send(client_id.as_ref()) {
                taso_resp
                    .success
                    .unwrap_or_else(|| KeePassBoolean(false))
                    .into()
            } else {
                warn!(
                    LOGGER.get().unwrap(),
                    "Failed to authenticate against database {} using stored key", &db.id
                );
                false
            }
        })
        .collect();
    if databases.is_empty() {
        Err(anyhow!(
            "No valid database associations found in configuration file"
        ))
    } else {
        Ok(databases)
    }
}

fn configure<T: AsRef<Path>>(config_path: T, args: &ArgMatches) -> Result<()> {
    // start session
    let (client_id, session_seckey, _) = start_session()?;
    let session_pubkey = session_seckey.public_key();

    // generate permanent client key for future authentication
    let id_seckey = generate_secret_key();
    let id_seckey_b64 = base64::encode(id_seckey.to_bytes());
    let id_pubkey = id_seckey.public_key();
    let id_pubkey_b64 = base64::encode(id_pubkey.as_bytes());

    let aso_req = AssociateRequest::new(&session_pubkey, &id_pubkey);
    let aso_resp = aso_req.send(&client_id)?;
    let database_id = aso_resp.id.ok_or_else(|| anyhow!("Association failed"))?;

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
        pkey: id_pubkey_b64,
        group: group.name,
        group_uuid: group.uuid,
        only_group: args.is_present("only-group"),
    });
    config_file.write_to(&config_path)?;

    Ok(())
}

fn get_logins<T: AsRef<Path>>(config_path: T, args: &ArgMatches) -> Result<()> {
    let config = Config::read_from(config_path.as_ref())?;

    // read credential request
    let git_req = {
        let mut git_req_string = String::with_capacity(256);
        io::stdin().read_to_string(&mut git_req_string)?;
        GitCredentialMessage::from_str(&git_req_string)?
    };
    let url = {
        if let Some(ref url_string) = git_req.url {
            url_string.clone()
        } else {
            if git_req.protocol.is_none() || git_req.host.is_none() {
                return Err(anyhow!(
                    "Protocol and host are both required when URL is not provided"
                ));
            }
            format!(
                "{}://{}/{}",
                git_req.protocol.clone().unwrap(),
                git_req.host.clone().unwrap(),
                git_req.path.clone().unwrap_or_else(|| "".to_owned())
            )
        }
    };

    // start session
    let (client_id, _, _) = start_session()?;

    let databases = associated_databases(&client_id, &config)?;
    let id_key_pairs: Vec<_> = databases
        .iter()
        .map(|d| (d.id.as_str(), d.pkey.as_str()))
        .collect();

    // ask KeePassXC for logins
    let gl_req = GetLoginsRequest::new(&url, None, None, &id_key_pairs[..]);
    let gl_resp = gl_req.send(&client_id)?;

    let login_entries: Vec<_> = gl_resp
        .entries
        .iter()
        .filter(|e| e.expired.is_none() || !e.expired.as_ref().unwrap().0)
        .collect();

    if login_entries.is_empty() {
        return Err(anyhow!("No matching logins found"));
    }
    if login_entries.len() > 1 {
        warn!(
            LOGGER.get().unwrap(),
            "More than 1 matching logins found, only the first one will be returned"
        );
    }

    let login = login_entries.first().unwrap();
    let mut git_resp = git_req;
    git_resp.username = Some(login.login.clone());
    git_resp.password = Some(login.password.clone());

    io::stdout().write_all(git_resp.to_string().as_bytes())?;

    Ok(())
}

fn real_main() -> Result<()> {
    if cfg!(unix) && !cfg!(debug_assertions) {
        prctl::set_dumpable(false)
            .or_else(|c| Err(anyhow!("Failed to disable dump, code: {}", c)))?;
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
        .map_err(|_| anyhow!("Failed to initialise logger"))?;

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
        .ok_or_else(|| anyhow!("No subcommand selected"))?;
    match subcommand {
        "configure" => configure(config_path, &args),
        "get" => get_logins(config_path, &args),
        _ => Err(anyhow!(anyhow!("Unrecognised subcommand"))),
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
