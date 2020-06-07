use aes_gcm::aead::{generic_array::GenericArray, Aead, NewAead};
use aes_gcm::Aes256Gcm;
use anyhow::{anyhow, Result};
use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};
use serde::{Deserialize, Serialize};
use slog::*;
use std::cell::{Ref, RefCell};
use std::fs;
use std::io::prelude::*;
use std::ops::Deref;
use std::path::Path;
use std::str::FromStr;
use yubico_manager::config as yubico_config;
use yubico_manager::Yubico;

const YUBIKEY_CHALLENGE_LENGTH: usize = 64usize;
const YUBIKEY_RESPONSE_LENGTH: usize = 20usize;
const AES_KEY_LENGTH: usize = 32usize;
const AES_NONCE_LENGTH: usize = 12usize;

#[derive(Serialize, Deserialize, Default, Debug)]
pub struct Config {
    databases: Vec<Database>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub callers: Option<Vec<Caller>>,
    #[serde(default)]
    pub encryption: Vec<Encryption>,
}

impl Config {
    pub fn new() -> Self {
        Self {
            ..Default::default()
        }
    }

    pub fn read_from<T: AsRef<Path>>(config_path: T) -> Result<Self> {
        let json = fs::read_to_string(config_path.as_ref())?;
        let config: Config = serde_json::from_str(&json)?;
        Ok(config)
    }

    pub fn write_to<T: AsRef<Path>>(&self, config_path: T) -> Result<()> {
        let json = serde_json::to_string_pretty(self)?;
        let mut file = fs::File::create(config_path.as_ref())?;
        file.write_all(&json.as_bytes())?;
        Ok(())
    }

    pub fn get_databases(&self) -> Result<Vec<Database>> {
        let mut databases: Vec<_> = self.databases.clone();
        for database in &mut databases {
            if database.encrypted {
                database.key = self.base64_decrypt(database.key.as_ref())?;
                database.pkey = self.base64_decrypt(database.pkey.as_ref())?;
            }
        }
        Ok(databases)
    }

    pub fn clear_databases(&mut self) {
        self.databases.clear();
    }

    pub fn add_database(&mut self, mut database: Database) -> Result<()> {
        if database.encrypted {
            database.key = self.base64_encrypt(database.key.as_ref())?;
            database.pkey = self.base64_encrypt(database.pkey.as_ref())?;
        }
        self.databases.push(database);
        Ok(())
    }

    fn base64_decrypt(&self, data: &str) -> Result<String> {
        let (key, nonce) = self.get_encryption_key()?;
        let key = GenericArray::from_slice(key.as_ref());
        let nonce = base64::decode(nonce)?;
        let nonce = GenericArray::from_slice(nonce.as_ref());
        let aead = Aes256Gcm::new(key);

        let encrypted = base64::decode(data)?;
        let decrypted = aead
            .decrypt(nonce, encrypted.as_ref())
            .map_err(|_| anyhow!("Failed to decrypt database key"))?;
        Ok(base64::encode(&decrypted))
    }

    fn base64_encrypt(&self, data: &str) -> Result<String> {
        let (key, nonce) = self.get_encryption_key()?;
        let key = GenericArray::from_slice(key.as_ref());
        let nonce = base64::decode(nonce)?;
        let nonce = GenericArray::from_slice(nonce.as_ref());
        let aead = Aes256Gcm::new(key);

        let decrypted = base64::decode(data)?;
        let encrypted = aead
            .encrypt(nonce, decrypted.as_ref())
            .map_err(|_| anyhow!("Failed to encrypt database key"))?;
        Ok(base64::encode(&encrypted))
    }

    fn get_encryption_key(&self) -> Result<(Ref<Vec<u8>>, &str)> {
        if self.encryption.is_empty() {
            return Err(anyhow!("No encryption profile found"));
        }
        let encryption = &self.encryption[0];
        match encryption {
            Encryption::ChallengeResponse {
                slot,
                challenge,
                response,
                nonce,
            } => {
                if !response.borrow().is_empty() {
                    return Ok((response.borrow(), nonce));
                }
                let mut yubi = Yubico::new();
                let device = yubi.find_yubikey()?;
                debug!(
                    crate::LOGGER.get().unwrap(),
                    "Found YubiKey, vendor: {}, product: {}", device.vendor_id, device.product_id
                );
                let slot = if *slot == 1 {
                    yubico_config::Slot::Slot1
                } else {
                    yubico_config::Slot::Slot2
                };
                debug!(crate::LOGGER.get().unwrap(), "Using YubiKey {:?}", slot);
                let config = yubico_config::Config::default()
                    .set_vendor_id(device.vendor_id)
                    .set_product_id(device.product_id)
                    .set_variable_size(true)
                    .set_mode(yubico_config::Mode::Sha1)
                    .set_slot(slot);
                debug!(crate::LOGGER.get().unwrap(), "Challenge: {}", challenge);
                warn!(
                    crate::LOGGER.get().unwrap(),
                    "Retrieving response, tap your YubiKey if needed"
                );
                let hmac_result = yubi.challenge_response_hmac(challenge.as_bytes(), config)?;
                let hmac_response: &[u8] = hmac_result.deref();
                response.borrow_mut().extend_from_slice(hmac_response);
                let padding = [0u8; AES_KEY_LENGTH - YUBIKEY_RESPONSE_LENGTH];
                response.borrow_mut().extend_from_slice(&padding);
                Ok((response.borrow(), nonce))
            }
        }
    }
}

fn default_as_false() -> bool {
    false
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Database {
    pub id: String,
    pub key: String,
    pub pkey: String,
    #[serde(default = "default_as_false")]
    pub encrypted: bool,
    pub group: String,
    pub group_uuid: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Caller {
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gid: Option<u32>,
}

#[derive(Serialize, Deserialize, Debug)]
pub enum Encryption {
    ChallengeResponse {
        slot: u8,
        challenge: String,
        #[serde(skip)]
        response: RefCell<Vec<u8>>,
        nonce: String,
    },
}

impl FromStr for Encryption {
    type Err = anyhow::Error;

    fn from_str(profile: &str) -> Result<Self, Self::Err> {
        let profile_vec: Vec<_> = profile.split(':').collect();
        if profile_vec.is_empty() {
            return Err(anyhow!("Failed to parse encryption profile: {}", profile));
        }
        match profile_vec[0] {
            "challenge-response" => {
                let slot = if let Some(slot) = profile_vec.get(1) {
                    u8::from_str(slot)?
                } else {
                    2u8
                };
                if !(slot == 1 || slot == 2) {
                    return Err(anyhow!("Invalid YubiKey slot: {}", slot));
                }
                let mut rng = thread_rng();
                let challenge = if let Some(challenge) = profile_vec.get(2) {
                    challenge.deref().to_owned()
                } else {
                    rng.sample_iter(Alphanumeric)
                        .take(YUBIKEY_CHALLENGE_LENGTH)
                        .collect()
                };
                let mut nonce = [0u8; AES_NONCE_LENGTH];
                rng.fill(&mut nonce);
                let nonce = base64::encode(nonce);
                let response = RefCell::new(Vec::new());
                Ok(Encryption::ChallengeResponse {
                    slot,
                    challenge,
                    response,
                    nonce,
                })
            }
            _ => Err(anyhow!("Unknown encryption profile: {}", profile)),
        }
    }
}
