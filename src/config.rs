use aes_gcm::aead::generic_array::{typenum, GenericArray};
#[cfg(feature = "encryption")]
use aes_gcm::aead::{Aead, NewAead};
#[cfg(feature = "encryption")]
use aes_gcm::Aes256Gcm;
use anyhow::{anyhow, Result};
#[cfg(feature = "encryption")]
use rand::distributions::Alphanumeric;
#[cfg(feature = "encryption")]
use rand::{thread_rng, Rng};
use serde::{de, Deserialize, Serialize};
use slog::*;
use std::cell::{Ref, RefCell};
use std::fs;
use std::io::prelude::*;
use std::path::Path;
use std::str::FromStr;
#[cfg(feature = "yubikey")]
use yubico_manager::config as yubico_config;
#[cfg(feature = "yubikey")]
use yubico_manager::Yubico;

#[cfg(feature = "yubikey")]
const YUBIKEY_CHALLENGE_LENGTH: usize = 64usize;
#[cfg(feature = "yubikey")]
const YUBIKEY_RESPONSE_LENGTH: usize = 20usize;
#[cfg(feature = "encryption")]
const AES_KEY_LENGTH: usize = 32usize;
type AesKey = GenericArray<u8, typenum::U32>;
#[cfg(feature = "encryption")]
const AES_NONCE_LENGTH: usize = 12usize;
type AesNonce = GenericArray<u8, typenum::U12>;

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
            if database.encrypted() {
                database.key =
                    self.base64_decrypt(database.key.as_ref(), database.nonce.as_ref().unwrap())?;
                database.pkey =
                    self.base64_decrypt(database.pkey.as_ref(), database.nonce.as_ref().unwrap())?;
            }
        }
        Ok(databases)
    }

    pub fn clear_databases(&mut self) {
        self.databases.clear();
    }

    pub fn add_database(&mut self, mut database: Database) -> Result<()> {
        if database.encrypted() {
            database.key =
                self.base64_encrypt(database.key.as_ref(), database.nonce.as_ref().unwrap())?;
            database.pkey =
                self.base64_encrypt(database.pkey.as_ref(), database.nonce.as_ref().unwrap())?;
        }
        self.databases.push(database);
        Ok(())
    }

    #[cfg(not(feature = "encryption"))]
    fn base64_decrypt(&self, _data: &str, _nonce: &AesNonce) -> Result<String> {
        error!(
            crate::LOGGER.get().unwrap(),
            "Enable encryption to use this feature"
        );
        Err(anyhow!("Encryption is not enabled in this build"))
    }

    #[cfg(feature = "encryption")]
    fn base64_decrypt(&self, data: &str, nonce: &AesNonce) -> Result<String> {
        let key = self.get_encryption_key()?;
        let aead = Aes256Gcm::new(key.as_ref().unwrap());

        let encrypted = base64::decode(data)?;
        let decrypted = aead
            .decrypt(nonce, encrypted.as_ref())
            .map_err(|_| anyhow!("Failed to decrypt database key"))?;
        Ok(base64::encode(&decrypted))
    }

    #[cfg(not(feature = "encryption"))]
    fn base64_encrypt(&self, _data: &str, _nonce: &AesNonce) -> Result<String> {
        error!(
            crate::LOGGER.get().unwrap(),
            "Enable encryption to use this feature"
        );
        Err(anyhow!("Encryption is not enabled in this build"))
    }

    #[cfg(feature = "encryption")]
    fn base64_encrypt(&self, data: &str, nonce: &AesNonce) -> Result<String> {
        let key = self.get_encryption_key()?;
        let aead = Aes256Gcm::new(key.as_ref().unwrap());

        let decrypted = base64::decode(data)?;
        let encrypted = aead
            .encrypt(nonce, decrypted.as_ref())
            .map_err(|_| anyhow!("Failed to encrypt database key"))?;
        Ok(base64::encode(&encrypted))
    }

    #[allow(dead_code)]
    fn get_encryption_key(&self) -> Result<Ref<Option<AesKey>>> {
        if self.encryption.is_empty() {
            return Err(anyhow!("No encryption profile found"));
        }
        let encryption = &self.encryption[0];
        match encryption {
            #[cfg(not(feature = "yubikey"))]
            Encryption::ChallengeResponse {
                slot: _,
                challenge: _,
                response: _,
            } => {
                error!(
                    crate::LOGGER.get().unwrap(),
                    "Challenge-response encryption profile found however YubiKey is not enabled in this build"
                );
                Err(anyhow!("YubiKey is not enabled in this build"))
            }
            #[cfg(feature = "yubikey")]
            Encryption::ChallengeResponse {
                slot,
                challenge,
                response,
            } => {
                if response.borrow().is_some() {
                    return Ok(response.borrow());
                }
                let mut yubi = Yubico::new();
                let device = yubi.find_yubikey()?;
                let config = yubico_config::Config::default()
                    .set_vendor_id(device.vendor_id)
                    .set_product_id(device.product_id);
                debug!(
                    crate::LOGGER.get().unwrap(),
                    "Found YubiKey, vendor: {}, product: {}, serial: {}",
                    device.vendor_id,
                    device.product_id,
                    yubi.read_serial_number(config).unwrap_or_default()
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
                let mut hmac_response = vec![0u8; AES_KEY_LENGTH];
                hmac_response.splice(..YUBIKEY_RESPONSE_LENGTH, (*hmac_result).iter().cloned());
                *response.borrow_mut() = Some(AesKey::clone_from_slice(&hmac_response));
                Ok(response.borrow())
            }
        }
    }
}

#[cfg(feature = "encryption")]
fn aes_nonce() -> AesNonce {
    let mut rng = rand::thread_rng();
    let mut nonce = AesNonce::clone_from_slice(&[0u8; AES_NONCE_LENGTH]);
    rng.fill(nonce.as_mut_slice());
    nonce
}

fn opt_aes_nonce_serialize<S>(nonce: &Option<AesNonce>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    match nonce {
        Some(nonce) => {
            let nonce = base64::encode(nonce);
            serializer.serialize_str(&nonce)
        }
        None => serializer.serialize_none(),
    }
}

fn opt_aes_nonce_deserialize<'de, D>(deserializer: D) -> Result<Option<AesNonce>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let nonce: Option<&str> = de::Deserialize::deserialize(deserializer)?;
    match nonce {
        Some(nonce) => {
            let nonce = base64::decode(nonce).map_err(|_| {
                de::Error::invalid_value(de::Unexpected::Str(nonce), &"base64 encoded data")
            })?;
            Ok(Some(AesNonce::clone_from_slice(nonce.as_ref())))
        }
        None => Ok(None),
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Database {
    pub id: String,
    pub key: String,
    pub pkey: String,
    #[serde(
        default,
        serialize_with = "opt_aes_nonce_serialize",
        deserialize_with = "opt_aes_nonce_deserialize",
        skip_serializing_if = "Option::is_none"
    )]
    nonce: Option<AesNonce>,
    pub group: String,
    pub group_uuid: String,
}

impl Database {
    pub fn new(
        id: String,
        id_seckey: crypto_box::SecretKey,
        group: crate::keepassxc::Group,
        encrypted: bool,
    ) -> Result<Self> {
        if encrypted && cfg!(not(feature = "encryption")) {
            return Err(anyhow!("Encryption is not enabled in this build"));
        }
        let id_seckey_b64 = base64::encode(id_seckey.to_bytes());
        let id_pubkey = id_seckey.public_key();
        let id_pubkey_b64 = base64::encode(id_pubkey.as_bytes());
        let nonce = if encrypted {
            #[cfg(not(feature = "encryption"))]
            {
                None
            }
            #[cfg(feature = "encryption")]
            {
                Some(aes_nonce())
            }
        } else {
            None
        };
        Ok(Self {
            id,
            key: id_seckey_b64,
            pkey: id_pubkey_b64,
            nonce,
            group: group.name,
            group_uuid: group.uuid,
        })
    }

    pub fn encrypted(&self) -> bool {
        self.nonce.is_some()
    }

    #[cfg(feature = "encryption")]
    pub fn encrypt(&mut self) -> Result<()> {
        if self.nonce.is_some() {
            return Ok(());
        }
        self.nonce = Some(aes_nonce());
        Ok(())
    }

    #[cfg(not(feature = "encryption"))]
    pub fn encrypt(&mut self) -> Result<()> {
        Err(anyhow!("Encryption is not enabled in this build"))
    }

    #[cfg(feature = "encryption")]
    pub fn decrypt(&mut self) -> Result<()> {
        self.nonce = None;
        Ok(())
    }

    #[cfg(not(feature = "encryption"))]
    pub fn decrypt(&mut self) -> Result<()> {
        Err(anyhow!("Encryption is not enabled in this build"))
    }
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
        response: RefCell<Option<AesKey>>,
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
            #[cfg(not(feature = "yubikey"))]
            "challenge-response" => {
                error!(
                    crate::LOGGER.get().unwrap(),
                    "YubiKey is not enabled in this build"
                );
                Err(anyhow!("YubiKey is not enabled in this build"))
            }
            #[cfg(feature = "yubikey")]
            "challenge-response" => {
                let slot = if let Some(slot) = profile_vec.get(1) {
                    u8::from_str(slot)?
                } else {
                    2u8
                };
                if !(slot == 1 || slot == 2) {
                    return Err(anyhow!("Invalid YubiKey slot: {}", slot));
                }
                let rng = thread_rng();
                let challenge = if let Some(challenge) = profile_vec.get(2) {
                    (*challenge).to_owned()
                } else {
                    rng.sample_iter(Alphanumeric)
                        .take(YUBIKEY_CHALLENGE_LENGTH)
                        .collect()
                };
                Ok(Encryption::ChallengeResponse {
                    slot,
                    challenge,
                    response: RefCell::new(None),
                })
            }
            _ => Err(anyhow!("Unknown encryption profile: {}", profile)),
        }
    }
}
