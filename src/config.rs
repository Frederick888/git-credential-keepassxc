use aes_gcm::aead::generic_array::{typenum, GenericArray};
use anyhow::{anyhow, Result};
use serde::{de, Deserialize, Serialize};
use slog::*;
use std::cell::RefCell;
use std::fs;
use std::io::prelude::*;
use std::path::Path;
use std::string::ToString;
#[cfg(feature = "encryption")]
use {
    aes_gcm::aead::{Aead, NewAead},
    aes_gcm::Aes256Gcm,
    rand::distributions::Alphanumeric,
    rand::{thread_rng, Rng},
    std::str::FromStr,
};
#[cfg(feature = "yubikey")]
use {yubico_manager::config as yubico_config, yubico_manager::Yubico};

#[cfg(any(feature = "encryption", feature = "yubikey"))]
const YUBIKEY_CHALLENGE_LENGTH: usize = 64usize;
#[cfg(all(feature = "encryption", feature = "yubikey"))]
const YUBIKEY_RESPONSE_LENGTH: usize = 20usize;
#[cfg(feature = "encryption")]
const AES_KEY_LENGTH: usize = 32usize;
#[cfg(feature = "encryption")]
const AES_NONCE_LENGTH: usize = 12usize;

type AesKey = GenericArray<u8, typenum::U32>;
type AesNonce = GenericArray<u8, typenum::U12>;

#[derive(Serialize, Deserialize, Default, Debug)]
pub struct Config {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    databases: Vec<Database>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    encrypted_databases: Vec<EncryptedProfile>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    callers: Vec<Caller>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    encrypted_callers: Vec<EncryptedProfile>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    encryptions: Vec<Encryption>,
    #[serde(skip)]
    encryption_key: RefCell<Option<AesKey>>,
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
        for encrypted_database in &self.encrypted_databases {
            let database_json =
                self.base64_decrypt(&encrypted_database.data, &encrypted_database.nonce);
            if let Ok(database_json) = database_json {
                databases.push(serde_json::from_str(database_json.as_str())?);
            } else {
                warn!(
                    crate::LOGGER.get().unwrap(),
                    "Failed to decrypt database profile {}.. (omitted)",
                    &encrypted_database.data[..8]
                );
            }
        }
        Ok(databases)
    }

    pub fn count_databases(&self) -> usize {
        self.databases.len() + self.encrypted_databases.len()
    }

    pub fn count_encrypted_databases(&self) -> usize {
        self.encrypted_databases.len()
    }

    pub fn add_database(&mut self, database: Database, encrypted: bool) -> Result<()> {
        if encrypted {
            let (data, nonce) = self.base64_encrypt(&serde_json::to_string(&database)?)?;
            self.encrypted_databases
                .push(EncryptedProfile { data, nonce });
        } else {
            self.databases.push(database);
        }
        Ok(())
    }

    pub fn encrypt_databases(&mut self) -> Result<usize> {
        let result = self.databases.len();
        for database in &self.databases {
            let (data, nonce) = self.base64_encrypt(&serde_json::to_string(database)?)?;
            self.encrypted_databases
                .push(EncryptedProfile { data, nonce });
        }
        self.databases.clear();
        Ok(result)
    }

    pub fn decrypt_databases(&mut self) -> Result<usize> {
        // TODO: check if Vec::drain_filter() can help simplifies this when it's stabilised
        let mut decrypted_database_indices = Vec::new();
        for (idx, encrypted_database) in self.encrypted_databases.iter().enumerate() {
            if let Ok(json) =
                self.base64_decrypt(&encrypted_database.data, &encrypted_database.nonce)
            {
                if let Ok(database) = serde_json::from_str(&json) {
                    self.databases.push(database);
                    decrypted_database_indices.push(idx);
                    continue;
                }
            }
            warn!(
                crate::LOGGER.get().unwrap(),
                "Failed to decrypt database profile {}.. (omitted)",
                &encrypted_database.data[..8]
            );
        }
        for idx in decrypted_database_indices.iter().rev() {
            self.encrypted_databases.remove(*idx);
        }

        Ok(decrypted_database_indices.len())
    }

    pub fn get_callers(&self) -> Result<Vec<Caller>> {
        let mut callers: Vec<_> = self.callers.clone();
        for encrypted_caller in &self.encrypted_callers {
            // must decrypt all encrypted callers
            callers.push(serde_json::from_str(
                &self.base64_decrypt(&encrypted_caller.data, &encrypted_caller.nonce)?,
            )?);
        }
        Ok(callers)
    }

    pub fn count_callers(&self) -> usize {
        self.callers.len() + self.encrypted_callers.len()
    }

    pub fn count_encrypted_callers(&self) -> usize {
        self.encrypted_callers.len()
    }

    pub fn clear_callers(&mut self) {
        self.callers.clear();
        self.encrypted_callers.clear();
    }

    pub fn add_caller(&mut self, caller: Caller, encrypted: bool) -> Result<()> {
        if encrypted {
            let (data, nonce) = self.base64_encrypt(&serde_json::to_string(&caller)?)?;
            self.encrypted_callers
                .push(EncryptedProfile { data, nonce });
        } else {
            self.callers.push(caller);
        }
        Ok(())
    }

    pub fn encrypt_callers(&mut self) -> Result<usize> {
        let result = self.callers.len();
        for caller in &self.callers {
            let (data, nonce) = self.base64_encrypt(&serde_json::to_string(caller)?)?;
            self.encrypted_callers
                .push(EncryptedProfile { data, nonce });
        }
        Ok(result)
    }

    pub fn decrypt_callers(&mut self) -> Result<usize> {
        // TODO: check if Vec::drain_filter() can help simplifies this when it's stabilised
        let mut decrypted_caller_indices = Vec::new();
        for (idx, encrypted_caller) in self.encrypted_callers.iter().enumerate() {
            if let Ok(json) = self.base64_decrypt(&encrypted_caller.data, &encrypted_caller.nonce) {
                if let Ok(caller) = serde_json::from_str(&json) {
                    self.callers.push(caller);
                    decrypted_caller_indices.push(idx);
                    continue;
                }
            }
            warn!(
                crate::LOGGER.get().unwrap(),
                "Failed to decrypt caller profile {}.. (omitted)",
                &encrypted_caller.data[..8]
            );
        }
        for idx in decrypted_caller_indices.iter().rev() {
            self.encrypted_callers.remove(*idx);
        }

        Ok(decrypted_caller_indices.len())
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
    fn base64_decrypt_with(data: &str, key: &AesKey, nonce: &AesNonce) -> Result<Vec<u8>> {
        let aead = Aes256Gcm::new(key);

        let decrypted = aead
            .decrypt(nonce, base64::decode(data)?.as_ref())
            .map_err(|_| anyhow!("Failed to decrypt database key"))?;
        Ok(decrypted)
    }

    #[cfg(feature = "encryption")]
    fn base64_decrypt(&self, data: &str, nonce: &AesNonce) -> Result<String> {
        let key = self.get_encryption_key()?;
        Ok(String::from_utf8(Self::base64_decrypt_with(
            data,
            key.as_ref().unwrap(),
            nonce,
        )?)?)
    }

    #[cfg(not(feature = "encryption"))]
    fn base64_encrypt(&self, _data: &str) -> Result<(String, AesNonce)> {
        error!(
            crate::LOGGER.get().unwrap(),
            "Enable encryption to use this feature"
        );
        Err(anyhow!("Encryption is not enabled in this build"))
    }

    #[cfg(feature = "encryption")]
    fn base64_encrypt_with(data: &[u8], key: &AesKey, nonce: &AesNonce) -> Result<String> {
        let aead = Aes256Gcm::new(key);

        let encrypted = aead
            .encrypt(&nonce, data)
            .map_err(|_| anyhow!("Failed to encrypt database key"))?;
        Ok(base64::encode(&encrypted))
    }

    #[cfg(feature = "encryption")]
    fn base64_encrypt(&self, data: &str) -> Result<(String, AesNonce)> {
        let nonce = aes_nonce();
        let key = self.get_encryption_key()?;
        Ok((
            Self::base64_encrypt_with(data.as_bytes(), key.as_ref().unwrap(), &nonce)?,
            nonce,
        ))
    }

    #[cfg(feature = "encryption")]
    fn get_encryption(&self, strict: bool) -> Result<&Encryption> {
        if self.encryptions.is_empty() {
            return Err(anyhow!("No encryption profile found"));
        }
        let mut strict_match = false;
        let mut profile: &Encryption = &self.encryptions[0];
        let curr_serial = read_yubikey_serial();
        match curr_serial {
            Ok(curr_serial) => {
                for encryption in &self.encryptions {
                    match encryption {
                        Encryption::ChallengeResponse { serial, .. } => {
                            if *serial.as_ref().unwrap() == curr_serial {
                                strict_match = true;
                                profile = encryption;
                            }
                        }
                    }
                }
            }
            Err(_) => {
                warn!(
                    crate::LOGGER.get().unwrap(),
                    "Failed to read YubiKey serial number"
                );
            }
        }

        if strict && !strict_match {
            return Err(anyhow!(
                "Failed to find a strictly matching encryption profile"
            ));
        }
        Ok(profile)
    }

    pub fn count_encryptions(&self) -> usize {
        self.encryptions.len()
    }

    #[cfg(not(feature = "encryption"))]
    pub fn add_encryption(&mut self, _profile: &str) -> Result<()> {
        error!(
            crate::LOGGER.get().unwrap(),
            "Enable encryption to use this feature"
        );
        Err(anyhow!("Encryption is not enabled in this build"))
    }

    #[cfg(feature = "encryption")]
    pub fn add_encryption(&mut self, profile: &str) -> Result<()> {
        // strict match, so that we can add multiple tokens
        let existing_profile = self.get_encryption(true);
        // avoid adding multiple encryption profiles for single underlying hardward/etc
        match existing_profile {
            // user would like to use an existing profile
            Ok(_) if profile.is_empty() => Ok(()),
            // existing profile found, user specifies the same method but without any details
            Ok(existing_profile) if existing_profile.method() == profile => Ok(()),
            // existing profile found, same specs
            Ok(existing_profile) if existing_profile.to_string() == profile => Ok(()),
            // existing profile found, different specs
            Ok(_) => Err(anyhow!(
                "Encryption profile for this (hardward) token already exists"
            )),
            Err(_) => {
                // no existing profiles
                let profile = Encryption::from_str(profile)?;
                match &profile {
                    Encryption::ChallengeResponse { key, nonce, .. } => {
                        // extract key from an existing profile
                        *key.borrow_mut() = {
                            let encryption_key =
                                self.get_encryption_key().or_else(|_| -> Result<_> {
                                    warn!(
                                        crate::LOGGER.get().unwrap(),
                                        "Failed to extract encryption key from existing profiles, gonna create a new one"
                                    );
                                    *self.encryption_key.borrow_mut() = Some(aes_key());
                                    Ok(self.encryption_key.borrow())
                                })?;
                            let response = profile.get_response()?;
                            Self::base64_encrypt_with(
                                encryption_key.as_ref().unwrap(),
                                response.as_ref().unwrap(),
                                nonce,
                            )?
                        };
                        self.encryptions.push(profile);
                        return Ok(());
                    }
                }
            }
        }
    }

    pub fn clear_encryptions(&mut self) {
        self.encryptions.clear();
    }

    #[cfg(feature = "encryption")]
    pub fn get_encryption_key(&self) -> Result<std::cell::Ref<Option<AesKey>>> {
        if self.encryption_key.borrow().is_some() {
            return Ok(self.encryption_key.borrow());
        }
        let encryption = self.get_encryption(false)?;
        match encryption {
            Encryption::ChallengeResponse { key, nonce, .. } => {
                let response = encryption.get_response()?;
                *self.encryption_key.borrow_mut() =
                    Some(AesKey::clone_from_slice(&Self::base64_decrypt_with(
                        key.borrow().as_str(),
                        response.as_ref().unwrap(),
                        nonce,
                    )?));
                Ok(self.encryption_key.borrow())
            }
        }
    }
}

#[cfg(feature = "encryption")]
fn aes_key() -> AesKey {
    let mut rng = rand::thread_rng();
    let mut key = AesKey::clone_from_slice(&[0u8; AES_KEY_LENGTH]);
    rng.fill(key.as_mut_slice());
    key
}

#[cfg(feature = "encryption")]
fn aes_nonce() -> AesNonce {
    let mut rng = rand::thread_rng();
    let mut nonce = AesNonce::clone_from_slice(&[0u8; AES_NONCE_LENGTH]);
    rng.fill(nonce.as_mut_slice());
    nonce
}

fn aes_nonce_serialize<S>(nonce: &AesNonce, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    let nonce = base64::encode(nonce);
    serializer.serialize_str(&nonce)
}

fn aes_nonce_deserialize<'de, D>(deserializer: D) -> Result<AesNonce, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let nonce: &str = de::Deserialize::deserialize(deserializer)?;
    let nonce = base64::decode(nonce).map_err(|_| {
        de::Error::invalid_value(de::Unexpected::Str(nonce), &"base64 encoded data")
    })?;
    Ok(AesNonce::clone_from_slice(nonce.as_ref()))
}

#[cfg(feature = "encryption")]
fn read_yubikey_serial() -> Result<u32> {
    #[cfg(not(feature = "yubikey"))]
    {
        error!(
            crate::LOGGER.get().unwrap(),
            "YubiKey is not enabled in this build"
        );
        Err(anyhow!("YubiKey is not enabled in this build"))
    }
    #[cfg(feature = "yubikey")]
    {
        let mut yubi = Yubico::new();
        let device = yubi.find_yubikey()?;
        let config = yubico_config::Config::default()
            .set_vendor_id(device.vendor_id)
            .set_product_id(device.product_id);
        yubi.read_serial_number(config)
            .map_err(|_| anyhow!("Failed to read YubiKey serial number"))
    }
}

#[derive(Serialize, Deserialize, Debug)]
struct EncryptedProfile {
    data: String,
    #[serde(
        serialize_with = "aes_nonce_serialize",
        deserialize_with = "aes_nonce_deserialize"
    )]
    nonce: AesNonce,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Database {
    pub id: String,
    pub key: String,
    pub pkey: String,
    pub group: String,
    pub group_uuid: String,
}

impl Database {
    pub fn new(
        id: String,
        id_seckey: crypto_box::SecretKey,
        group: crate::keepassxc::Group,
    ) -> Result<Self> {
        let id_seckey_b64 = base64::encode(id_seckey.to_bytes());
        let id_pubkey = id_seckey.public_key();
        let id_pubkey_b64 = base64::encode(id_pubkey.as_bytes());
        Ok(Self {
            id,
            key: id_seckey_b64,
            pkey: id_pubkey_b64,
            group: group.name,
            group_uuid: group.uuid,
        })
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Caller {
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gid: Option<u32>,
}

#[derive(Serialize, Deserialize, Debug)]
enum Encryption {
    ChallengeResponse {
        #[serde(skip_serializing_if = "Option::is_none")]
        serial: Option<u32>,
        slot: u8,
        challenge: String,
        key: RefCell<String>,
        #[serde(
            serialize_with = "aes_nonce_serialize",
            deserialize_with = "aes_nonce_deserialize"
        )]
        nonce: AesNonce,
        #[serde(skip)]
        response: RefCell<Option<AesKey>>,
    },
}

impl Encryption {
    fn method(&self) -> String {
        match self {
            Encryption::ChallengeResponse { .. } => "challenge-response".to_owned(),
        }
    }

    #[cfg(feature = "encryption")]
    fn get_response(&self) -> Result<std::cell::Ref<Option<AesKey>>> {
        match self {
            #[cfg(not(feature = "yubikey"))]
            Encryption::ChallengeResponse { .. } => {
                error!(
                    crate::LOGGER.get().unwrap(),
                    "YubiKey is not enabled in this build"
                );
                Err(anyhow!("YubiKey is not enabled in this build"))
            }
            #[cfg(feature = "yubikey")]
            Encryption::ChallengeResponse {
                slot,
                challenge,
                response,
                ..
            } => {
                if response.borrow().is_some() {
                    return Ok(response.borrow());
                }
                let mut yubi = Yubico::new();
                let device = yubi.find_yubikey()?;
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
                info!(
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

impl ToString for Encryption {
    fn to_string(&self) -> String {
        match self {
            Encryption::ChallengeResponse {
                slot, challenge, ..
            } => format!("{}:{}:{}", self.method(), slot, challenge),
        }
    }
}

#[cfg(feature = "encryption")]
impl FromStr for Encryption {
    type Err = anyhow::Error;

    fn from_str(profile: &str) -> Result<Self, Self::Err> {
        let profile_vec: Vec<_> = profile.split(':').collect();
        if profile_vec.is_empty() {
            return Err(anyhow!("Failed to parse encryption profile: {}", profile));
        }
        match profile_vec[0] {
            "challenge-response" => {
                let serial = read_yubikey_serial().ok();
                if serial.is_none() {
                    warn!(
                        crate::LOGGER.get().unwrap(),
                        "Failed to read YubiKey serial number"
                    );
                }
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
                    serial,
                    slot,
                    challenge,
                    key: RefCell::new(String::new()),
                    nonce: aes_nonce(),
                    response: RefCell::new(None),
                })
            }
            _ => Err(anyhow!("Unknown encryption profile: {}", profile)),
        }
    }
}
