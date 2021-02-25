use crate::utils::callers::CurrentCaller;
#[allow(unused_imports)]
use crate::{debug, error, info, warn};
use aes_gcm::aead::generic_array::{typenum, GenericArray};
use anyhow::{anyhow, Context, Result};
#[cfg(test)]
use mockall::automock;
use serde::{de, Deserialize, Serialize};
use std::cell::RefCell;
use std::fs;
use std::io::prelude::*;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
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
use {
    yubico_manager::config as yubico_config, yubico_manager::yubicoerror::YubicoError,
    yubico_manager::Yubico,
};

#[cfg(unix)]
const DEFAULT_CONFIG_MODE: u32 = 0o600;

#[cfg(any(feature = "encryption", feature = "yubikey"))]
const HMAC_SHA1_CHALLENGE_LENGTH: usize = 64usize;
#[cfg(all(feature = "encryption", feature = "yubikey"))]
const HMAC_SHA1_RESPONSE_LENGTH: usize = 20usize;
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
        info!(
            "Reading configuration from {}",
            config_path.as_ref().to_string_lossy()
        );
        let json = fs::read_to_string(config_path.as_ref()).with_context(|| {
            format!(
                "Failed to read configuration from {}",
                config_path.as_ref().to_string_lossy()
            )
        })?;
        let config: Config = serde_json::from_str(&json).with_context(|| {
            format!(
                "Invalid configuration file {}",
                config_path.as_ref().to_string_lossy()
            )
        })?;
        Ok(config)
    }

    pub fn write_to<T: AsRef<Path>>(&self, config_path: T) -> Result<()> {
        info!(
            "Writing configuration to {}",
            config_path.as_ref().to_string_lossy()
        );
        let json = serde_json::to_string_pretty(self)?;
        let mut file_options = fs::OpenOptions::new();
        #[cfg(unix)]
        file_options.mode(DEFAULT_CONFIG_MODE);
        let mut file = file_options
            .create(true)
            .write(true)
            .truncate(true)
            .open(config_path.as_ref())
            .with_context(|| {
                format!(
                    "Failed to open configuration to {}",
                    config_path.as_ref().to_string_lossy()
                )
            })?;

        file.write_all(&json.as_bytes()).with_context(|| {
            format!(
                "Failed to write configuration to {}",
                config_path.as_ref().to_string_lossy()
            )
        })?;
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
            self.encrypted_databases.push(EncryptedProfile {
                data,
                nonce,
                ..Default::default()
            });
        } else {
            self.databases.push(database);
        }
        Ok(())
    }

    pub fn encrypt_databases(&mut self) -> Result<usize> {
        let result = self.databases.len();
        for database in &self.databases {
            let (data, nonce) = self.base64_encrypt(&serde_json::to_string(database)?)?;
            self.encrypted_databases.push(EncryptedProfile {
                data,
                nonce,
                ..Default::default()
            });
        }
        self.databases.clear();
        Ok(result)
    }

    pub fn decrypt_databases(&mut self) -> Result<usize> {
        // TODO: check if Vec::drain_filter() can help simplify this when it's stabilised
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
        if self.count_encrypted_callers() > 0 {
            if self.callers.len() > 0 {
                warn!(
                    "{} unencrypted caller profile(s) ignored",
                    self.callers.len()
                );
            }
            let mut callers: Vec<_> = Vec::new();
            for encrypted_caller in &self.encrypted_callers {
                // must decrypt all encrypted callers
                callers.push(serde_json::from_str(
                    &self.base64_decrypt(&encrypted_caller.data, &encrypted_caller.nonce)?,
                )?);
            }
            Ok(callers)
        } else {
            Ok(self.callers.clone())
        }
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
            let description = Some(format!(
                "[This field is not used during verification] Caller profile for {}",
                caller.path
            ));
            let (data, nonce) = self.base64_encrypt(&serde_json::to_string(&caller)?)?;
            self.encrypted_callers.push(EncryptedProfile {
                data,
                nonce,
                description,
            });
        } else {
            self.callers.push(caller);
        }
        Ok(())
    }

    pub fn encrypt_callers(&mut self) -> Result<usize> {
        let result = self.callers.len();
        for caller in &self.callers {
            let description = Some(format!(
                "[This field is not used during verification] Caller profile for {}",
                caller.path
            ));
            let (data, nonce) = self.base64_encrypt(&serde_json::to_string(caller)?)?;
            self.encrypted_callers.push(EncryptedProfile {
                data,
                nonce,
                description,
            });
        }
        self.callers.clear();
        Ok(result)
    }

    pub fn decrypt_callers(&mut self) -> Result<usize> {
        // TODO: check if Vec::drain_filter() can help simplify this when it's stabilised
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
        error!("Enable encryption to use this feature");
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
        error!("Enable encryption to use this feature");
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
                warn!("Failed to read YubiKey serial number");
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
        error!("Enable encryption to use this feature");
        Err(anyhow!("Encryption is not enabled in this build"))
    }

    #[cfg(feature = "encryption")]
    pub fn add_encryption(&mut self, profile: &str) -> Result<()> {
        // strict match, so that we can add multiple tokens
        let existing_profile = self.get_encryption(true);
        // avoid adding multiple encryption profiles for single underlying hardware/etc
        match existing_profile {
            // user would like to use an existing profile
            Ok(_) if profile.is_empty() => Ok(()),
            // existing profile found, user specifies the same method but without any details
            Ok(existing_profile) if existing_profile.method() == profile => Ok(()),
            // existing profile found, same specs
            Ok(existing_profile) if existing_profile.to_string() == profile => Ok(()),
            // existing profile found, different specs
            Ok(_) => Err(anyhow!(
                "Encryption profile for this (hardware) token already exists"
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

    #[cfg(not(feature = "encryption"))]
    pub fn get_encryption_key(&self) -> Result<std::cell::Ref<Option<AesKey>>> {
        error!("Enable encryption to use this feature");
        Err(anyhow!("Encryption is not enabled in this build"))
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
        error!("YubiKey is not enabled in this build");
        Err(anyhow!("YubiKey is not enabled in this build"))
    }
    #[cfg(feature = "yubikey")]
    {
        #[cfg(not(test))]
        let mut yubikey = YubiKey::new()?;
        #[cfg(test)]
        let mut yubikey = MockYubiKeyTrait::new_mock();
        yubikey
            .read_serial_number()
            .map_err(|_| anyhow!("Failed to read YubiKey serial number"))
    }
}

#[derive(Serialize, Deserialize, Default, Debug)]
struct EncryptedProfile {
    data: String,
    #[serde(
        serialize_with = "aes_nonce_serialize",
        deserialize_with = "aes_nonce_deserialize"
    )]
    nonce: AesNonce,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    description: Option<String>,
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
    ) -> Self {
        let id_seckey_b64 = base64::encode(id_seckey.to_bytes());
        let id_pubkey = id_seckey.public_key();
        let id_pubkey_b64 = base64::encode(id_pubkey.as_bytes());
        Self {
            id,
            key: id_seckey_b64,
            pkey: id_pubkey_b64,
            group: group.name,
            group_uuid: group.uuid,
        }
    }
}

fn default_as_false() -> bool {
    false
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct Caller {
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gid: Option<u32>,
    #[serde(default = "default_as_false")]
    pub canonicalize: bool,
}

impl Caller {
    #[cfg(unix)]
    pub fn from_current_caller(
        current_caller: &CurrentCaller,
        no_uid: bool,
        no_gid: bool,
        canonicalize: bool,
    ) -> Self {
        Self {
            path: String::from(current_caller.path.to_string_lossy()),
            uid: if no_uid {
                None
            } else {
                Some(current_caller.uid)
            },
            gid: if no_gid {
                None
            } else {
                Some(current_caller.gid)
            },
            canonicalize,
        }
    }

    #[cfg(windows)]
    pub fn from_current_caller(current_caller: &CurrentCaller, canonicalize: bool) -> Self {
        Self {
            path: String::from(current_caller.path.to_string_lossy()),
            uid: None,
            gid: None,
            canonicalize,
        }
    }
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
                error!("YubiKey is not enabled in this build");
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
                let slot = if *slot == 1 {
                    yubico_config::Slot::Slot1
                } else {
                    yubico_config::Slot::Slot2
                };
                #[cfg(not(test))]
                let mut yubikey = YubiKey::new()?;
                #[cfg(test)]
                let mut yubikey = MockYubiKeyTrait::new_mock();
                let mut hmac_response = yubikey.challenge_response_hmac(&challenge, slot)?;
                debug_assert_eq!(hmac_response.len(), HMAC_SHA1_RESPONSE_LENGTH);
                hmac_response.extend_from_slice(&[0u8; AES_KEY_LENGTH - HMAC_SHA1_RESPONSE_LENGTH]);
                debug_assert_eq!(hmac_response.len(), AES_KEY_LENGTH);
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
                    warn!("Failed to read YubiKey serial number");
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
                        .take(HMAC_SHA1_CHALLENGE_LENGTH)
                        .map(char::from)
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

#[cfg(feature = "yubikey")]
#[cfg_attr(test, automock)]
trait YubiKeyTrait {
    fn read_serial_number(&mut self) -> Result<u32, YubicoError>;
    fn challenge_response_hmac(
        &mut self,
        challenge: &String,
        slot: yubico_config::Slot,
    ) -> Result<Vec<u8>, YubicoError>;
}

#[cfg(test)]
impl MockYubiKeyTrait {
    fn new_mock() -> Self {
        use hmac::{Mac, NewMac};

        let mut mock_yubikey = Self::new();
        mock_yubikey
            .expect_read_serial_number()
            .returning_st(|| Ok(tests::TEST_YUBIKEY_SERIAL));
        mock_yubikey
            .expect_challenge_response_hmac()
            .returning(|challenge, _| {
                let mut mac = tests::HmacSha1::new_from_slice(
                    tests::TEST_YUBIKEY_HMAC_SHA1_SECRET.as_bytes(),
                )
                .unwrap();
                mac.update(challenge.as_bytes());
                let result = mac.finalize();
                let bytes: Vec<_> = result.into_bytes().into_iter().collect();
                assert_eq!(
                    bytes.len(),
                    HMAC_SHA1_RESPONSE_LENGTH,
                    "Incorrect mock YubiKey response length"
                );
                Ok(bytes)
            });
        mock_yubikey
    }
}

#[cfg(feature = "yubikey")]
struct YubiKey {
    yubi: Yubico,
    device: yubico_manager::Device,
}

#[cfg(all(not(test), feature = "yubikey"))]
impl YubiKey {
    fn new() -> Result<Self> {
        let mut yubi = Yubico::new();
        let device = yubi.find_yubikey()?;
        Ok(Self { yubi, device })
    }
}

#[cfg(feature = "yubikey")]
impl YubiKeyTrait for YubiKey {
    fn read_serial_number(&mut self) -> Result<u32, YubicoError> {
        let config = yubico_config::Config::default()
            .set_vendor_id(self.device.vendor_id)
            .set_product_id(self.device.product_id);
        self.yubi.read_serial_number(config)
    }

    fn challenge_response_hmac(
        &mut self,
        challenge: &String,
        slot: yubico_config::Slot,
    ) -> Result<Vec<u8>, YubicoError> {
        debug!("Using YubiKey {:?}", slot);
        let config = yubico_config::Config::default()
            .set_vendor_id(self.device.vendor_id)
            .set_product_id(self.device.product_id)
            .set_variable_size(true)
            .set_mode(yubico_config::Mode::Sha1)
            .set_slot(slot);
        debug!("Challenge: {}", challenge);
        info!("Sending HMAC challenge, tap your YubiKey if needed");
        #[cfg(feature = "notification")]
        {
            use notify_rust::{Notification, Timeout};
            let notification = Notification::new()
                .summary("Tap YubiKey if necessary")
                .body(&format!(
                    "{} is going to send HMAC challenge to YubiKey",
                    clap::crate_name!()
                ))
                .timeout(Timeout::Milliseconds(3000))
                .show();
            if let Err(e) = notification {
                warn!("Failed to show notification for YubiKey operation, {}", e);
            }
        }
        let hmac_result = self
            .yubi
            .challenge_response_hmac(challenge.as_bytes(), config)?;
        debug!("HMAC response: {:?}", &*hmac_result);
        info!("HMAC response received");
        Ok((*hmac_result).iter().cloned().collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keepassxc::Group;
    use crate::utils::generate_secret_key;
    use hmac::Hmac;
    use sha1::Sha1;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    pub type HmacSha1 = Hmac<Sha1>;

    pub static TEST_YUBIKEY_SERIAL: u32 = 1234567;
    pub static TEST_YUBIKEY_HMAC_SHA1_SECRET: &'static str = "test_secret";

    #[test]
    fn test_00_config_read_write_plain_text() {
        let config_path = {
            let mut temp = std::env::temp_dir();
            temp.push(format!("{}.test_00.json", clap::crate_name!()));
            assert!(
                !temp.exists(),
                "Test configuration file {} already exists",
                temp.to_string_lossy()
            );
            temp
        };
        let group = Group::new("mock group", "mock uuid");
        let secret_key = generate_secret_key();
        let database = Database::new(
            "mock database".to_owned(),
            secret_key.clone(),
            group.clone(),
        );

        {
            // write
            let mut config = Config::new();
            config.add_database(database.clone(), false).unwrap();
            config.write_to(&config_path).unwrap();
        }
        {
            // read, validate
            let config = Config::read_from(&config_path).unwrap();
            assert_eq!(config.count_databases(), 1);
            let databases = config.get_databases().unwrap();
            assert_eq!(databases[0].id, database.id);
            assert_eq!(databases[0].key, base64::encode(secret_key.to_bytes()));
        }

        fs::remove_file(config_path).unwrap();
    }

    #[test]
    fn test_01_config_read_write_challenge_response() {
        let config_path = {
            let mut temp = std::env::temp_dir();
            temp.push(format!("{}.test_01.json", clap::crate_name!()));
            assert!(
                !temp.exists(),
                "Test configuration file {} already exists",
                temp.to_string_lossy()
            );
            temp
        };
        let group = Group::new("mock group", "mock uuid");
        let secret_key = generate_secret_key();
        let database = Database::new(
            "mock database".to_owned(),
            secret_key.clone(),
            group.clone(),
        );

        {
            // write plain text config
            let mut config = Config::new();
            config.add_database(database.clone(), false).unwrap();
            config.write_to(&config_path).unwrap();
        }
        {
            // read plain text, write encrypted
            let mut config = Config::read_from(&config_path).unwrap();
            config.add_encryption("challenge-response").unwrap();
            let encrypted = config.encrypt_databases().unwrap();
            assert_eq!(encrypted, 1);
            config.write_to(&config_path).unwrap();
        }
        {
            // read encrypted, validate, write back
            let mut config = Config::read_from(&config_path).unwrap();
            assert_eq!(config.count_databases(), 1);
            let databases = config.get_databases().unwrap();
            assert_eq!(databases[0].id, database.id);
            assert_eq!(databases[0].key, base64::encode(secret_key.to_bytes()));
            let decrypted = config.decrypt_databases().unwrap();
            assert_eq!(decrypted, 1);
            config.write_to(&config_path).unwrap();
        }
        {
            // still valid
            let _config = Config::read_from(&config_path).unwrap();
        }

        fs::remove_file(config_path).unwrap();
    }

    #[test]
    fn test_02_ignore_plaintext_callers_when_there_are_encrypted_ones() {
        let config_path = {
            let mut temp = std::env::temp_dir();
            temp.push(format!("{}.test_02.json", clap::crate_name!()));
            assert!(
                !temp.exists(),
                "Test configuration file {} already exists",
                temp.to_string_lossy()
            );
            temp
        };
        let caller = Caller {
            path: "/mock/path".to_owned(),
            uid: None,
            gid: None,
            ..Default::default()
        };

        {
            let mut config = Config::new();
            config.add_encryption("challenge-response").unwrap();
            config.add_caller(caller.clone(), true).unwrap();
            config.add_caller(caller.clone(), true).unwrap();
            config.add_caller(caller.clone(), false).unwrap();
            config.write_to(&config_path).unwrap();
        }
        {
            let config = Config::read_from(&config_path).unwrap();
            assert_eq!(config.count_callers(), 3);
            assert_eq!(config.count_encrypted_callers(), 2);
            assert_eq!(config.get_callers().unwrap().len(), 2);
        }

        fs::remove_file(config_path).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn test_github_15_00_new_config_file_permissions() {
        let config_path = {
            let mut temp = std::env::temp_dir();
            temp.push(format!("{}.test_github_15_00.json", clap::crate_name!()));
            assert!(
                !temp.exists(),
                "Test configuration file {} already exists",
                temp.to_string_lossy()
            );
            temp
        };
        let group = Group::new("mock group", "mock uuid");
        let secret_key = generate_secret_key();
        let database = Database::new(
            "mock database".to_owned(),
            secret_key.clone(),
            group.clone(),
        );

        {
            let mut config = Config::new();
            config.add_database(database.clone(), false).unwrap();
            config.write_to(&config_path).unwrap();
        }
        {
            assert!(config_path.exists());
            let metadata = config_path.metadata().unwrap();
            let permissions = metadata.permissions();
            assert_eq!(permissions.mode() & 0o777, DEFAULT_CONFIG_MODE);
        }

        fs::remove_file(config_path).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn test_github_15_01_existing_config_file_permissions() {
        let config_path = {
            let mut temp = std::env::temp_dir();
            temp.push(format!("{}.test_github_15_01.json", clap::crate_name!()));
            assert!(
                !temp.exists(),
                "Test configuration file {} already exists",
                temp.to_string_lossy()
            );
            temp
        };
        let group = Group::new("mock group", "mock uuid");
        let secret_key = generate_secret_key();
        let database = Database::new(
            "mock database".to_owned(),
            secret_key.clone(),
            group.clone(),
        );

        {
            let mut config = Config::new();
            config.add_database(database.clone(), false).unwrap();
            config.write_to(&config_path).unwrap();
        }
        {
            assert!(config_path.exists());
            let config_file = fs::File::open(&config_path).unwrap();
            let mut permissions = config_file.metadata().unwrap().permissions();
            permissions.set_mode(0o644);
            config_file.set_permissions(permissions).unwrap();
        }
        {
            assert!(config_path.exists());
            let mut database = database.clone();
            database.id = "mock database 2".to_owned();
            let mut config = Config::read_from(&config_path).unwrap();
            config.add_database(database, false).unwrap();
            config.write_to(&config_path).unwrap();
        }
        {
            assert!(config_path.exists());
            let config_file = fs::File::open(&config_path).unwrap();
            let permissions = config_file.metadata().unwrap().permissions();
            assert_eq!(permissions.mode() & 0o777, 0o644);
        }

        fs::remove_file(config_path).unwrap();
    }
}
