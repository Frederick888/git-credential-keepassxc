pub mod callers;

use anyhow::{anyhow, Context, Error, Result};
use crypto_box::{
    self,
    aead::{generic_array, Aead},
    PublicKey, SalsaBox, SecretKey, KEY_SIZE,
};
#[cfg(test)]
use mockall::mock;
#[cfg(windows)]
use named_pipe::PipeClient;
use once_cell::unsync::OnceCell;
use std::cell::RefCell;
use std::fmt;
use std::io::{Read, Write};
#[cfg(unix)]
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::rc::Rc;
use std::str;

#[cfg(windows)]
const NAMED_PIPE_CONNECT_TIMEOUT_MS: u32 = 100;
const KEEPASS_SOCKET_NAME: &str = "org.keepassxc.KeePassXC.BrowserServer";
const KEEPASS_SOCKET_NAME_LEGACY: &str = "kpxc_server";

#[macro_export]
macro_rules! error {
    ($($args:tt)+) => {
        #[cfg(not(test))] slog::log!(crate::LOGGER.get().unwrap(), slog::Level::Error, "", $($args)+);
        #[cfg(test)] eprintln!("{}: {}", slog::Level::Error, format!($($args)+));
    };
}
#[macro_export]
macro_rules! warn {
    ($($args:tt)+) => {
        #[cfg(not(test))] slog::log!(crate::LOGGER.get().unwrap(), slog::Level::Warning, "", $($args)+);
        #[cfg(test)] eprintln!("{}: {}", slog::Level::Warning, format!($($args)+));
    };
}
#[macro_export]
macro_rules! info {
    ($($args:tt)+) => {
        #[cfg(not(test))] slog::log!(crate::LOGGER.get().unwrap(), slog::Level::Info, "", $($args)+);
        #[cfg(test)] eprintln!("{}: {}", slog::Level::Info, format!($($args)+));
    };
}
#[macro_export]
macro_rules! debug {
    ($($args:tt)+) => {
        #[cfg(not(test))] slog::log!(crate::LOGGER.get().unwrap(), slog::Level::Debug, "", $($args)+);
        #[cfg(test)] eprintln!("{}: {}", slog::Level::Debug, format!($($args)+));
    };
}

thread_local!(pub static SOCKET_PATH: OnceCell<PathBuf> = OnceCell::new());
pub fn get_socket_path() -> Result<PathBuf> {
    let socket_path = SOCKET_PATH.with(|s| -> Result<_> {
        Ok(s.get_or_try_init(|| -> Result<_> {
            let base_dirs = directories_next::BaseDirs::new()
                .ok_or_else(|| anyhow!("Failed to initialise base_dirs"))?;
            let get_socket_path_with_name = |name: &str| -> Result<PathBuf> {
                let socket_dir = if cfg!(windows) && name == KEEPASS_SOCKET_NAME_LEGACY {
                    let temp_dir = std::env::temp_dir();
                    let temp_dir = std::fs::canonicalize(&temp_dir)?;
                    PathBuf::from(format!(
                        "\\\\.\\pipe\\\\{}\\{}",
                        &temp_dir.to_string_lossy()[4..],
                        name
                    ))
                } else if cfg!(windows) {
                    PathBuf::from(format!("\\\\.\\pipe\\{}", name))
                } else if cfg!(target_os = "macos") {
                    std::env::temp_dir().join(name)
                } else {
                    base_dirs
                        .runtime_dir()
                        .ok_or_else(|| anyhow!("Failed to locate runtime_dir automatically"))?
                        .join(name)
                };
                Ok(socket_dir)
            };
            let legacy_path = get_socket_path_with_name(KEEPASS_SOCKET_NAME_LEGACY);
            if let Ok(legacy_path) = legacy_path {
                if legacy_path.exists() {
                    return Ok(legacy_path);
                }
                #[cfg(windows)]
                if PipeClient::connect_ms(&legacy_path, NAMED_PIPE_CONNECT_TIMEOUT_MS).is_ok() {
                    return Ok(legacy_path);
                }
                info!(
                    "Legacy socket path {} does not exist",
                    legacy_path.to_string_lossy()
                );
            }
            let path = get_socket_path_with_name(KEEPASS_SOCKET_NAME)?;
            #[cfg(windows)]
            if PipeClient::connect_ms(&path, NAMED_PIPE_CONNECT_TIMEOUT_MS).is_ok() {
                // KPXC 2.6.0 - 2.6.1 didn't have USERNAME in named pipe
                return Ok(path);
            } else {
                info!(
                    "Legacy socket path {} does not exist",
                    path.to_string_lossy()
                );
            }
            if cfg!(windows) {
                Ok(path.with_file_name(
                    KEEPASS_SOCKET_NAME.to_owned() + "_" + &std::env::var("USERNAME")?,
                ))
            } else {
                Ok(path)
            }
        })?
        .clone())
    });
    if let Ok(ref socket_path) = socket_path {
        debug!("Socket path: {}", socket_path.to_string_lossy());
    }
    socket_path
}

#[derive(Debug)]
pub struct InvalidKeyError(String, usize);
impl fmt::Display for InvalidKeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Invalid {} key length {}", self.0, self.1)
    }
}
impl std::error::Error for InvalidKeyError {}
#[derive(Debug)]
pub struct CryptionError(bool);
impl fmt::Display for CryptionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.0 {
            write!(f, "Encryption error")
        } else {
            write!(f, "Decryption error")
        }
    }
}
impl std::error::Error for CryptionError {}

#[cfg(unix)]
fn get_stream() -> Result<Rc<RefCell<UnixStream>>> {
    thread_local!(static STREAM: OnceCell<Rc<RefCell<UnixStream>>> = OnceCell::new());
    Ok(STREAM.with(|s| -> Result<_> {
        Ok(s.get_or_try_init(|| -> Result<_> {
            let path = get_socket_path()?;
            Ok(Rc::new(RefCell::new(
                UnixStream::connect(&path).with_context(|| {
                    format!(
                        "Failed to connect to Unix socket {}",
                        path.to_string_lossy()
                    )
                })?,
            )))
        })?
        .clone())
    })?)
}

#[cfg(windows)]
fn get_stream() -> Result<Rc<RefCell<PipeClient>>> {
    thread_local!(static STREAM: OnceCell<Rc<RefCell<PipeClient>>> = OnceCell::new());
    Ok(STREAM.with(|s| -> Result<_> {
        Ok(s.get_or_try_init(|| -> Result<_> {
            let path = get_socket_path()?;
            Ok(Rc::new(RefCell::new(
                PipeClient::connect_ms(&path, NAMED_PIPE_CONNECT_TIMEOUT_MS).with_context(
                    || format!("Failed to connect to named pipe {}", path.to_string_lossy()),
                )?,
            )))
        })?
        .clone())
    })?)
}

pub trait MessagingUtilsTrait {
    fn exchange_message(request: String) -> Result<String>;
    fn send_message(request: String) -> Result<()>;
    fn receive_message() -> Result<String>;
}

trait MessagingUtilsInternalTrait {
    fn read_to_end() -> Result<String>;
}

pub struct MessagingUtils {}
#[cfg(test)]
mock! {
    pub MessagingUtils {}
    impl MessagingUtilsTrait for MessagingUtils {
        fn exchange_message(request: String) -> Result<String>;
        fn send_message(request: String) -> Result<()>;
        fn receive_message() -> Result<String>;
    }
    impl MessagingUtilsInternalTrait for MessagingUtils {
        fn read_to_end() -> Result<String>;
    }
}

impl MessagingUtilsTrait for MessagingUtils {
    fn exchange_message(request: String) -> Result<String> {
        Self::send_message(request)?;
        Self::receive_message()
    }

    fn send_message(request: String) -> Result<()> {
        debug!("SEND: {}", request);
        let stream_rc = get_stream()?;
        let mut stream = stream_rc.borrow_mut();
        stream.write_all(request.as_bytes())?;
        Ok(())
    }

    fn receive_message() -> Result<String> {
        loop {
            #[cfg(not(test))]
            let response = Self::read_to_end()?;
            #[cfg(test)]
            let response = MockMessagingUtils::read_to_end()?;
            let jsons = cut_jsons(&response);
            if jsons.len() == 1 {
                break Ok(response);
            }
            warn!(
                "Response contains {} (> 1) JSONs, hence discarded",
                jsons.len(),
            );
        }
    }
}

impl MessagingUtilsInternalTrait for MessagingUtils {
    fn read_to_end() -> Result<String> {
        let stream_rc = get_stream()?;
        let mut stream = stream_rc.borrow_mut();
        let mut response = String::new();
        const BUF_SIZE: usize = 128;
        let mut buf = [0u8; BUF_SIZE];
        loop {
            let len = stream.read(&mut buf)?;
            response.push_str(str::from_utf8(&buf[0..len]).unwrap());
            if len < BUF_SIZE {
                break;
            }
        }
        debug!("RECV: {}", response);
        Ok(response)
    }
}

fn cut_jsons(response: &str) -> Vec<&str> {
    let mut results = Vec::new();

    let matching_symbol = |c: &char| -> Option<char> {
        match c {
            '{' => Some('}'),
            '}' => Some('{'),
            '[' => Some(']'),
            ']' => Some('['),
            '"' => Some('"'),
            _ => None,
        }
    };
    let is_symbol = |c: &char| -> bool { matching_symbol(c).is_some() };

    let mut stack = Vec::new();
    let mut start = 0;
    let mut current = 0;
    let mut escape = false;
    for c in response.chars() {
        if stack.is_empty() && current > 0 {
            results.push(&response[start..current]);
            start = current;
        }
        if !escape && c == '\\' {
            escape = true;
            current += 1;
            continue;
        }
        if !is_symbol(&c) || escape {
            escape = false;
            current += 1;
            continue;
        }
        if !stack.is_empty() && stack.last().unwrap() == &matching_symbol(&c).unwrap() {
            stack.pop();
        } else {
            stack.push(c);
        }
        current += 1;
    }
    results.push(&response[start..]);

    results
}

pub fn to_public_key<T: AsRef<str>>(public_key_b64: T) -> Result<PublicKey> {
    let public_key = base64::decode(public_key_b64.as_ref())?;
    if public_key.len() != crypto_box::KEY_SIZE {
        return Err(Error::from(InvalidKeyError(
            "host public".to_owned(),
            public_key.len(),
        )));
    }
    let public_key = {
        let mut bytes = [0u8; KEY_SIZE];
        bytes.copy_from_slice(&public_key[..KEY_SIZE]);
        bytes
    };
    Ok(PublicKey::from(public_key))
}

// pub fn to_secret_key<T: AsRef<str>>(secret_key_b64: T) -> Result<SecretKey> {
//     let secret_key = base64::decode(secret_key_b64.as_ref())?;
//     if secret_key.len() != crypto_box::KEY_SIZE {
//         return Err(Error::from(InvalidKeyError(
//             "client secret".to_owned(),
//             secret_key.len(),
//         )));
//     }
//     let secret_key = {
//         let mut bytes = [0u8; crypto_box::KEY_SIZE];
//         bytes.copy_from_slice(&secret_key[..KEY_SIZE]);
//         bytes
//     };
//     Ok(SecretKey::from(secret_key))
// }

pub fn generate_secret_key() -> SecretKey {
    let mut rng = rand::thread_rng();
    SecretKey::generate(&mut rng)
}

pub fn get_client_box(
    host_public_key: Option<&PublicKey>,
    client_secret_key: Option<&SecretKey>,
) -> Result<Rc<SalsaBox>> {
    thread_local!(static CLIENT_BOX: OnceCell<Rc<SalsaBox>> = OnceCell::new());
    Ok(CLIENT_BOX.with(|cb| -> Result<_> {
        Ok(cb.get_or_try_init(|| -> Result<_> {
            let client_secret_key = client_secret_key.ok_or_else(||
                anyhow!("get_client_box() is called before client secret key is available, this shouldn't happen")
            )?;
            let host_public_key = host_public_key.ok_or_else(||
                anyhow!("get_client_box() is called before host public key is available, this shouldn't happen")
            )?;
            Ok(Rc::new(SalsaBox::new(host_public_key, client_secret_key)))
        })?.clone())
    })?)
}

type NaClNonce = generic_array::GenericArray<u8, generic_array::typenum::U24>;

pub fn nacl_nonce() -> (NaClNonce, String) {
    let mut rng = rand::thread_rng();
    let nonce = crypto_box::generate_nonce(&mut rng);
    let nonce_b64 = base64::encode(&nonce);
    (nonce, nonce_b64)
}

pub fn to_encrypted_json<M: serde::Serialize>(request: &M, nonce: &NaClNonce) -> Result<String> {
    let json = serde_json::to_string(request)?;
    debug!("ENC : {}", json);
    let client_box = get_client_box(None, None)?;
    let encrypted = client_box
        .encrypt(&nonce, json.as_bytes())
        .map_err(|_| CryptionError(true))?;
    let encrypted = base64::encode(&encrypted);
    Ok(encrypted)
}

pub fn to_decrypted_json<T: AsRef<str>>(encrypted_b64: T, nonce: T) -> Result<String> {
    let bytes = base64::decode(encrypted_b64.as_ref())?;
    let client_box = get_client_box(None, None)?;
    let decrypted_json = client_box
        .decrypt(
            NaClNonce::from_slice(&base64::decode(nonce.as_ref())?),
            &bytes[..],
        )
        .map_err(|_| CryptionError(false))?;
    let json = String::from_utf8(decrypted_json)?;
    debug!("DEC : {}", json);
    Ok(json)
}

#[cfg(test)]
pub use tests::*;
#[cfg(test)]
mod tests {
    use super::*;
    use crate::keepassxc::messages::*;
    use once_cell::sync::OnceCell;
    use serde::{Deserialize, Serialize};
    use std::sync::{mpsc, Mutex};
    use std::thread;

    static TEST_HOST_KEY: OnceCell<SecretKey> = OnceCell::new();
    static TEST_SESSION_KEY: OnceCell<SecretKey> = OnceCell::new();

    pub fn test_guard() -> &'static Mutex<()> {
        static GUARD: OnceCell<Mutex<()>> = OnceCell::new();
        GUARD.get_or_init(|| Mutex::new(()))
    }

    pub fn test_host_secret_key() -> SecretKey {
        TEST_HOST_KEY.get_or_init(|| generate_secret_key()).clone()
    }

    pub fn test_session_secret_key() -> SecretKey {
        TEST_SESSION_KEY
            .get_or_init(|| generate_secret_key())
            .clone()
    }

    pub type ExchangeMessageContext =
        __mock_MockMessagingUtils_MessagingUtilsTrait::__exchange_message::Context;
    pub type SendMessageContext =
        __mock_MockMessagingUtils_MessagingUtilsTrait::__send_message::Context;
    pub type ReceiveMessageContext =
        __mock_MockMessagingUtils_MessagingUtilsTrait::__receive_message::Context;
    pub type ReadToEndContext =
        __mock_MockMessagingUtils_MessagingUtilsInternalTrait::__read_to_end::Context;

    pub fn mock_kpxc_initialise(host_secret_key: &SecretKey) -> ExchangeMessageContext {
        let host_public_key = host_secret_key.public_key();
        let exchange_message_context = MockMessagingUtils::exchange_message_context();
        exchange_message_context
            .expect()
            .times(1)
            .withf(|request: &String| {
                request.contains(KeePassAction::ChangePublicKeys.to_string().as_str())
            })
            .return_once(move |_| {
                let response = ChangePublicKeysResponse {
                    action: Some(KeePassAction::ChangePublicKeys),
                    public_key: Some(base64::encode(host_public_key.as_bytes())),
                    version: Some("git-credential-keepassxc mock".to_string()),
                    success: Some(KeePassBoolean(true)),
                };
                Ok(serde_json::to_string(&response).unwrap())
            });
        exchange_message_context
    }

    pub fn mock_kpxc_initialise_send_receive(
        host_secret_key: &SecretKey,
    ) -> (SendMessageContext, ReceiveMessageContext) {
        let host_public_key = host_secret_key.public_key();

        let send_message_context = MockMessagingUtils::send_message_context();
        send_message_context.expect().returning(|_| Ok(()));

        let receive_message_context = MockMessagingUtils::receive_message_context();
        receive_message_context
            .expect()
            .times(1)
            .return_once(move || {
                let response = ChangePublicKeysResponse {
                    action: Some(KeePassAction::ChangePublicKeys),
                    public_key: Some(base64::encode(host_public_key.as_bytes())),
                    version: Some("git-credential-keepassxc mock".to_string()),
                    success: Some(KeePassBoolean(true)),
                };
                Ok(serde_json::to_string(&response).unwrap())
            });

        (send_message_context, receive_message_context)
    }

    pub fn mock_kpxc_with_cipher_response<S>(
        context: &ReceiveMessageContext,
        host_secret_key: &SecretKey,
        client_public_key: &PublicKey,
        action: KeePassAction,
        response: S,
    ) where
        S: Serialize + CipherTextResponse,
    {
        let host_box = SalsaBox::new(client_public_key, host_secret_key);
        let (nonce, nonce_b64) = nacl_nonce();
        let json = serde_json::to_string(&response).unwrap();

        let wrapper = GenericResponseWrapper {
            action: action.clone(),
            message: Some(base64::encode(
                host_box.encrypt(&nonce, json.as_bytes()).unwrap(),
            )),
            nonce: Some(nonce_b64),
            error: None,
            error_code: None,
        };

        context
            .expect()
            .times(1)
            .return_once(move || Ok(serde_json::to_string(&wrapper).unwrap()));
    }

    pub fn mock_kpxc_with_jsons(jsons: Vec<&str>) -> ReadToEndContext {
        let read_to_end_ctx = MockMessagingUtils::read_to_end_context();
        for json in jsons {
            let json = json.to_string();
            read_to_end_ctx
                .expect()
                .times(1)
                .return_once(move || Ok(json));
        }
        read_to_end_ctx
    }

    #[test]
    fn test_00_cut_jsons_single_json() {
        let response = "{\"action\":\"test-associate\"}".to_owned();
        let results = cut_jsons(&response);
        assert_eq!(1, results.len());
        assert_eq!(&response, results[0]);
    }

    #[test]
    fn test_01_cut_jsons_multiple_jsons() {
        let jsons = vec![
            "{\"action\":\"test-associate\"}".to_owned(),
            "{\"action\":\"get-logins\",\"message\":\"testing\"}".to_owned(),
            "{\"action\":\"set-login\",\"message\":\"testing\"}".to_owned(),
        ];
        let response = jsons.iter().fold(String::new(), |acc, j| acc + &j);
        let results = cut_jsons(&response);
        assert_eq!(jsons.len(), results.len());
        for i in 0..jsons.len() {
            assert_eq!(&jsons[i], results[i]);
        }
    }

    #[test]
    fn test_02_cut_jsons_with_escaping() {
        let jsons = vec![
            "{\"action\":\"test-associate\",\"message\":\"\\\"\\[\"}".to_owned(),
            "[{\"action\":\"get-logins\",\"message\":\"testing\\]\"}]".to_owned(),
        ];
        let response = jsons.iter().fold(String::new(), |acc, j| acc + &j);
        let results = cut_jsons(&response);
        assert_eq!(jsons.len(), results.len());
        for i in 0..jsons.len() {
            assert_eq!(&jsons[i], results[i]);
        }
    }

    #[test]
    fn test_03_discard_multiple_jsons() {
        let jsons = vec![
            "{\"action\":\"test-associate\",\"message\":\"\\\"\\[\"}".to_owned()
                + "[{\"action\":\"get-logins\",\"message\":\"testing\\]\"}]",
            "{\"action\":\"test-associate\",\"message\":\"\\\"\\[\"}".to_owned()
                + "[{\"action\":\"get-logins\",\"message\":\"testing\\]\"}]",
            "[{\"action\":\"get-logins\",\"message\":\"testing\\]\"}]".to_owned(),
        ];

        let read_to_end_ctx = mock_kpxc_with_jsons(jsons.iter().map(String::as_str).collect());
        let response = MessagingUtils::receive_message();
        assert!(response.is_ok());
        let response = response.unwrap();
        assert_eq!(&response, jsons.last().unwrap());
        read_to_end_ctx.checkpoint();
    }

    #[test]
    #[should_panic(expected = "get_client_box() is called before client secret key is available")]
    fn test_04_fail_encrypt_before_initialise() {
        #[derive(Serialize)]
        struct Foo {
            bar: String,
        }
        let foo = Foo {
            bar: "Hello, world!".to_owned(),
        };
        let (nonce, _) = nacl_nonce();
        let (sender, receiver) = mpsc::channel();
        thread::spawn(move || {
            let encrypted = to_encrypted_json(&foo, &nonce);
            sender.send(encrypted).unwrap();
        })
        .join()
        .unwrap();
        let encrypted = receiver.recv().unwrap();
        encrypted.unwrap();
    }

    #[test]
    fn test_05_encryption_decryption() {
        #[derive(Serialize, Deserialize)]
        struct Foo {
            bar: String,
        }
        let foo = Foo {
            bar: "Hello, world!".to_owned(),
        };

        // initialise crypto_box
        let session_seckey = test_session_secret_key();
        let session_pubkey = session_seckey.public_key();
        let _ = get_client_box(Some(&session_pubkey), Some(&session_seckey));

        let (nonce, nonce_b64) = nacl_nonce();
        let encrypted = to_encrypted_json(&foo, &nonce);
        assert!(encrypted.is_ok(), "Encryption failed");
        let encrypted = encrypted.unwrap();

        let decrypted = to_decrypted_json(&encrypted, &nonce_b64);
        assert!(decrypted.is_ok(), "Decryption failed");
        let decrypted = decrypted.unwrap();
        assert_eq!(
            decrypted,
            serde_json::to_string(&foo).unwrap(),
            "Decrypted string differs from original JSON"
        );
    }
}
