use anyhow::{anyhow, Error, Result};
use crypto_box::{
    self,
    aead::{generic_array, Aead},
    PublicKey, SalsaBox, SecretKey, KEY_SIZE,
};
#[cfg(windows)]
use named_pipe::PipeClient;
use once_cell::unsync::OnceCell;
use rand::rngs::ThreadRng;
use slog::debug;
use std::cell::RefCell;
use std::fmt;
use std::io::{Read, Write};
#[cfg(unix)]
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::rc::Rc;
use std::str;

static KEEPASS_SOCKET_NAME: &str = "kpxc_server";

#[derive(Debug)]
pub struct SocketPathError;
impl fmt::Display for SocketPathError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Failed to find KeePassXC socket")
    }
}
impl std::error::Error for SocketPathError {}

thread_local!(pub static SOCKET_PATH: OnceCell<PathBuf> = OnceCell::new());
pub fn get_socket_path() -> Result<PathBuf> {
    let socket_path = SOCKET_PATH.with(|s| -> Result<_> {
        Ok(s.get_or_try_init(|| -> Result<_> {
            let base_dirs = directories_next::BaseDirs::new()
                .ok_or_else(|| anyhow!("Failed to initialise base_dirs"))?;
            let socket_dir = if cfg!(windows) {
                let cache_dir = base_dirs.cache_dir();
                PathBuf::from(format!(
                    "\\\\.\\pipe\\\\{}\\Temp\\kpxc_server",
                    cache_dir.to_string_lossy()
                ))
            } else {
                // TODO: check macOS value
                base_dirs
                    .runtime_dir()
                    .ok_or_else(|| anyhow!("Failed to locate runtime_dir automatically"))?
                    .join(KEEPASS_SOCKET_NAME)
            };
            Ok(socket_dir)
        })?
        .clone())
    });
    if let Ok(ref socket_path) = socket_path {
        debug!(
            crate::LOGGER.get().unwrap(),
            "Socket path: {}",
            socket_path.to_string_lossy()
        );
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
            Ok(Rc::new(RefCell::new(UnixStream::connect(path)?)))
        })?
        .clone())
    })?)
}

pub fn exchange_message(request: String) -> Result<String> {
    debug!(crate::LOGGER.get().unwrap(), "SEND: {}", request);
    #[cfg(unix)]
    let mut stream = get_stream()?.borrow().try_clone()?;
    #[cfg(windows)]
    let mut stream = PipeClient::connect(get_socket_path()?)?;
    stream.write_all(request.as_bytes())?;
    #[cfg(unix)]
    stream.write_all(b"\n")?;
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
    debug!(crate::LOGGER.get().unwrap(), "RECV: {}", response);
    Ok(response)
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

fn get_rng() -> Rc<RefCell<ThreadRng>> {
    thread_local! {
        static RNG: OnceCell<Rc<RefCell<ThreadRng>>> = OnceCell::new();
    }
    RNG.with(|r| {
        r.get_or_init(|| Rc::new(RefCell::new(rand::thread_rng())))
            .clone()
    })
}

pub fn generate_secret_key() -> SecretKey {
    let mut rng = *get_rng().borrow_mut();
    SecretKey::generate(&mut rng)
}

pub fn get_client_box(
    host_public_key: Option<&PublicKey>,
    client_secret_key: Option<&SecretKey>,
) -> Result<Rc<SalsaBox>> {
    thread_local!(static CLIENT_BOX: OnceCell<Rc<SalsaBox>> = OnceCell::new());
    Ok(CLIENT_BOX.with(|cb| -> Result<_> {
        Ok(cb.get_or_init(|| {
            let client_secret_key = client_secret_key.expect(
                "get_client_box() is called before client secret key is available, this shouldn't happen"
            );
            let host_public_key = host_public_key.expect(
                "get_client_box() is called before host public key is available, this shouldn't happen",
            );
            Rc::new(SalsaBox::new(host_public_key, client_secret_key))
        }).clone())
    })?)
}

type NonceType = generic_array::GenericArray<u8, generic_array::typenum::U24>;

pub fn generate_nonce() -> (NonceType, String) {
    let mut rng = *get_rng().borrow_mut();
    let nonce = crypto_box::generate_nonce(&mut rng);
    let nonce_b64 = base64::encode(&nonce);
    (nonce, nonce_b64)
}

pub fn to_encrypted_json<M: serde::Serialize>(request: &M, nonce: &NonceType) -> Result<String> {
    let json = serde_json::to_string(request)?;
    debug!(crate::LOGGER.get().unwrap(), "ENC : {}", json);
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
            NonceType::from_slice(&base64::decode(nonce.as_ref())?),
            &bytes[..],
        )
        .map_err(|_| CryptionError(false))?;
    let json = String::from_utf8(decrypted_json)?;
    debug!(crate::LOGGER.get().unwrap(), "DEC : {}", json);
    Ok(json)
}
