use crate::{debug, info};
use anyhow::{anyhow, Result};
use std::{env, io, path::PathBuf};

pub const KEEPASS_SOCKET_ENVIRONMENT_VARIABLE: &str = "KEEPASSXC_BROWSER_SOCKET_PATH";

#[cfg(windows)]
const NAMED_PIPE_CONNECT_TIMEOUT_MS: u32 = 100;
const KEEPASS_SOCKET_NAME: &str = "org.keepassxc.KeePassXC.BrowserServer";
// socket name prior to KeePassXC 2.6.0
const KEEPASS_SOCKET_NAME_LEGACY: &str = "kpxc_server";

pub fn get_socket_path() -> Result<PathBuf> {
    if let Ok(env_socket_path) = env::var(KEEPASS_SOCKET_ENVIRONMENT_VARIABLE) {
        return Ok(PathBuf::from(env_socket_path));
    }

    let candidates: Vec<Box<dyn SocketPath>> = vec![
        Box::new(LinuxSocketPathLegacy),
        Box::new(MacSocketPathLegacy),
        Box::new(WindowsSocketPathLegacy),
        Box::new(LinuxSocketPath260),
        Box::new(MacSocketPath260),
        Box::new(WindowsSocketPath260),
        Box::new(LinuxSocketPath272),
        Box::new(WindowsSocketPath262),
        Box::new(WindowsSocketPathNatMsg),
    ];
    let winner = candidates
        .iter()
        .filter(|c| c.matches_os())
        .find_map(|c| match c.get_path() {
            Ok(path) => Some(path),
            Err(e) => {
                debug!("Unqualified socket path candidate: {:?}", e);
                None
            }
        });
    match winner {
        Some(winner) => {
            info!("Socket path: {}", winner.to_string_lossy());
            Ok(winner)
        }
        None => Err(anyhow!("Failed to locate socket")),
    }
}

trait SocketPath {
    fn get_path(&self) -> Result<PathBuf>;
    fn matches_os(&self) -> bool;
}

struct LinuxSocketPathLegacy;
impl SocketPath for LinuxSocketPathLegacy {
    fn get_path(&self) -> Result<PathBuf> {
        let base_dirs = directories_next::BaseDirs::new()
            .ok_or_else(|| anyhow!("Failed to initialise base_dirs"))?;
        let result = base_dirs
            .runtime_dir()
            .ok_or_else(|| anyhow!("Failed to locate runtime_dir automatically"))?
            .join(KEEPASS_SOCKET_NAME_LEGACY);
        exist_or_error(result)
    }

    fn matches_os(&self) -> bool {
        cfg!(target_os = "linux")
    }
}

struct LinuxSocketPath260;
impl SocketPath for LinuxSocketPath260 {
    fn get_path(&self) -> Result<PathBuf> {
        let base_dirs = directories_next::BaseDirs::new()
            .ok_or_else(|| anyhow!("Failed to initialise base_dirs"))?;
        let result = base_dirs
            .runtime_dir()
            .ok_or_else(|| anyhow!("Failed to locate runtime_dir automatically"))?
            .join(KEEPASS_SOCKET_NAME);
        exist_or_error(result)
    }

    fn matches_os(&self) -> bool {
        cfg!(target_os = "linux")
    }
}

// https://github.com/keepassxreboot/keepassxc/commit/1009650b5c2697f5420c0f4398271652a4158c1a
struct LinuxSocketPath272;
impl SocketPath for LinuxSocketPath272 {
    fn get_path(&self) -> Result<PathBuf> {
        let base_dirs = directories_next::BaseDirs::new()
            .ok_or_else(|| anyhow!("Failed to initialise base_dirs"))?;
        let result = base_dirs
            .runtime_dir()
            .ok_or_else(|| anyhow!("Failed to locate runtime_dir automatically"))?
            .join("app")
            .join("org.keepassxc.KeePassXC")
            .join(KEEPASS_SOCKET_NAME);
        exist_or_error(result)
    }

    fn matches_os(&self) -> bool {
        cfg!(target_os = "linux")
    }
}

struct MacSocketPathLegacy;
impl SocketPath for MacSocketPathLegacy {
    fn get_path(&self) -> Result<PathBuf> {
        let result = std::env::temp_dir().join(KEEPASS_SOCKET_NAME_LEGACY);
        exist_or_error(result)
    }

    fn matches_os(&self) -> bool {
        cfg!(target_os = "macos")
    }
}

struct MacSocketPath260;
impl SocketPath for MacSocketPath260 {
    fn get_path(&self) -> Result<PathBuf> {
        let result = std::env::temp_dir().join(KEEPASS_SOCKET_NAME);
        exist_or_error(result)
    }

    fn matches_os(&self) -> bool {
        cfg!(target_os = "macos")
    }
}

struct WindowsSocketPathLegacy;
impl SocketPath for WindowsSocketPathLegacy {
    #[cfg(not(target_os = "windows"))]
    fn get_path(&self) -> Result<PathBuf> {
        unreachable!("Resolving WindowsSocketPathLegacy under non-Windows system");
    }

    #[cfg(target_os = "windows")]
    fn get_path(&self) -> Result<PathBuf> {
        let temp_dir = std::env::temp_dir();
        let temp_dir = std::fs::canonicalize(temp_dir)?;
        let result = PathBuf::from(format!(
            r#"\\.\pipe\\{}\{}"#,
            &temp_dir.to_string_lossy()[4..],
            KEEPASS_SOCKET_NAME_LEGACY
        ));
        connectable_or_error(result)
    }

    fn matches_os(&self) -> bool {
        cfg!(target_os = "windows")
    }
}

// https://github.com/Frederick888/git-credential-keepassxc/pull/34
struct WindowsSocketPathNatMsg;
impl SocketPath for WindowsSocketPathNatMsg {
    #[cfg(not(target_os = "windows"))]
    fn get_path(&self) -> Result<PathBuf> {
        unreachable!("Resolving WindowsSocketPathNatMsg under non-Windows system");
    }

    #[cfg(target_os = "windows")]
    fn get_path(&self) -> Result<PathBuf> {
        let username = std::env::var("USERNAME")?;
        let result = PathBuf::from(r"\\.\pipe\keepassxc\".to_owned() + &username + r"\kpxc_server");
        connectable_or_error(result)
    }

    fn matches_os(&self) -> bool {
        cfg!(target_os = "windows")
    }
}

struct WindowsSocketPath260;
impl SocketPath for WindowsSocketPath260 {
    #[cfg(not(target_os = "windows"))]
    fn get_path(&self) -> Result<PathBuf> {
        unreachable!("Resolving WindowsSocketPath260 under non-Windows system");
    }

    #[cfg(target_os = "windows")]
    fn get_path(&self) -> Result<PathBuf> {
        let result = PathBuf::from(format!(r#"\\.\pipe\{KEEPASS_SOCKET_NAME}"#));
        connectable_or_error(result)
    }

    fn matches_os(&self) -> bool {
        cfg!(target_os = "windows")
    }
}

struct WindowsSocketPath262;
impl SocketPath for WindowsSocketPath262 {
    #[cfg(not(target_os = "windows"))]
    fn get_path(&self) -> Result<PathBuf> {
        unreachable!("Resolving WindowsSocketPath260 under non-Windows system");
    }

    #[cfg(target_os = "windows")]
    fn get_path(&self) -> Result<PathBuf> {
        use std::sync::OnceLock;

        const CORRUPTED_CHAR: char = '\u{FFFD}';

        static CACHED_REPLACEMENT: OnceLock<String> = OnceLock::new();
        let get_replacement_string = || {
            // Lazily compute due to most of environments being ASCII-based
            CACHED_REPLACEMENT.get_or_init(|| {
                use windows_sys::Win32::Globalization;
                let max_char_size = unsafe {
                    let acp = Globalization::GetACP();
                    let mut cp_info = std::mem::zeroed::<Globalization::CPINFO>();
                    if Globalization::GetCPInfo(acp, &mut cp_info) == 0 {
                        1
                    } else {
                        cp_info.MaxCharSize as usize
                    }
                };
                std::iter::repeat_n(CORRUPTED_CHAR, max_char_size).collect()
            })
        };

        // KeePassXC will replace non-ASCII characters with "U+FFFD"s
        let username = std::env::var("USERNAME")?;
        let username_corrupted = {
            let mut buffer = String::with_capacity(username.len() * 2); 
            for c in username.chars() {
                if matches!(c, ' '..='~') { // is_ascii_graphic or ' '
                    buffer.push(c);
                } else if c.is_ascii_control() {
                    buffer.push(CORRUPTED_CHAR) // 1 char for ASCII control chars
                } else {
                    // For non-ASCII chars, the number of "U+FFFD"s replaced
                    // depends on the MaxCharSize of CPINFO
                    buffer.push_str(get_replacement_string());
                }
            }
            buffer
        };

        // Construct the pipe path according to
        // https://github.com/keepassxreboot/keepassxc/blob/develop/src/browser/BrowserShared.cpp
        let path_string = format!(r"\\.\pipe\{KEEPASS_SOCKET_NAME}_{username_corrupted}");
        let result = PathBuf::from(path_string);
        connectable_or_error(result)
    }

    fn matches_os(&self) -> bool {
        cfg!(target_os = "windows")
    }
}

fn exist_or_error(path: PathBuf) -> Result<PathBuf> {
    if path.exists() {
        Ok(path)
    } else {
        Err(anyhow!(io::Error::new(
            io::ErrorKind::NotFound,
            format!("{} does not exist", path.to_string_lossy()),
        )))
    }
}

#[cfg(target_os = "windows")]
fn connectable_or_error(path: PathBuf) -> Result<PathBuf> {
    let path = exist_or_error(path)?;
    match named_pipe::PipeClient::connect_ms(&path, NAMED_PIPE_CONNECT_TIMEOUT_MS) {
        Ok(_) => Ok(path),
        Err(e) => Err(anyhow!(e)),
    }
}
