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
        // KeePassXC uses Qt's `qgetenv(...)`,
        // which based on C stdlib's `::getenv(...)` to get USERNAME,
        // It returns different results between Rust's `std::env::var(...)`.
        let username_byte = c_getenv("USERNAME")
            .ok_or_else(|| anyhow!("Failed to get USERNAME from environment"))?;
        let username = String::from_utf8_lossy(&username_byte);

        // Construct the pipe path according to
        // https://github.com/keepassxreboot/keepassxc/blob/develop/src/browser/BrowserShared.cpp
        let path_string = format!(r"\\.\pipe\{KEEPASS_SOCKET_NAME}_{username}");
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

#[cfg(target_os = "windows")]
fn c_getenv(name: &str) -> Option<Vec<u8>> {
    use std::ffi::{CStr, CString};
    use std::os::raw::c_char;

    extern "C" {
        fn getenv(name: *const c_char) -> *const c_char;
    }

    let c_name = CString::new(name).ok()?;
    let ptr = unsafe { getenv(c_name.as_ptr()) };
    if ptr.is_null() {
        return None;
    }

    let c_str = unsafe { CStr::from_ptr(ptr) };
    Some(c_str.to_bytes().to_vec())
}

#[cfg(test)]
#[cfg(target_os = "windows")]
mod test_c_getenv {
    use super::c_getenv;

    fn to_local_8bit_win32(s: &str) -> Vec<u8> {
        use std::os::windows::ffi::OsStrExt as _;
        use windows_sys::Win32::Globalization::{WideCharToMultiByte, CP_ACP};

        let wide_str: Vec<u16> = std::ffi::OsStr::new(s).encode_wide().collect();
        unsafe {
            let len = WideCharToMultiByte(
                CP_ACP, // Use local code page
                0,
                wide_str.as_ptr(),
                wide_str.len() as i32,
                std::ptr::null_mut(),
                0,
                std::ptr::null(),
                std::ptr::null_mut(),
            );

            let mut res = vec![0u8; len as usize];
            WideCharToMultiByte(
                CP_ACP,
                0,
                wide_str.as_ptr(),
                wide_str.len() as i32,
                res.as_mut_ptr(),
                len,
                std::ptr::null(),
                std::ptr::null_mut(),
            );
            res
        }
    }

    fn c_putenv(name: &str, value: &str) -> i32 {
        extern "C" {
            fn _putenv(envstring: *const std::os::raw::c_char) -> std::os::raw::c_int;
        }

        let value_bytes = to_local_8bit_win32(value);
        let value = String::from_utf8_lossy(&value_bytes);
        let env_setter = format!("{}={}", name, value);
        let c_str = std::ffi::CString::new(env_setter).unwrap();
        unsafe { _putenv(c_str.as_ptr()) }
    }

    #[test]
    fn test_c_env_corrupted_string() {
        #[rustfmt::skip]
        use windows_sys::Win32::System::Console::{
            GetConsoleCP, SetConsoleCP,
            GetConsoleOutputCP, SetConsoleOutputCP,
        };

        const TEST_ENV_VAR_NAME: &str = "GCK_CORRUPTED_TEST";
        const TEST_CASES: [(u32, &str, &str); 25] = [
            (437, "ABCabc123!@#", "ABCabc123!@#"),
            (437, "Café", "Caf��"),
            (437, "€uro", "�uro"),
            (437, "\t\n\r\x0B\x0C", "\t\n\r\x0B\x0C"),
            (874, "ไทย", "???"),
            (932, "日本ごテスト★", "�ձ����ƥ��ȡ�"),
            (936, "中文测试～", "���Ĳ��ԡ�"),
            (949, "조선어 검측", "??? ??"),
            (949, "한국어 테스트", "??? ???"),
            (950, "中文測試！", "���Ĝyԇ��"),
            (1250, "Český", "?esky"),
            (1250, "Cześć", "Cze??"),
            (1251, "Русский тест", "������ܧڧ� ��֧��"),
            (1251, "Український тест", "���ܧ��?�ߧ��ܧڧ� ��֧��"),
            (1252, "Blåbærgrød", "Bl?b?rgr?d"),
            (1252, "Español", "Espa?ol"),
            (1252, "Français", "Fran?ais"),
            (1252, "Grüße", "Gr��?e"),
            (1253, "Ελληνικά", "���˦˦Ǧͦɦ�?"),
            (1254, "Türkçe", "T��rk?e"),
            (1255, "עברית", "?????"),
            (1256, "العربية", "???????"),
            (1257, "Latviešu", "Latvie?u"),
            (1258, "Tiếng Việt", "Ti?ng Vi?t"),
            (65001, "Emoji 絵文字：😀～", "Emoji �}���֣�??��"),
        ];
        let mut unique_codepages: Vec<u32> = TEST_CASES.iter().map(|(cp, _, _)| *cp).collect();
        unique_codepages.sort_unstable();
        unique_codepages.dedup();

        // Restore the original code page after the test, avoiding side effects on other tests
        struct CodePageGuard {
            original_cp: u32,
            original_output_cp: u32,
        }

        impl Drop for CodePageGuard {
            fn drop(&mut self) {
                unsafe {
                    SetConsoleCP(self.original_cp);
                    SetConsoleOutputCP(self.original_output_cp);
                }
                std::env::remove_var(TEST_ENV_VAR_NAME);
            }
        }

        let _guard = CodePageGuard {
            original_cp: unsafe { GetConsoleCP() },
            original_output_cp: unsafe { GetConsoleOutputCP() },
        };

        for (cp, input, expected) in TEST_CASES {
            unsafe {
                SetConsoleCP(cp);
            }
            c_putenv(TEST_ENV_VAR_NAME, input);

            // The output should not be affected by the current code page
            for codepage in &unique_codepages {
                unsafe {
                    windows_sys::Win32::System::Console::SetConsoleOutputCP(*codepage);
                }
                let bytes = c_getenv(TEST_ENV_VAR_NAME).unwrap_or_default();
                let actual = String::from_utf8_lossy(&bytes);
                assert_eq!(&actual, expected);
            }
        }
    }
}
