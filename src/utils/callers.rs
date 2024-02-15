use crate::config::Caller;
#[allow(unused_imports)]
use crate::{debug, error, info, warn};
use anyhow::{anyhow, Result};
#[cfg(unix)]
use std::ops::Deref;
use std::path::PathBuf;
use sysinfo::{get_current_pid, ProcessRefreshKind, RefreshKind, System, UpdateKind};

#[derive(Debug)]
pub struct CurrentCaller {
    pub path: PathBuf,
    pub pid: u32,
    #[cfg(unix)]
    pub uid: u32,
    #[cfg(unix)]
    pub gid: u32,
    pub canonical_path: Option<PathBuf>,
}

impl CurrentCaller {
    pub fn new() -> Result<Self> {
        debug!("Collecting process info");
        let pid =
            get_current_pid().map_err(|s| anyhow!("Failed to retrieve current PID: {}", s))?;
        info!("PID: {}", pid);
        let mut system = System::new_with_specifics(
            RefreshKind::new().with_processes(
                ProcessRefreshKind::new()
                    .with_user(UpdateKind::OnlyIfNotSet)
                    .with_exe(UpdateKind::OnlyIfNotSet),
            ),
        );
        system.refresh_process(pid);
        let proc = system
            .process(pid)
            .ok_or_else(|| anyhow!("Failed to retrieve information of current process"))?;
        debug!("Collecting parent process info");
        let ppid = proc
            .parent()
            .ok_or_else(|| anyhow!("Failed to retrieve parent PID"))?;
        info!("PPID: {}", ppid);
        system.refresh_process(ppid);
        let pproc = system
            .process(ppid)
            .ok_or_else(|| anyhow!("Failed to retrieve information of parent process"))?;
        let ppath = pproc
            .exe()
            .ok_or_else(|| anyhow!("Failed to determine parent process path"))?;
        info!("Parent process path: {}", ppath.to_string_lossy());
        let canonical_ppath = ppath.canonicalize();
        if canonical_ppath.is_ok() {
            info!(
                "Canonical parent process path: {}",
                canonical_ppath.as_ref().unwrap().to_string_lossy()
            );
        } else {
            warn!("Failed to determine canonical parent process path");
        }
        Ok(Self {
            path: ppath.to_owned(),
            pid: ppid.as_u32(),
            #[cfg(unix)]
            uid: *pproc
                .user_id()
                .ok_or_else(|| anyhow!("Failed to retrieve parent process user ID"))?
                .deref(),
            #[cfg(unix)]
            gid: *pproc
                .group_id()
                .ok_or_else(|| anyhow!("Failed to retrieve parent process group ID"))?
                .deref(),
            canonical_path: canonical_ppath.ok(),
        })
    }

    pub fn matches(&self, caller: &Caller) -> bool {
        #[cfg(unix)]
        if caller.uid.map(|id| id != self.uid).unwrap_or(false)
            || caller.gid.map(|id| id != self.gid).unwrap_or(false)
        {
            return false;
        }
        if caller.canonicalize && self.canonical_path.is_some() {
            let canonical_caller = PathBuf::from(&caller.path).canonicalize();
            if canonical_caller
                .as_ref()
                .map(|p| p.to_string_lossy() != caller.path)
                .unwrap_or_else(|_| false)
            {
                info!(
                    "Canonical caller path: {}",
                    canonical_caller.as_ref().unwrap().to_string_lossy()
                );
            }
            if canonical_caller.is_ok()
                && self.canonical_path.as_ref().unwrap() == &canonical_caller.unwrap()
            {
                return true;
            }
        }
        caller.path == self.path.to_string_lossy()
    }

    pub fn command_to_add(&self, encrypt: bool) -> String {
        let mut command = format!("{} caller add", env!("CARGO_BIN_NAME"));
        #[cfg(not(windows))]
        {
            use std::fmt::Write;
            let _ = write!(command, " --uid {} --gid {}", self.uid, self.gid);
        }
        if let Some(ref canonical_path) = self.canonical_path {
            if canonical_path != &self.path {
                command += " --canonicalize";
            }
        }
        if encrypt {
            command += " --encrypt \"\"";
        }
        command + " " + &self.path.to_string_lossy()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MOCK_PROCESS_PATH: &str = "/usr/bin/false";

    #[test]
    fn test_00_path_check() {
        let current_caller = CurrentCaller {
            path: PathBuf::from(MOCK_PROCESS_PATH),
            pid: 1,
            #[cfg(unix)]
            uid: 1,
            #[cfg(unix)]
            gid: 1,
            canonical_path: None,
        };

        let caller_matches = Caller {
            path: MOCK_PROCESS_PATH.to_owned(),
            uid: None,
            gid: None,
            canonicalize: false,
        };
        assert!(current_caller.matches(&caller_matches));

        let caller_mismatches = Caller {
            path: MOCK_PROCESS_PATH.to_owned() + "1",
            uid: None,
            gid: None,
            canonicalize: false,
        };
        assert!(!current_caller.matches(&caller_mismatches));
    }

    #[test]
    #[cfg(unix)]
    fn test_01_unix_uid_gid_check() {
        let current_caller = CurrentCaller {
            path: PathBuf::from(MOCK_PROCESS_PATH),
            pid: 1,
            uid: 1,
            gid: 1,
            canonical_path: None,
        };

        let caller_matches = Caller {
            path: MOCK_PROCESS_PATH.to_owned(),
            uid: Some(1),
            gid: Some(1),
            canonicalize: false,
        };
        assert!(current_caller.matches(&caller_matches));

        let caller_mismatches = Caller {
            path: MOCK_PROCESS_PATH.to_owned(),
            uid: Some(2),
            gid: Some(1),
            canonicalize: false,
        };
        assert!(!current_caller.matches(&caller_mismatches));

        let caller_mismatches = Caller {
            path: MOCK_PROCESS_PATH.to_owned(),
            uid: Some(1),
            gid: Some(2),
            canonicalize: false,
        };
        assert!(!current_caller.matches(&caller_mismatches));
    }

    #[test]
    #[cfg(windows)]
    fn test_02_windows_uid_gid_ignored() {
        let current_caller = CurrentCaller {
            path: PathBuf::from(MOCK_PROCESS_PATH),
            pid: 1,
            canonical_path: None,
        };

        let caller_matches = Caller {
            path: MOCK_PROCESS_PATH.to_owned(),
            uid: Some(1),
            gid: Some(1),
            canonicalize: false,
        };
        assert!(current_caller.matches(&caller_matches));
    }

    #[test]
    #[cfg(unix)]
    fn test_03_generate_add_caller_command() {
        struct TestCase {
            path: String,
            canonical_path: Option<String>,
            uid: u32,
            gid: u32,
            encrypt: bool,
            want: String,
        }
        let cases = vec![
            TestCase {
                path: "/path/to/foo".to_string(),
                canonical_path: None,
                uid: 1,
                gid: 2,
                encrypt: false,
                want: "git-credential-keepassxc caller add --uid 1 --gid 2 /path/to/foo".to_string(),
            },
            TestCase {
                path: "/path/to/foo".to_string(),
                canonical_path: Some("/path/to/bar".to_string()),
                uid: 1,
                gid: 2,
                encrypt: false,
                want: "git-credential-keepassxc caller add --uid 1 --gid 2 --canonicalize /path/to/foo".to_string(),
            },
            TestCase {
                path: "/path/to/foo".to_string(),
                canonical_path: None,
                uid: 1,
                gid: 2,
                encrypt: true,
                want: "git-credential-keepassxc caller add --uid 1 --gid 2 --encrypt \"\" /path/to/foo".to_string(),
            },
            TestCase {
                path: "/path/to/foo".to_string(),
                canonical_path: Some("/path/to/bar".to_string()),
                uid: 1,
                gid: 2,
                encrypt: true,
                want: "git-credential-keepassxc caller add --uid 1 --gid 2 --canonicalize --encrypt \"\" /path/to/foo".to_string(),
            },
        ];
        for case in cases {
            let current_caller = CurrentCaller {
                path: PathBuf::from(case.path),
                pid: 1,
                uid: case.uid,
                gid: case.gid,
                canonical_path: case.canonical_path.map(PathBuf::from),
            };
            let actual = current_caller.command_to_add(case.encrypt);
            assert_eq!(case.want, actual);
        }
    }

    #[test]
    #[cfg(windows)]
    fn test_04_windows_generate_add_caller_command() {
        struct TestCase {
            path: String,
            canonical_path: Option<String>,
            encrypt: bool,
            want: String,
        }
        let cases = vec![
            TestCase {
                path: "/path/to/foo".to_string(),
                canonical_path: None,
                encrypt: false,
                want: "git-credential-keepassxc caller add /path/to/foo".to_string(),
            },
            TestCase {
                path: "/path/to/foo".to_string(),
                canonical_path: Some("/path/to/bar".to_string()),
                encrypt: false,
                want: "git-credential-keepassxc caller add --canonicalize /path/to/foo".to_string(),
            },
            TestCase {
                path: "/path/to/foo".to_string(),
                canonical_path: None,
                encrypt: true,
                want: "git-credential-keepassxc caller add --encrypt \"\" /path/to/foo".to_string(),
            },
            TestCase {
                path: "/path/to/foo".to_string(),
                canonical_path: Some("/path/to/bar".to_string()),
                encrypt: true,
                want:
                    "git-credential-keepassxc caller add --canonicalize --encrypt \"\" /path/to/foo"
                        .to_string(),
            },
        ];
        for case in cases {
            let current_caller = CurrentCaller {
                path: PathBuf::from(case.path),
                pid: 1,
                canonical_path: case.canonical_path.map(PathBuf::from),
            };
            let actual = current_caller.command_to_add(case.encrypt);
            assert_eq!(case.want, actual);
        }
    }

    #[test]
    fn test_05_get_current_caller() {
        let current_caller = CurrentCaller::new();
        assert!(current_caller.is_ok(), "{:?}", current_caller);
        if let Ok(current_caller) = current_caller {
            assert!(!current_caller.path.to_string_lossy().is_empty());
            assert!(current_caller.pid > 0);
        }
    }
}
