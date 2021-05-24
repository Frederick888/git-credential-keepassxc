use crate::config::Caller;
#[allow(unused_imports)]
use crate::{debug, error, info, warn};
use anyhow::{anyhow, Result};
use std::path::PathBuf;
use sysinfo::{get_current_pid, ProcessExt, RefreshKind, System, SystemExt};

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
        let pid =
            get_current_pid().map_err(|s| anyhow!("Failed to retrieve current PID: {}", s))?;
        info!("PID: {}", pid);
        let system = System::new_with_specifics(RefreshKind::new().with_processes());
        debug!("Collecting process info");
        let proc = system
            .get_process(pid)
            .ok_or_else(|| anyhow!("Failed to retrieve information of current process"))?;
        debug!("Collecting parent process info");
        let ppid = proc
            .parent()
            .ok_or_else(|| anyhow!("Failed to retrieve parent PID"))?;
        info!("PPID: {}", ppid);
        let pproc = system
            .get_process(ppid)
            .ok_or_else(|| anyhow!("Failed to retrieve parent process information"))?;
        let ppath = pproc.exe();
        info!("Parent process path: {}", ppath.to_string_lossy());
        let canonical_ppath = ppath.canonicalize();
        if canonical_ppath.is_ok() {
            info!(
                "Canonical parent process path: {}",
                canonical_ppath.as_ref().unwrap().to_string_lossy()
            );
        } else {
            warn!("Cannot determine canonical parent process path");
        }
        Ok(Self {
            path: ppath.to_owned(),
            pid: ppid as u32,
            #[cfg(unix)]
            uid: pproc.uid,
            #[cfg(unix)]
            gid: pproc.gid,
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
}

#[cfg(test)]
mod tests {
    use super::*;

    const MOCK_PROCESS_PATH: &'static str = "/usr/bin/false";

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
}
