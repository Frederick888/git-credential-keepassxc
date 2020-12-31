use crate::config::Caller;
#[allow(unused_imports)]
use crate::{debug, error, info, warn};
use anyhow::{anyhow, Result};
use std::path::PathBuf;
use sysinfo::{get_current_pid, ProcessExt, System, SystemExt};

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
        let system = System::new_all();
        let proc = system
            .get_process(pid)
            .ok_or_else(|| anyhow!("Failed to retrieve information of current process"))?;
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
