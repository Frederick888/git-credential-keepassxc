use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::prelude::*;
use std::path::Path;

#[derive(Serialize, Deserialize, Default, Debug)]
pub struct Config {
    pub databases: Vec<Database>,
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
        let json = serde_json::to_string(self)?;
        let mut file = fs::File::create(config_path.as_ref())?;
        file.write_all(&json.as_bytes())?;
        Ok(())
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Database {
    pub id: String,
    pub key: String,
    pub group: String,
    pub group_uuid: String,
    pub only_group: bool,
}
