use super::messages::GenericResponseWrapper;
use std::error::Error;
use std::fmt::{self, Display, Formatter};

#[derive(Debug)]
pub struct KeePassError {
    pub message: String,
    pub response: GenericResponseWrapper,
}

impl KeePassError {
    pub fn is_database_locked(&self) -> bool {
        if let Some(error_message) = &self.response.error {
            error_message.contains("not opened")
        } else {
            false
        }
    }
}

impl Display for KeePassError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(self.message.as_str())?;
        Ok(())
    }
}

impl Error for KeePassError {}
