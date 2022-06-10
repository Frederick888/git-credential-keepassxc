use num_enum::FromPrimitive;
use serde::{Deserialize, Serialize};
use strum::AsRefStr;

#[derive(FromPrimitive, AsRefStr, Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum KeePassErrorCode {
    #[num_enum(default)]
    Unknown = 0,
    DatabaseNotOpened = 1,
    DatabaseHashNotReceived = 2,
    ClientPublicKeyNotReceived = 3,
    CannotDecryptMessage = 4,
    TimeoutOrNotConnected = 5,
    ActionCancelledOrDenied = 6,
    CannotEncryptMessage = 7,
    AssociationFailed = 8,
    KeyChangeFailed = 9,
    EncryptionKeyUnrecognized = 10,
    NoSavedDatabasesFound = 11,
    IncorrectAction = 12,
    EmptyMessageReceived = 13,
    NoUrlProvided = 14,
    NoLoginsFound = 15,
    NoGroupsFound = 16,
    CannotCreateNewGroup = 17,
}

impl Serialize for KeePassErrorCode {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&format!("{}", *self as u8))
    }
}

impl<'de> Deserialize<'de> for KeePassErrorCode {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let u = String::deserialize(deserializer)?
            .parse::<u8>()
            .unwrap_or(0u8);
        Ok(KeePassErrorCode::from(u))
    }
}
