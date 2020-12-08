use anyhow::Result;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

#[derive(Clone, Debug)]
pub struct KeePassBoolean(pub bool);

impl Serialize for KeePassBoolean {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(if self.0 { "true" } else { "false" })
    }
}

impl<'de> Deserialize<'de> for KeePassBoolean {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?.to_lowercase();
        match s.as_str() {
            "true" => Ok(KeePassBoolean(true)),
            "false" => Ok(KeePassBoolean(false)),
            _ => Err(serde::de::Error::custom(format!("Unknown boolean {}", s))),
        }
    }
}

impl Into<bool> for KeePassBoolean {
    fn into(self) -> bool {
        self.0
    }
}

impl AsRef<bool> for KeePassBoolean {
    fn as_ref(&self) -> &bool {
        &self.0
    }
}

macro_rules! define_action {
    ([$(($variant:ident, $string:literal),)*]) => {
        #[derive(Clone, Debug, PartialEq)]
        pub enum KeePassAction {
            $($variant,)*
        }

        impl ToString for KeePassAction {
            fn to_string(&self) -> String {
                match *self {
                    $(Self::$variant => $string.to_owned(),)*
                }
            }
        }

        impl Serialize for KeePassAction {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                serializer.serialize_str(match *self {
                    $(Self::$variant => $string,)*
                })
            }
        }

        impl<'de> Deserialize<'de> for KeePassAction {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                let s = String::deserialize(deserializer)?.to_lowercase();
                Ok(match s.as_str() {
                    $($string => Self::$variant,)*
                    _ => panic!("Unknown action: {}", s),
                })
            }
        }
    };
}

define_action!([
    (ChangePublicKeys, "change-public-keys"),
    (GetDatabaseHash, "get-databasehash"),
    (Associate, "associate"),
    (TestAssociate, "test-associate"),
    (GeneratePassword, "generate-password"),
    (GetLogins, "get-logins"),
    (SetLogin, "set-login"),
    (LockDatabase, "lock-database"),
    (GetDatabaseGroups, "get-database-groups"),
    (DatabaseLocked, "database-locked"),
    (DatabaseUnlocked, "database-unlocked"),
    (CreateNewGroup, "create-new-group"),
    (GetTotp, "get-totp"),
]);
