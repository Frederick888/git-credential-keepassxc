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

impl From<KeePassBoolean> for bool {
    fn from(v: KeePassBoolean) -> Self {
        v.0
    }
}

impl AsRef<bool> for KeePassBoolean {
    fn as_ref(&self) -> &bool {
        &self.0
    }
}

macro_rules! define_action {
    ([$(($variant:ident, $string:literal, $readable:literal),)*]) => {
        #[derive(Clone, Debug, PartialEq)]
        pub enum KeePassAction {
            $($variant,)*
        }

        impl KeePassAction {
            pub fn to_readable(&self) -> String {
                match *self {
                    $(Self::$variant => $readable.to_owned(),)*
                }
            }
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
    (
        ChangePublicKeys,
        "change-public-keys",
        "exchange public keys"
    ),
    (GetDatabaseHash, "get-databasehash", "get database hash"),
    (Associate, "associate", "associate"),
    (TestAssociate, "test-associate", "test associate"),
    (GeneratePassword, "generate-password", "generate password"),
    (GetLogins, "get-logins", "get logins"),
    (SetLogin, "set-login", "set logins"),
    (LockDatabase, "lock-database", "lock database"),
    (
        GetDatabaseGroups,
        "get-database-groups",
        "get database groups"
    ),
    (DatabaseLocked, "database-locked", "database locked"),
    (DatabaseUnlocked, "database-unlocked", "database unlocked"),
    (CreateNewGroup, "create-new-group", "create new group"),
    (GetTotp, "get-totp", "get TOTP"),
]);
