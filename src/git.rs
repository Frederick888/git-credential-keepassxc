#[allow(unused_imports)]
use crate::{debug, error, info, warn};
use serde::Serialize;
use std::collections::HashMap;
use std::fmt;
use std::io::{self, Read};
use std::str::FromStr;

const KPXC_ADVANCED_FIELD_PREFIX: &str = "KPH: ";

#[derive(Debug)]
pub struct GitMessageParsingError {
    message: String,
    source: String,
}

impl fmt::Display for GitMessageParsingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Failed to parse Git credential message: {}\nOriginal message:\n{}",
            self.message, self.source
        )
    }
}

impl std::error::Error for GitMessageParsingError {}

macro_rules! message_from_to_string {
    ($vis:vis struct $name:ident {
        $($field_vis:vis $field_name:ident: $field_type:ty,)*
    }) => {
        #[derive(Default, Serialize, Debug)]
        $vis struct $name {
            $(
                #[serde(skip_serializing_if = "Option::is_none")]
                $field_vis $field_name: $field_type,
            )*
            #[serde(skip_serializing_if = "Option::is_none")]
            pub string_fields: Option<HashMap<String, String>>,
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                let mut msg = String::new();
                $(
                    if let Some(ref value) = self.$field_name {
                        msg.push_str(stringify!($field_name));
                        msg.push('=');
                        msg.push_str(value);
                        msg.push('\n');
                    }
                )*
                if let Some(ref string_fields) = self.string_fields {
                    for (key, value) in string_fields {
                        msg.push_str(key);
                        msg.push('=');
                        msg.push_str(value);
                        msg.push('\n');
                    }
                }
                msg.push('\n');
                write!(f, "{}", msg)
            }
        }

        impl FromStr for $name {
            type Err = GitMessageParsingError;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                let pairs: Vec<_> = s.split("\n").collect();
                let mut msg = $name::default();
                for pair in pairs {
                    if pair.len() == 0 {
                        continue;
                    }
                    let split_at = pair.find('=').ok_or(Self::Err {
                        message: "Equal sign not found in line".to_owned(),
                        source: s.to_owned(),
                    })?;
                    let key = &pair[..split_at];
                    match key {
                        $(
                            stringify!($field_name) => {
                                msg.$field_name = Some(pair[split_at + 1..].to_owned());
                            },
                        )*
                            _ => {},
                    }
                }
                Ok(msg)
            }
        }
    }
}

message_from_to_string!(
    pub struct GitCredentialMessage {
        pub protocol: Option<String>,
        pub host: Option<String>,
        pub path: Option<String>,
        pub username: Option<String>,
        pub password: Option<String>,
        pub url: Option<String>,
        pub totp: Option<String>,
    }
);

impl GitCredentialMessage {
    pub fn from_stdin() -> anyhow::Result<Self> {
        let git_req = {
            let mut git_req_string = String::with_capacity(256);
            io::stdin().read_to_string(&mut git_req_string)?;
            GitCredentialMessage::from_str(&git_req_string)?
        };
        debug!("Git credential request: {:?}", git_req);
        Ok(git_req)
    }

    pub fn set_string_fields(&mut self, login_entry_fields: &[HashMap<String, String>]) {
        let mut result = HashMap::new();
        login_entry_fields.iter().for_each(|login_entry_field| {
            for (key, value) in login_entry_field {
                if key.len() < KPXC_ADVANCED_FIELD_PREFIX.len()
                    || &key[..KPXC_ADVANCED_FIELD_PREFIX.len()] != KPXC_ADVANCED_FIELD_PREFIX
                {
                    warn!("Ignored advanced field {} due to malformed key", key);
                } else {
                    result.insert(
                        key[KPXC_ADVANCED_FIELD_PREFIX.len()..].to_string(),
                        value.clone(),
                    );
                }
            }
        });
        self.string_fields = Some(result);
    }

    pub fn get_url(&self) -> anyhow::Result<String> {
        if let Some(ref url_string) = self.url {
            Ok(url_string.clone())
        } else {
            if self.protocol.is_none() || self.host.is_none() {
                return Err(anyhow::anyhow!(
                    "Protocol and host are both required when URL is not provided"
                ));
            }
            Ok(format!(
                "{}://{}/{}",
                self.protocol.as_deref().unwrap(),
                self.host.as_deref().unwrap(),
                self.path.as_deref().unwrap_or("")
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_00_url_message() {
        let string = "url=http://example.com\n".to_owned();
        let message = GitCredentialMessage::from_str(string.as_str()).unwrap();
        assert!(message.url.is_some());
        assert_eq!(message.url.as_ref().unwrap().as_str(), "http://example.com");
        assert_eq!(string + "\n", message.to_string());
    }

    #[test]
    fn test_01_url_username_message() {
        let string = "username=foo\nurl=http://example.com\n".to_owned();
        let message = GitCredentialMessage::from_str(string.as_str()).unwrap();
        assert!(message.url.is_some());
        assert_eq!(message.url.as_ref().unwrap().as_str(), "http://example.com");
        assert!(message.username.is_some());
        assert_eq!(message.username.as_ref().unwrap().as_str(), "foo");
        assert_eq!(string + "\n", message.to_string());
    }

    #[test]
    fn test_02_advanced_fields() {
        let string1 = "username=foo\nurl=http://example.com\n".to_owned();
        let string2 = "advanced_field1=foo\n".to_owned();
        let mut message = GitCredentialMessage::from_str(string1.as_str()).unwrap();
        let advanced_fields: Vec<HashMap<String, String>> = [("KPH: advanced_field1", "foo")]
            .iter()
            .map(|(key, value)| {
                let mut advanced_field = HashMap::new();
                advanced_field.insert(key.to_string(), value.to_string());
                advanced_field
            })
            .collect();
        message.set_string_fields(&advanced_fields);
        assert_eq!(string1 + &string2 + "\n", message.to_string());
    }

    #[test]
    fn test_03_ignore_unknown_fields() {
        let string = "url=http://example.com\nfoo=bar\n".to_owned();
        let message = GitCredentialMessage::from_str(string.as_str()).unwrap();
        assert!(message.url.is_some());
        assert_eq!(message.url.as_ref().unwrap().as_str(), "http://example.com");
        assert_eq!(
            "url=http://example.com\n\n".to_string(),
            message.to_string()
        );
    }
}
