use std::fmt;
use std::str::FromStr;

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
        #[derive(Default, Debug)]
        $vis struct $name {
            $($field_vis $field_name: $field_type,)*
        }

        impl ToString for $name {
            fn to_string(&self) -> String {
                let mut msg = String::new();
                $(
                    if let Some(ref value) = self.$field_name {
                        msg.push_str(stringify!($field_name));
                        msg.push('=');
                        msg.push_str(value);
                        msg.push('\n');
                    }
                )*
                msg.push('\n');
                msg
            }
        }

        impl FromStr for $name {
            type Err = GitMessageParsingError;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                let pairs: Vec<_> = s.split("\n").collect();
                let mut msg = $name { ..Default::default() };
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
                            _ => return Err(GitMessageParsingError {
                                message: format!("Unknown key {}", key),
                                source: s.to_owned(),
                            }),
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
    }
);
