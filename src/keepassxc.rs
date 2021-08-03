pub mod errors;
pub mod messages;
use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize, Default, Debug)]
pub struct Group {
    pub name: String,
    pub uuid: String,
    pub children: Vec<Group>,
}

impl Group {
    pub fn new<T: Into<String>>(name: T, uuid: T) -> Self {
        Self {
            name: name.into(),
            uuid: uuid.into(),
            ..Default::default()
        }
    }
}
