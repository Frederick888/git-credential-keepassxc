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

    pub fn get_flat_groups(&self) -> Vec<FlatGroup> {
        let flat_self = FlatGroup::new(&self.name, &self.uuid);
        let mut flat_groups = vec![flat_self];
        for child in &self.children {
            flat_groups.extend(child.get_flat_groups());
        }
        flat_groups
    }
}

#[derive(Clone, Serialize, Deserialize, Default, Debug)]
pub struct FlatGroup {
    pub name: String,
    pub uuid: String,
}

impl FlatGroup {
    pub fn new<T: Into<String>>(name: T, uuid: T) -> Self {
        Self {
            name: name.into(),
            uuid: uuid.into(),
        }
    }
}
