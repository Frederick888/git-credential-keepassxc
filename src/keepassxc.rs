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

    pub fn get_flat_groups<'a>(&'a self, mut parents: Vec<&'a str>) -> Vec<FlatGroup<'a>> {
        let flat_self = FlatGroup::new(&self.name, &self.uuid, &parents);
        parents.push(&self.name);
        let mut flat_groups = vec![flat_self];
        for child in &self.children {
            flat_groups.extend(child.get_flat_groups(parents.clone()));
        }
        flat_groups
    }
}

#[derive(Clone, Serialize, Deserialize, Default, Debug)]
pub struct FlatGroup<'a> {
    pub name: &'a str,
    pub uuid: &'a str,
    pub parents: Vec<&'a str>,
}

impl<'a> FlatGroup<'a> {
    pub fn new(name: &'a str, uuid: &'a str, parents: &[&'a str]) -> Self {
        Self {
            name,
            uuid,
            parents: Vec::from(parents),
        }
    }
}
