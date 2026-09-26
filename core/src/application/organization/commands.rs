use std::collections::{HashMap, HashSet};

use uuid::Uuid;

use crate::domain::organization::OrganizationId;

#[derive(Debug, Clone)]
pub struct CreateOrganization {
    aggregate_id: OrganizationId,
    name: String,
    display_name: String,
    description: String,
    is_enabled: bool,
    attributes: HashMap<String, HashSet<String>>,
}

impl CreateOrganization {
    pub fn new(
        aggregate_id: Uuid,
        name: String,
        display_name: String,
        description: String,
        is_enabled: bool,
        attributes: HashMap<String, HashSet<String>>,
    ) -> Self {
        CreateOrganization {
            aggregate_id: OrganizationId::new(aggregate_id),
            name,
            display_name,
            description,
            is_enabled,
            attributes,
        }
    }

    pub fn aggregate_id(&self) -> &OrganizationId {
        &self.aggregate_id
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn display_name(&self) -> &str {
        &self.display_name
    }

    pub fn description(&self) -> &str {
        &self.description
    }

    pub fn is_enabled(&self) -> bool {
        self.is_enabled
    }

    pub fn attributes(&self) -> &HashMap<String, HashSet<String>> {
        &self.attributes
    }

    pub fn into_parts(
        self,
    ) -> (
        Uuid,
        String,
        String,
        String,
        bool,
        HashMap<String, HashSet<String>>,
    ) {
        (
            self.aggregate_id.value(),
            self.name,
            self.display_name,
            self.description,
            self.is_enabled,
            self.attributes,
        )
    }
}
