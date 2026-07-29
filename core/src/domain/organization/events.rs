use std::collections::{HashMap, HashSet};

use chrono::{DateTime, Utc};
use kern::{DomainEvent, building_blocks::ids::EventId};
use uuid::Uuid;

use crate::domain::organization::OrganizationId;

#[derive(DomainEvent)]
pub struct CreatedOrganization {
    id: EventId,
    aggregate_id: OrganizationId,
    aggregate_version: u32,
    name: String,
    display_name: String,
    attributes: HashMap<String, HashSet<String>>,
    occurred_at: DateTime<Utc>,
}

impl CreatedOrganization {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        aggregate_id: OrganizationId,
        aggregate_version: u32,
        name: String,
        display_name: String,
        attributes: HashMap<String, HashSet<String>>,
        occurred_at: DateTime<Utc>,
    ) -> Self {
        Self {
            id: EventId::new(Uuid::new_v4()),
            aggregate_id,
            aggregate_version,
            name,
            display_name,
            attributes,
            occurred_at,
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

    pub fn attributes(&self) -> &HashMap<String, HashSet<String>> {
        &self.attributes
    }
}

pub const CREATED_ORGANIZATION: &str = "created-organization";
