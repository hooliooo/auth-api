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
    #[field]
    name: String,
    #[field]
    display_name: String,
    #[field]
    description: String,
    #[field(copy)]
    is_enabled: bool,
    #[field]
    attributes: HashMap<String, HashSet<String>>,
    occurred_on: DateTime<Utc>,
}

impl CreatedOrganization {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        aggregate_id: OrganizationId,
        aggregate_version: u32,
        name: String,
        display_name: String,
        description: String,
        is_enabled: bool,
        attributes: HashMap<String, HashSet<String>>,
        occurred_on: DateTime<Utc>,
    ) -> Self {
        Self {
            id: EventId::new(Uuid::new_v4()),
            aggregate_id,
            aggregate_version,
            name,
            display_name,
            description,
            is_enabled,
            attributes,
            occurred_on,
        }
    }
}
