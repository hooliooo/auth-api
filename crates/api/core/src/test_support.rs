//! In-memory implementations of the core ports, for this crate's tests and for adapters' tests
//! through the `test-support` feature.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use async_trait::async_trait;
use kern::{
    application::event::EventPublisher,
    building_blocks::{aggregate::Aggregate, domain_event::DynDomainEvent, entity::Entity},
};

use crate::domain::{
    error::RepositoryWriteError,
    organization::{
        Organization, OrganizationId, events::CreatedOrganization,
        repository::OrganizationWriteRepository,
    },
    state::Create,
};

/// Stores organizations in memory, rejecting a taken id or name like the database does.
#[derive(Default)]
pub struct InMemoryOrganizationWriteRepository {
    names: Mutex<HashMap<OrganizationId, String>>,
    failure: Option<String>,
}

impl InMemoryOrganizationWriteRepository {
    /// A repository whose every write fails with `RepositoryWriteError::Failure(message)`.
    pub fn failing(message: impl Into<String>) -> Self {
        Self {
            names: Mutex::default(),
            failure: Some(message.into()),
        }
    }

    pub fn contains(&self, id: &OrganizationId) -> bool {
        self.names.lock().unwrap().contains_key(id)
    }

    pub fn len(&self) -> usize {
        self.names.lock().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[async_trait]
impl OrganizationWriteRepository for InMemoryOrganizationWriteRepository {
    async fn create(
        &self,
        organization: &Organization<Create>,
        _event: &CreatedOrganization,
    ) -> Result<(), RepositoryWriteError> {
        if let Some(message) = &self.failure {
            return Err(RepositoryWriteError::Failure(message.clone()));
        }

        let mut names = self.names.lock().unwrap();
        let already_exists = |field, value| RepositoryWriteError::AlreadyExists {
            entity: Organization::<Create>::type_name().to_owned(),
            field,
            value,
        };
        if names.contains_key(organization.id()) {
            return Err(already_exists("id", organization.id().value().to_string()));
        }
        if names.values().any(|name| name == organization.name()) {
            return Err(already_exists("name", organization.name().to_owned()));
        }

        names.insert(*organization.id(), organization.name().to_owned());
        Ok(())
    }
}

/// Keeps every published event so tests can inspect them.
#[derive(Default)]
pub struct RecordingEventPublisher {
    published: Mutex<Vec<(&'static str, Arc<dyn DynDomainEvent>)>>,
}

impl RecordingEventPublisher {
    pub fn published(&self) -> Vec<(&'static str, Arc<dyn DynDomainEvent>)> {
        self.published.lock().unwrap().clone()
    }
}

impl EventPublisher for RecordingEventPublisher {
    fn publish(&self, topic: &'static str, event: Arc<dyn DynDomainEvent>) {
        self.published.lock().unwrap().push((topic, event));
    }
}
