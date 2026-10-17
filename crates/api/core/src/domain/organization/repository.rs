use async_trait::async_trait;

use crate::domain::{
    error::RepositoryWriteError,
    organization::{CreatedOrganization, Organization},
    state::Create,
};

#[async_trait]
pub trait OrganizationWriteRepository: Send + Sync {
    async fn create(
        &self,
        organization: &Organization<Create>,
        event: &CreatedOrganization,
    ) -> Result<(), RepositoryWriteError>;
}
