use async_trait::async_trait;

use crate::domain::{
    exception::RepositoryWriteError,
    organization::{CreatedOrganization, Organization},
    state::Create,
};

#[cfg_attr(test, mockall::automock)]
#[async_trait]
pub trait OrganizationWriteRepository: Send + Sync {
    async fn create(
        &self,
        organization: &Organization<Create>,
        event: &CreatedOrganization,
    ) -> Result<(), RepositoryWriteError>;
}
