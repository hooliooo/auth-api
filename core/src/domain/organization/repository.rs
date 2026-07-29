use async_trait::async_trait;

use crate::domain::{exception::RepositoryWriteError, organization::Organization, state::Create};

#[cfg_attr(test, mockall::automock)]
#[async_trait]
pub trait OrganizationWriteRepository: Send + Sync {
    async fn create(&self, organization: &Organization<Create>)
    -> Result<(), RepositoryWriteError>;
}
