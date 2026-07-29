use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Error)]
pub enum RepositoryWriteError {
    #[error("{0} entity with id {1} already exists")]
    AlreadyExists(String, Uuid),
    #[error("Repository Error: {0}")]
    Failure(String),
}

#[derive(Debug, Error)]
pub enum RepositoryQueryError {
    #[error("{0} entity with id {1} was not found")]
    NotFound(String, Uuid),
}
