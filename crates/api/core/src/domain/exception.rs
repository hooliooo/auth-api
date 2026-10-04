use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Error)]
pub enum RepositoryWriteError {
    /// A unique field of the entity is already taken, e.g. `field` = "name"
    #[error("{entity} entity with {field} '{value}' already exists")]
    AlreadyExists {
        entity: String,
        field: &'static str,
        value: String,
    },
    #[error("Repository Error: {0}")]
    Failure(String),
}

#[derive(Debug, Error)]
pub enum RepositoryQueryError {
    #[error("{0} entity with id {1} was not found")]
    NotFound(String, Uuid),
}
