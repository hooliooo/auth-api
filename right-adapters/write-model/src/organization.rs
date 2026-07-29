use auth_core::domain::{
    exception::RepositoryWriteError,
    organization::{Organization, repository::OrganizationWriteRepository},
    state::Create,
};
use chrono::{DateTime, Utc};
use kern::building_blocks::entity::Entity;
use sqlx::{PgPool, prelude::FromRow, types::Uuid};

#[derive(Clone)]
pub struct SQLOrganizationWriteRepository {
    pool: PgPool,
}

impl SQLOrganizationWriteRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait::async_trait]
impl OrganizationWriteRepository for SQLOrganizationWriteRepository {
    async fn create(
        &self,
        organization: &Organization<Create>,
    ) -> Result<(), RepositoryWriteError> {
        dbg!("Persisting Organization");
        let mut transaction = self.pool.begin().await.unwrap();
        let result: Result<Uuid, sqlx::Error> = sqlx::query_scalar(
            "INSERT INTO organization_entity (id, name, display_name) \
            VALUES ($1, $2, $3) \
            RETURNING id",
        )
        .bind(organization.id().value())
        .bind(organization.name().clone())
        .bind(organization.display_name().clone())
        .fetch_one(&mut *transaction)
        .await;

        match result {
            Ok(id) => {
                dbg!(format_args!(
                    "Organization saved to database with id: {}",
                    id
                ));
            }
            Err(err) => return Err(RepositoryWriteError::Failure(err.to_string())),
        }

        for (key, elements) in organization.attributes() {
            for element in elements {
                let id: Uuid = sqlx::query_scalar(
                    "INSERT INTO organization_attribute (id, key, value, organization_id) \
                    VALUES ($1, $2, $3, $4) \
                    RETURNING id",
                )
                .bind(Uuid::now_v7())
                .bind(key.clone())
                .bind(element.clone())
                .bind(organization.id().value())
                .fetch_one(&mut *transaction)
                .await
                .unwrap();

                dbg!(format_args!(
                    "Organization Attribute key: '{}', value '{}' saved to database with id '{}'",
                    key.clone(),
                    element.clone(),
                    id
                ));
            }
        }

        transaction.commit().await.unwrap();
        Ok(())
    }
}

#[derive(Clone, FromRow)]
pub struct OrganizationEntity {
    pub id: Uuid,
    pub name: String,
    pub display_name: String,
    pub created_at: DateTime<Utc>,
    pub version: i64,
}

#[derive(Clone, FromRow)]
pub struct OrganizationAttribute {
    pub id: Uuid,
    pub key: String,
    pub value: String,
    pub organization_id: Uuid,
}

#[cfg(test)]
mod tests {
    use std::collections::{HashMap, HashSet};

    use auth_core::domain::organization::{Organization, repository::OrganizationWriteRepository};
    use kern::building_blocks::entity::Entity;
    use uuid::Uuid;

    use crate::{organization::SQLOrganizationWriteRepository, tests::get_db_pool};

    #[tokio::test]
    pub async fn create_organization_db_test() {
        let pool = get_db_pool().await;
        let repo = SQLOrganizationWriteRepository::new(pool.clone());

        let attributes: HashMap<String, HashSet<String>> = vec![
            (
                "Custom Value 1".to_string(),
                vec!["ABC".to_string(), "DEF".to_string()]
                    .into_iter()
                    .collect(),
            ),
            (
                "Custom Value 2".to_string(),
                vec!["GHI".to_string()].into_iter().collect(),
            ),
        ]
        .into_iter()
        .collect();

        let organization = Organization::try_new(
            Uuid::new_v4(),
            "organization-a".to_owned(),
            "Organization A".to_owned(),
            attributes,
            0,
        )
        .unwrap();

        let result: Result<i64, sqlx::Error> =
            sqlx::query_scalar("SELECT COUNT(*) FROM organization_entity")
                .fetch_one(pool)
                .await;
        let count = result.unwrap();
        assert_eq!(0, count);

        repo.create(&organization).await.unwrap();

        let result: Result<i64, sqlx::Error> =
            sqlx::query_scalar("SELECT COUNT(*) FROM organization_entity")
                .fetch_one(pool)
                .await;
        let count = result.unwrap();
        assert_eq!(1, count);

        let exists: bool =
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM organization_entity WHERE id = $1)")
                .bind(organization.id().value())
                .fetch_one(pool)
                .await
                .unwrap();
        assert!(exists);

        let result: Result<i64, sqlx::Error> = sqlx::query_scalar(
            "SELECT COUNT(*) FROM organization_attribute WHERE organization_id = $1",
        )
        .bind(organization.id().value())
        .fetch_one(pool)
        .await;
        let count = result.unwrap();
        assert_eq!(3, count);
    }
}
