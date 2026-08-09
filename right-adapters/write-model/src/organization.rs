use auth_core::domain::{
    exception::RepositoryWriteError,
    organization::{
        Organization, events::CreatedOrganization, repository::OrganizationWriteRepository,
    },
    state::Create,
};
use chrono::{DateTime, Utc};
use kern::building_blocks::{aggregate::Aggregate, entity::Entity};
use sqlx::{PgPool, prelude::FromRow, types::Uuid};

use crate::outbox::insert_outbox_message;

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
        event: &CreatedOrganization,
    ) -> Result<(), RepositoryWriteError> {
        let organization_id = organization.id().value();
        tracing::debug!(%organization_id, "Persisting organization");

        // Any early return below drops the transaction, which rolls it back.
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|err| RepositoryWriteError::Failure(err.to_string()))?;

        sqlx::query(
            "INSERT INTO organization_entity (id, name, display_name, description, is_enabled, version) \
            VALUES ($1, $2, $3, $4, $5, $6)",
        )
        .bind(organization_id)
        .bind(organization.name())
        .bind(organization.display_name())
        .bind(organization.description())
        .bind(organization.is_enabled())
        .bind(organization.version() as i64)
        .execute(&mut *transaction)
        .await
        .map_err(|err| match &err {
            // `name` is the organization's unique identifier in the domain, so a conflict
            // here means it already exists — the one failure the caller can act on.
            sqlx::Error::Database(database_error) if database_error.is_unique_violation() => {
                RepositoryWriteError::AlreadyExists(
                    Organization::<Create>::type_name().to_owned(),
                    organization_id,
                )
            }
            _ => RepositoryWriteError::Failure(err.to_string()),
        })?;

        // Flattened into parallel arrays so the attributes go in as one statement rather than
        // a round trip per value.
        let mut ids: Vec<Uuid> = Vec::new();
        let mut keys: Vec<&str> = Vec::new();
        let mut values: Vec<&str> = Vec::new();
        for (key, elements) in organization.attributes() {
            for element in elements {
                ids.push(Uuid::now_v7());
                keys.push(key.as_str());
                values.push(element.as_str());
            }
        }

        if !ids.is_empty() {
            sqlx::query(
                "INSERT INTO organization_attribute (id, key, value, organization_id) \
                SELECT id, key, value, $4 \
                FROM UNNEST($1::uuid[], $2::text[], $3::text[]) AS attribute(id, key, value)",
            )
            .bind(&ids)
            .bind(&keys)
            .bind(&values)
            .bind(organization_id)
            .execute(&mut *transaction)
            .await
            .map_err(|err| RepositoryWriteError::Failure(err.to_string()))?;
        }

        insert_outbox_message(
            &mut transaction,
            Organization::<Create>::type_name(),
            organization_id,
            event,
        )
        .await
        .map_err(|err| RepositoryWriteError::Failure(err.to_string()))?;

        transaction
            .commit()
            .await
            .map_err(|err| RepositoryWriteError::Failure(err.to_string()))?;

        tracing::debug!(
            %organization_id,
            attributes = ids.len(),
            "Persisted organization",
        );
        Ok(())
    }
}

#[derive(Clone, FromRow)]
pub struct OrganizationEntity {
    pub id: Uuid,
    pub name: String,
    pub display_name: String,
    pub description: String,
    pub is_enabled: bool,
    pub version: i64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
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

    use auth_core::domain::{
        exception::RepositoryWriteError,
        organization::{
            Organization, events::CreatedOrganization, repository::OrganizationWriteRepository,
        },
        state::Create,
    };
    use kern::building_blocks::{domain_event::DomainEvent, entity::Entity};
    use sqlx::types::JsonValue;
    use uuid::Uuid;

    use crate::{organization::SQLOrganizationWriteRepository, tests::get_db_pool};

    /// Every test shares one container and one schema, and `name` is now unique, so each test
    /// builds its organization under its own name and asserts only against its own id.
    fn organization(name: &str) -> (Organization<Create>, CreatedOrganization) {
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

        Organization::create(
            Uuid::now_v7(),
            name.to_owned(),
            "Organization A".to_owned(),
            "Some description".to_owned(),
            true,
            attributes,
            0,
        )
        .unwrap()
    }

    async fn organization_exists(pool: &sqlx::PgPool, id: Uuid) -> bool {
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM organization_entity WHERE id = $1)")
            .bind(id)
            .fetch_one(pool)
            .await
            .unwrap()
    }

    #[tokio::test]
    pub async fn create_organization_db_test() {
        let pool = get_db_pool().await;
        let repo = SQLOrganizationWriteRepository::new(pool.clone());
        let (organization, event) = organization("organization-a");
        let organization_id = organization.id().value();

        repo.create(&organization, &event).await.unwrap();

        assert!(organization_exists(&pool, organization_id).await);

        let attributes: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM organization_attribute WHERE organization_id = $1",
        )
        .bind(organization_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(3, attributes);

        let version: i64 =
            sqlx::query_scalar("SELECT version FROM organization_entity WHERE id = $1")
                .bind(organization_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(0, version);

        let (id, subject, status, payload): (String, String, String, JsonValue) = sqlx::query_as(
            "SELECT id, subject, status, payload FROM outbox_message WHERE aggregate_id = $1",
        )
        .bind(organization_id.to_string())
        .fetch_one(&pool)
        .await
        .unwrap();

        assert_eq!(event.id().value().to_string(), id);
        // `created-organization` is derived from the event's type name by the DomainEvent
        // macro, so this also pins that derivation.
        assert_eq!(
            "com.iam.organization.domain-events.created-organization",
            subject
        );
        // The state the processor claims from.
        assert_eq!("PENDING", status);

        assert_eq!(payload["name"], "organization-a");
        assert_eq!(payload["display_name"], "Organization A");
        assert_eq!(payload["aggregate_id"], organization_id.to_string());
        assert_eq!(payload["id"], event.id().value().to_string());
        assert_eq!(payload["aggregate_version"], 0);

        let mut values = payload["attributes"]["Custom Value 1"]
            .as_array()
            .expect("attributes should serialize as arrays")
            .iter()
            .map(|value| value.as_str().unwrap())
            .collect::<Vec<&str>>();
        values.sort();
        assert_eq!(vec!["ABC", "DEF"], values);
    }

    #[tokio::test]
    pub async fn creating_an_organization_whose_name_is_taken_reports_already_exists() {
        let pool = get_db_pool().await;
        let repo = SQLOrganizationWriteRepository::new(pool.clone());
        let (first, first_event) = organization("organization-c");
        repo.create(&first, &first_event).await.unwrap();

        // Same name, different id — the unique index on `name` is what has to catch this.
        let (second, second_event) = organization("organization-c");
        let error = repo.create(&second, &second_event).await.unwrap_err();

        assert!(
            matches!(error, RepositoryWriteError::AlreadyExists(ref kind, id)
                if kind == "organization" && id == second.id().value()),
            "expected AlreadyExists, got {error:?}",
        );
        assert!(!organization_exists(&pool, second.id().value()).await);
    }

    #[tokio::test]
    pub async fn a_failed_outbox_write_rolls_back_the_organization() {
        let pool = get_db_pool().await;
        let repo = SQLOrganizationWriteRepository::new(pool.clone());
        let (organization, event) = organization("organization-d");
        let organization_id = organization.id().value();

        // Claim the event's id first so the repository's own outbox insert hits the primary key.
        sqlx::query(
            "INSERT INTO outbox_message (id, aggregate_id, aggregate_type, subject, payload) \
            VALUES ($1, $2, 'organization', 'test.subject', '{}'::jsonb)",
        )
        .bind(event.id().value().to_string())
        .bind(Uuid::new_v4().to_string())
        .execute(&pool)
        .await
        .unwrap();

        let error = repo.create(&organization, &event).await.unwrap_err();
        assert!(matches!(error, RepositoryWriteError::Failure(_)));

        assert!(!organization_exists(&pool, organization_id).await);
        let attributes: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM organization_attribute WHERE organization_id = $1",
        )
        .bind(organization_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(0, attributes);
    }
}
