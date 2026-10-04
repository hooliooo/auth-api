//! Writing domain events to the transactional outbox.
//!
//! Every repository that emits an event calls [`insert_outbox_message`] on the same
//! transaction it writes the aggregate with, so the row and the event commit together.

use kern::building_blocks::domain_event::DomainEvent;
use serde::Serialize;
use sqlx::{PgConnection, types::Json};
use uuid::Uuid;

/// The prefix every subject this service publishes under shares, matching the convention
/// already used by the IAM outbox messages (`com.iam.user.domain-events.created-user`).
const SUBJECT_PREFIX: &str = "com.iam";

/// Builds the NATS subject an event is published under, as
/// `com.iam.<aggregate_type>.domain-events.<event_type>`.
///
/// # Arguments
/// * `aggregate_type` - The aggregate the event belongs to, e.g. `organization`
/// * `event_type`     - The event's own name, e.g. `created-organization`
fn subject_for(aggregate_type: &str, event_type: &str) -> String {
    format!("{SUBJECT_PREFIX}.{aggregate_type}.domain-events.{event_type}")
}

/// Writes `event` to the outbox on the given transaction.
///
/// Generic over the event so that adding an event type costs nothing here: anything deriving
/// `DomainEvent` is serializable (kern's derive emits the `Serialize` impl) and so can be
/// written without a per-event row struct or mapping.
///
/// The remaining columns are left to their defaults: a new message is `PENDING` with a
/// `created_at` of te current time in UTC, `retry_count` of 0 and no lease
///
/// # Arguments
/// * `transaction`    - The transaction the aggregate is being written on
/// * `aggregate_type` - The aggregate the event belongs to, from `Aggregate::type_name`
/// * `aggregate_id`   - The identifier of the aggregate the event belongs to
/// * `event`          - The domain event to store
pub(crate) async fn insert_outbox_message<Event>(
    transaction: &mut PgConnection,
    aggregate_type: &str,
    aggregate_id: Uuid,
    event: &Event,
) -> Result<(), sqlx::Error>
where
    Event: DomainEvent + Serialize,
{
    let subject = subject_for(aggregate_type, event.event_type());

    sqlx::query(
        "INSERT INTO outbox_message \
        (id, aggregate_id, aggregate_type, subject, payload) \
        VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(event.id().value().to_string())
    .bind(aggregate_id.to_string())
    .bind(aggregate_type)
    .bind(&subject)
    .bind(Json(event))
    .execute(transaction)
    .await?;

    Ok(())
}
