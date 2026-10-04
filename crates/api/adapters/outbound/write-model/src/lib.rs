use anyhow::{Context, Result};
use sqlx::{PgPool, postgres::PgPoolOptions};
use std::time::Duration;

use crate::organization::SQLOrganizationWriteRepository;

pub mod organization;
mod outbox;

/// The most connections the service will hold open against Postgres.
const MAX_CONNECTIONS: u32 = 10;
/// Connections kept warm so a request after an idle period does not pay for a new handshake.
const MIN_CONNECTIONS: u32 = 1;
/// How long a caller waits for a free connection before giving up. Without this a request
/// blocks indefinitely when the pool is exhausted; with it, saturation surfaces as an error.
const ACQUIRE_TIMEOUT: Duration = Duration::from_secs(5);

pub async fn database_setup(url: &str) -> Result<DatabaseState> {
    let pool = PgPoolOptions::new()
        .max_connections(MAX_CONNECTIONS)
        .min_connections(MIN_CONNECTIONS)
        .acquire_timeout(ACQUIRE_TIMEOUT)
        .connect(url)
        .await
        .context("Failed to connect to url")?;
    sqlx::migrate!("./migrations").run(&pool).await?;

    let organization_write_repository = SQLOrganizationWriteRepository::new(pool.clone());
    Ok(DatabaseState {
        pool,
        organization_write_repository,
    })
}

pub struct DatabaseState {
    pub pool: PgPool,
    pub organization_write_repository: SQLOrganizationWriteRepository,
}

#[cfg(test)]
mod tests {

    use dtor::dtor;
    use sqlx::PgPool;
    use testcontainers::{ContainerAsync, runners::AsyncRunner};
    use testcontainers_modules::postgres::Postgres;
    use tokio::sync::OnceCell;

    pub struct TestEnvironment {
        #[allow(dead_code)]
        pub container: ContainerAsync<Postgres>, // keeps container alive
        url: String,
    }

    pub static TEST_ENV: OnceCell<TestEnvironment> = OnceCell::const_new();

    /// This destructor is called at the end of the test suite run to properly clean up test
    /// container
    /// This method must be used due to the fact that in Rust, static variables never call drop
    /// which means the test container stays alive even after the Rust program exits
    /// See [docs](https://doc.rust-lang.org/reference/items/static-items.html)
    /// See https://github.com/testcontainers/testcontainers-rs/issues/707#issuecomment-2290859092
    #[dtor(unsafe)]
    fn clean_up() {
        let container_id = TEST_ENV.get().unwrap().container.id();
        std::process::Command::new("docker")
            .args(["container", "rm", "-f", container_id])
            .output()
            .expect("failed to stop testcontainer");
    }

    /// Returns a pool for the calling test, starting the shared container on first use.
    ///
    /// The pool is deliberately per-test rather than shared. Every `#[tokio::test]` runs on its
    /// own runtime, and a `PgPool` is bound to the runtime that created it: connections released
    /// from a different runtime never make it back, so one shared pool bleeds out after a few
    /// tests and later tests fail with `PoolTimedOut`. Only the container — the expensive part —
    /// is shared.
    pub async fn get_db_pool() -> PgPool {
        let environment = TEST_ENV
            .get_or_init(|| async {
                let container = Postgres::default()
                    .start()
                    .await
                    .expect("Cannot create Docker container with Postgres");

                let port = container
                    .get_host_port_ipv4(5432)
                    .await
                    .expect("Cannot get port from node");

                let url = format!("postgres://postgres:postgres@localhost:{}/postgres", port);

                // This pool exists only to migrate; it is dropped with the runtime that ran the
                // initialization, which is exactly why it must not be the one tests use.
                let pool = PgPool::connect(&url).await.expect("Cannot create pool");
                sqlx::migrate!("./migrations")
                    .run(&pool)
                    .await
                    .expect("Cannot run migrations");
                pool.close().await;

                TestEnvironment { container, url }
            })
            .await;

        PgPool::connect(&environment.url)
            .await
            .expect("Cannot create pool")
    }
}
