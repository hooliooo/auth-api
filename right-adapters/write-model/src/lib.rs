use anyhow::{Context, Result};
use sqlx::PgPool;

use crate::organization::SQLOrganizationWriteRepository;

pub mod organization;

pub async fn database_setup(url: &str) -> Result<DatabaseState> {
    let pool = PgPool::connect(url)
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
        pool: PgPool,
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

    pub async fn get_db_pool() -> &'static PgPool {
        &TEST_ENV
            .get_or_init(|| async {
                // startup the module
                dbg!("Create Container");
                let container = Postgres::default()
                    .start()
                    .await
                    .expect("Cannot create Docker container with Postgres");

                dbg!("Created Container");
                let port = container
                    .get_host_port_ipv4(5432)
                    .await
                    .expect("Cannot get port from node");

                // prepare connection string
                let url = &format!("postgres://postgres:postgres@localhost:{}/postgres", port);

                dbg!("Connect to Pool");
                let pool = PgPool::connect(url).await.expect("Cannot create pool");
                dbg!("Conencted to Pool");
                dbg!("Migration running");
                sqlx::migrate!("./migrations")
                    .run(&pool)
                    .await
                    .expect("Cannot run migrations");
                dbg!("Migration finished");

                TestEnvironment { container, pool }
            })
            .await
            .pool
    }
}
