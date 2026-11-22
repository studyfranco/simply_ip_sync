//! Applies ordered `SeaQuery` migrations and records their versions in the existing ledger.

use sea_orm::sea_query::{
    ForeignKeyDropStatement, IndexCreateStatement, IndexDropStatement, SelectStatement,
    TableAlterStatement, TableCreateStatement, TableDropStatement, TableRenameStatement,
};
use sea_orm::{
    ActiveModelTrait, ConnectionTrait, DatabaseBackend, DatabaseExecutor, DbErr, EntityTrait,
    IntoDatabaseExecutor, Schema, Set, StatementBuilder, TransactionTrait,
};
use sea_schema::probe::SchemaProbe;

mod ledger {
    use sea_orm::entity::prelude::*;

    #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
    #[sea_orm(table_name = "seaql_migrations")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub version: String,
        pub applied_at: i64,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

/// A database connection or transaction used to execute typed migration statements.
pub struct SchemaManager<'a>(DatabaseExecutor<'a>);

macro_rules! schema_operations {
    ($($name:ident: $statement:ty),* $(,)?) => {$(
        #[doc = concat!("Executes a typed `", stringify!($statement), "` statement.")]
        ///
        /// # Errors
        /// Returns the database error if execution fails.
        pub async fn $name(&self, statement: $statement) -> Result<(), DbErr> {
            self.exec_stmt(statement).await
        }
    )*};
}

impl<'a> SchemaManager<'a> {
    /// Creates a schema manager backed by the given connection or transaction.
    pub fn new(connection: impl IntoDatabaseExecutor<'a>) -> Self {
        Self(connection.into_database_executor())
    }

    /// Returns the underlying database executor.
    #[must_use]
    pub fn get_connection(&self) -> &DatabaseExecutor<'a> {
        &self.0
    }

    /// Returns the active SQL backend.
    #[must_use]
    pub fn get_database_backend(&self) -> DatabaseBackend {
        self.0.get_database_backend()
    }

    /// Executes a `SeaQuery` statement.
    ///
    /// # Errors
    /// Returns the database error if execution fails.
    pub async fn exec_stmt(&self, statement: impl StatementBuilder) -> Result<(), DbErr> {
        self.0.execute(&statement).await.map(|_| ())
    }

    schema_operations!(
        create_table: TableCreateStatement,
        drop_table: TableDropStatement,
        rename_table: TableRenameStatement,
        alter_table: TableAlterStatement,
        create_index: IndexCreateStatement,
        drop_index: IndexDropStatement,
        drop_foreign_key: ForeignKeyDropStatement,
    );

    /// Checks whether an index exists on the given table.
    ///
    /// # Errors
    /// Returns a database error if schema inspection fails.
    pub async fn has_index(&self, table: &str, index: &str) -> Result<bool, DbErr> {
        let query: SelectStatement = match self.get_database_backend() {
            DatabaseBackend::MySql => sea_schema::mysql::MySql.has_index(table, index),
            DatabaseBackend::Postgres => sea_schema::postgres::Postgres.has_index(table, index),
            DatabaseBackend::Sqlite => sea_schema::sqlite::Sqlite.has_index(table, index),
            backend => {
                return Err(DbErr::BackendNotSupported {
                    db: backend.as_str(),
                    ctx: "index probe",
                });
            }
        };
        self.0
            .query_one(&query)
            .await?
            .ok_or_else(|| DbErr::Custom("index probe returned no row".into()))?
            .try_get("", "has_index")
    }
}

/// One versioned schema or data change.
#[async_trait::async_trait]
pub trait MigrationTrait: Send + Sync {
    /// Returns the stable version recorded in the migration ledger.
    fn name(&self) -> &'static str;

    /// Applies the migration.
    ///
    /// # Errors
    /// Returns the database error if the migration fails.
    async fn up(&self, manager: &SchemaManager<'_>) -> Result<(), DbErr>;

    /// Reverses the migration.
    ///
    /// # Errors
    /// Returns the database error if the rollback fails.
    async fn down(&self, manager: &SchemaManager<'_>) -> Result<(), DbErr>;
}

/// Whether a known migration is present in the ledger.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MigrationStatus {
    /// The version has been applied.
    Applied,
    /// The version is awaiting execution.
    Pending,
}

/// A known migration and its recorded status.
pub struct Migration {
    migration: Box<dyn MigrationTrait>,
    status: MigrationStatus,
}

impl Migration {
    /// Returns the migration's stable version.
    #[must_use]
    pub fn name(&self) -> &'static str {
        self.migration.name()
    }

    /// Returns the migration's recorded status.
    #[must_use]
    pub fn status(&self) -> MigrationStatus {
        self.status
    }
}

/// Runs an ordered set of migrations against the application database.
#[async_trait::async_trait]
pub trait MigratorTrait: Send {
    /// Returns the migrations in application order.
    fn migrations() -> Vec<Box<dyn MigrationTrait>>;

    /// Returns known versions alongside their current ledger status.
    ///
    /// # Errors
    /// Returns a database error if the ledger cannot be created or read.
    async fn get_migration_with_status(db: &impl ConnectionTrait) -> Result<Vec<Migration>, DbErr> {
        let mut table =
            Schema::new(db.get_database_backend()).create_table_from_entity(ledger::Entity);
        db.execute(table.if_not_exists()).await?;
        let mut applied: std::collections::BTreeSet<_> = ledger::Entity::find()
            .all(db)
            .await?
            .into_iter()
            .map(|row| row.version)
            .collect();
        let migrations = Self::migrations()
            .into_iter()
            .map(|migration| {
                let status = if applied.remove(migration.name()) {
                    MigrationStatus::Applied
                } else {
                    MigrationStatus::Pending
                };
                Migration { migration, status }
            })
            .collect();
        if !applied.is_empty() {
            return Err(DbErr::Custom(format!(
                "unknown applied migration versions: {applied:?}"
            )));
        }
        Ok(migrations)
    }

    /// Returns pending migrations in application order.
    ///
    /// # Errors
    /// Returns a database error if the ledger is unavailable.
    async fn get_pending_migrations(db: &impl ConnectionTrait) -> Result<Vec<Migration>, DbErr> {
        let mut migrations = Self::get_migration_with_status(db).await?;
        migrations.retain(|migration| migration.status == MigrationStatus::Pending);
        Ok(migrations)
    }

    /// Returns applied migrations in application order.
    ///
    /// # Errors
    /// Returns a database error if the ledger is unavailable.
    async fn get_applied_migrations(db: &impl ConnectionTrait) -> Result<Vec<Migration>, DbErr> {
        let mut migrations = Self::get_migration_with_status(db).await?;
        migrations.retain(|migration| migration.status == MigrationStatus::Applied);
        Ok(migrations)
    }

    /// Logs each known migration's status.
    ///
    /// # Errors
    /// Returns a database error if the ledger is unavailable.
    async fn status(db: &impl ConnectionTrait) -> Result<(), DbErr> {
        for entry in Self::get_migration_with_status(db).await? {
            tracing::info!(version = entry.name(), status = ?entry.status(), "migration status");
        }
        Ok(())
    }

    /// Applies up to `steps` pending migrations, or all of them if no limit is given.
    ///
    /// # Errors
    /// Returns a database error if a migration or its ledger update fails.
    async fn up(
        db: impl IntoDatabaseExecutor<'async_trait>,
        steps: Option<u32>,
    ) -> Result<(), DbErr> {
        let manager = SchemaManager::new(db);
        let pending = Self::get_pending_migrations(manager.get_connection()).await?;
        for entry in pending.into_iter().take(step_limit(steps)) {
            execute_migration(&manager, &entry, MigrationStatus::Applied).await?;
        }
        Ok(())
    }

    /// Reverses up to `steps` applied migrations, newest first.
    ///
    /// # Errors
    /// Returns a database error if a rollback or its ledger update fails.
    async fn down(
        db: impl IntoDatabaseExecutor<'async_trait>,
        steps: Option<u32>,
    ) -> Result<(), DbErr> {
        let manager = SchemaManager::new(db);
        let applied = Self::get_applied_migrations(manager.get_connection()).await?;
        for entry in applied.into_iter().rev().take(step_limit(steps)) {
            execute_migration(&manager, &entry, MigrationStatus::Pending).await?;
        }
        Ok(())
    }
}

fn step_limit(steps: Option<u32>) -> usize {
    steps
        .and_then(|limit| usize::try_from(limit).ok())
        .unwrap_or(usize::MAX)
}

async fn execute_migration(
    manager: &SchemaManager<'_>,
    entry: &Migration,
    target: MigrationStatus,
) -> Result<(), DbErr> {
    // MySQL commits DDL implicitly. PostgreSQL and SQLite can commit the ledger with the schema.
    if manager.get_database_backend() == DatabaseBackend::MySql {
        return change_migration(manager, entry, target).await;
    }

    let transaction = manager.get_connection().begin().await?;
    match change_migration(&SchemaManager::new(&transaction), entry, target).await {
        Ok(()) => transaction.commit().await,
        Err(error) => {
            transaction.rollback().await?;
            Err(error)
        }
    }
}

async fn change_migration(
    manager: &SchemaManager<'_>,
    entry: &Migration,
    target: MigrationStatus,
) -> Result<(), DbErr> {
    let db = manager.get_connection();
    let version = entry.name().to_owned();
    match target {
        MigrationStatus::Applied => {
            entry.migration.up(manager).await?;
            ledger::ActiveModel {
                version: Set(version),
                applied_at: Set(time::OffsetDateTime::now_utc().unix_timestamp()),
            }
            .insert(db)
            .await?;
        }
        MigrationStatus::Pending => {
            entry.migration.down(manager).await?;
            ledger::Entity::delete_by_id(version).exec(db).await?;
        }
    }
    Ok(())
}
