//! Adds scheduling, lookup, and temporal indexes across all core entities.
//!
//! Hot paths optimized by this migration:
//! - Scheduler boot & reload: `destination_groups(is_active)` and `vault_sync_tasks(is_active)`.
//! - Temporal sorting: `last_run_at`, `last_sync_at`, and `created_at` timestamps on resources.
//! - Execution log filtering: `sync_logs(status, timestamp DESC)` and `sync_logs(job_type, timestamp DESC)`.
//! - Granular permission lookups: `api_key_sync_permissions(resource_type, resource_id)`.
//! - Master key lookups & validation: `api_keys(is_master)`.

use super::runner::{MigrationTrait, SchemaManager};
use sea_orm::sea_query::{Index, IndexOrder};
use sea_orm::{DbErr, DeriveIden};

pub struct Migration;

#[derive(DeriveIden)]
enum DestinationGroups {
    Table,
    IsActive,
    LastRunAt,
    CreatedAt,
}

#[derive(DeriveIden)]
enum VaultSyncTasks {
    Table,
    IsActive,
    LastSyncAt,
    CreatedAt,
}

#[derive(DeriveIden)]
enum SyncLogs {
    Table,
    Status,
    JobType,
    Timestamp,
}

#[derive(DeriveIden)]
enum ApiKeySyncPermissions {
    Table,
    ResourceType,
    ResourceId,
}

#[derive(DeriveIden)]
enum ApiKeys {
    Table,
    IsMaster,
    CreatedAt,
}

#[derive(DeriveIden)]
enum VaultEndpoints {
    Table,
    CreatedAt,
}

#[derive(DeriveIden)]
enum ExternalSources {
    Table,
    CreatedAt,
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    fn name(&self) -> &'static str {
        stringify!(m20261110_000001_add_scheduling_and_lookup_indexes)
    }

    async fn up(&self, manager: &SchemaManager<'_>) -> Result<(), DbErr> {
        create_job_indexes(manager).await?;
        create_lookup_indexes(manager).await
    }

    async fn down(&self, manager: &SchemaManager<'_>) -> Result<(), DbErr> {
        drop_lookup_indexes(manager).await?;
        drop_job_indexes(manager).await
    }
}

async fn create_job_indexes(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    manager
        .create_index(
            Index::create()
                .name("idx_destination_groups_is_active")
                .table(DestinationGroups::Table)
                .col(DestinationGroups::IsActive)
                .to_owned(),
        )
        .await?;
    manager
        .create_index(
            Index::create()
                .name("idx_destination_groups_last_run_at")
                .table(DestinationGroups::Table)
                .col((DestinationGroups::LastRunAt, IndexOrder::Desc))
                .to_owned(),
        )
        .await?;
    manager
        .create_index(
            Index::create()
                .name("idx_destination_groups_created_at")
                .table(DestinationGroups::Table)
                .col((DestinationGroups::CreatedAt, IndexOrder::Desc))
                .to_owned(),
        )
        .await?;
    manager
        .create_index(
            Index::create()
                .name("idx_vault_sync_tasks_is_active")
                .table(VaultSyncTasks::Table)
                .col(VaultSyncTasks::IsActive)
                .to_owned(),
        )
        .await?;
    manager
        .create_index(
            Index::create()
                .name("idx_vault_sync_tasks_last_sync_at")
                .table(VaultSyncTasks::Table)
                .col((VaultSyncTasks::LastSyncAt, IndexOrder::Desc))
                .to_owned(),
        )
        .await?;
    manager
        .create_index(
            Index::create()
                .name("idx_vault_sync_tasks_created_at")
                .table(VaultSyncTasks::Table)
                .col((VaultSyncTasks::CreatedAt, IndexOrder::Desc))
                .to_owned(),
        )
        .await
}

async fn create_lookup_indexes(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    manager
        .create_index(
            Index::create()
                .name("idx_sync_logs_status_timestamp")
                .table(SyncLogs::Table)
                .col(SyncLogs::Status)
                .col((SyncLogs::Timestamp, IndexOrder::Desc))
                .to_owned(),
        )
        .await?;
    manager
        .create_index(
            Index::create()
                .name("idx_sync_logs_job_type_timestamp")
                .table(SyncLogs::Table)
                .col(SyncLogs::JobType)
                .col((SyncLogs::Timestamp, IndexOrder::Desc))
                .to_owned(),
        )
        .await?;
    manager
        .create_index(
            Index::create()
                .name("idx_api_key_sync_permissions_resource")
                .table(ApiKeySyncPermissions::Table)
                .col(ApiKeySyncPermissions::ResourceType)
                .col(ApiKeySyncPermissions::ResourceId)
                .to_owned(),
        )
        .await?;
    manager
        .create_index(
            Index::create()
                .name("idx_api_keys_is_master")
                .table(ApiKeys::Table)
                .col(ApiKeys::IsMaster)
                .to_owned(),
        )
        .await?;
    manager
        .create_index(
            Index::create()
                .name("idx_api_keys_created_at")
                .table(ApiKeys::Table)
                .col((ApiKeys::CreatedAt, IndexOrder::Desc))
                .to_owned(),
        )
        .await?;
    manager
        .create_index(
            Index::create()
                .name("idx_vault_endpoints_created_at")
                .table(VaultEndpoints::Table)
                .col((VaultEndpoints::CreatedAt, IndexOrder::Desc))
                .to_owned(),
        )
        .await?;
    manager
        .create_index(
            Index::create()
                .name("idx_external_sources_created_at")
                .table(ExternalSources::Table)
                .col((ExternalSources::CreatedAt, IndexOrder::Desc))
                .to_owned(),
        )
        .await
}

async fn drop_lookup_indexes(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    manager
        .drop_index(
            Index::drop()
                .name("idx_external_sources_created_at")
                .table(ExternalSources::Table)
                .to_owned(),
        )
        .await?;
    manager
        .drop_index(
            Index::drop()
                .name("idx_vault_endpoints_created_at")
                .table(VaultEndpoints::Table)
                .to_owned(),
        )
        .await?;
    manager
        .drop_index(
            Index::drop()
                .name("idx_api_keys_created_at")
                .table(ApiKeys::Table)
                .to_owned(),
        )
        .await?;
    manager
        .drop_index(
            Index::drop()
                .name("idx_api_keys_is_master")
                .table(ApiKeys::Table)
                .to_owned(),
        )
        .await?;
    manager
        .drop_index(
            Index::drop()
                .name("idx_api_key_sync_permissions_resource")
                .table(ApiKeySyncPermissions::Table)
                .to_owned(),
        )
        .await?;
    manager
        .drop_index(
            Index::drop()
                .name("idx_sync_logs_job_type_timestamp")
                .table(SyncLogs::Table)
                .to_owned(),
        )
        .await?;
    manager
        .drop_index(
            Index::drop()
                .name("idx_sync_logs_status_timestamp")
                .table(SyncLogs::Table)
                .to_owned(),
        )
        .await
}

async fn drop_job_indexes(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    manager
        .drop_index(
            Index::drop()
                .name("idx_vault_sync_tasks_created_at")
                .table(VaultSyncTasks::Table)
                .to_owned(),
        )
        .await?;
    manager
        .drop_index(
            Index::drop()
                .name("idx_vault_sync_tasks_last_sync_at")
                .table(VaultSyncTasks::Table)
                .to_owned(),
        )
        .await?;
    manager
        .drop_index(
            Index::drop()
                .name("idx_vault_sync_tasks_is_active")
                .table(VaultSyncTasks::Table)
                .to_owned(),
        )
        .await?;
    manager
        .drop_index(
            Index::drop()
                .name("idx_destination_groups_created_at")
                .table(DestinationGroups::Table)
                .to_owned(),
        )
        .await?;
    manager
        .drop_index(
            Index::drop()
                .name("idx_destination_groups_last_run_at")
                .table(DestinationGroups::Table)
                .to_owned(),
        )
        .await?;
    manager
        .drop_index(
            Index::drop()
                .name("idx_destination_groups_is_active")
                .table(DestinationGroups::Table)
                .to_owned(),
        )
        .await
}
