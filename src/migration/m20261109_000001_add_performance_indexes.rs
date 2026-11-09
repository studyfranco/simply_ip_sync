//! Adds performance indexes for audit logs, sync logs, and foreign key relations.
//!
//! Hot paths in `simply_ip_sync`:
//! - Audit logs listing: default is `ORDER BY timestamp DESC LIMIT 50`, optionally filtered by `action` or `api_key_id`.
//! - Sync logs listing: `ORDER BY timestamp DESC`, optionally filtered by `job_type` and `job_id`.
//! - Foreign key lookups: `external_sources(destination_group_id)`, `vault_sync_tasks(source_vault_id)`,
//!   `vault_sync_task_targets(target_vault_id)`, and `destination_group_vault_targets(vault_endpoint_id)`.

use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[derive(DeriveIden)]
enum AuditLogs {
    Table,
    ApiKeyId,
    Action,
    Timestamp,
}

#[derive(DeriveIden)]
enum SyncLogs {
    Table,
    JobType,
    JobId,
    Timestamp,
}

#[derive(DeriveIden)]
enum ExternalSources {
    Table,
    DestinationGroupId,
}

#[derive(DeriveIden)]
enum VaultSyncTasks {
    Table,
    SourceVaultId,
}

#[derive(DeriveIden)]
enum VaultSyncTaskTargets {
    Table,
    TargetVaultId,
}

#[derive(DeriveIden)]
enum DestinationGroupVaultTargets {
    Table,
    VaultEndpointId,
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Audit logs: default search newest-first
        manager
            .create_index(
                Index::create()
                    .name("idx_audit_logs_timestamp_desc")
                    .table(AuditLogs::Table)
                    .col((AuditLogs::Timestamp, IndexOrder::Desc))
                    .to_owned(),
            )
            .await?;

        // Audit logs: filter by action newest-first
        manager
            .create_index(
                Index::create()
                    .name("idx_audit_logs_action_timestamp_desc")
                    .table(AuditLogs::Table)
                    .col(AuditLogs::Action)
                    .col((AuditLogs::Timestamp, IndexOrder::Desc))
                    .to_owned(),
            )
            .await?;

        // Audit logs: filter by API key newest-first
        manager
            .create_index(
                Index::create()
                    .name("idx_audit_logs_api_key_id_timestamp")
                    .table(AuditLogs::Table)
                    .col(AuditLogs::ApiKeyId)
                    .col((AuditLogs::Timestamp, IndexOrder::Desc))
                    .to_owned(),
            )
            .await?;

        // Sync logs: default newest-first
        manager
            .create_index(
                Index::create()
                    .name("idx_sync_logs_timestamp_desc")
                    .table(SyncLogs::Table)
                    .col((SyncLogs::Timestamp, IndexOrder::Desc))
                    .to_owned(),
            )
            .await?;

        // Sync logs: filter by job_type and job_id newest-first
        manager
            .create_index(
                Index::create()
                    .name("idx_sync_logs_job_timestamp")
                    .table(SyncLogs::Table)
                    .col(SyncLogs::JobType)
                    .col(SyncLogs::JobId)
                    .col((SyncLogs::Timestamp, IndexOrder::Desc))
                    .to_owned(),
            )
            .await?;

        // External sources: foreign key lookup by destination group
        manager
            .create_index(
                Index::create()
                    .name("idx_external_sources_destination_group_id")
                    .table(ExternalSources::Table)
                    .col(ExternalSources::DestinationGroupId)
                    .to_owned(),
            )
            .await?;

        // Vault sync tasks: foreign key lookup by source vault
        manager
            .create_index(
                Index::create()
                    .name("idx_vault_sync_tasks_source_vault_id")
                    .table(VaultSyncTasks::Table)
                    .col(VaultSyncTasks::SourceVaultId)
                    .to_owned(),
            )
            .await?;

        // Vault sync task targets: foreign key lookup by target vault
        manager
            .create_index(
                Index::create()
                    .name("idx_vault_sync_task_targets_target_vault_id")
                    .table(VaultSyncTaskTargets::Table)
                    .col(VaultSyncTaskTargets::TargetVaultId)
                    .to_owned(),
            )
            .await?;

        // Destination group vault targets: foreign key lookup by vault endpoint
        manager
            .create_index(
                Index::create()
                    .name("idx_dgvt_vault_endpoint_id")
                    .table(DestinationGroupVaultTargets::Table)
                    .col(DestinationGroupVaultTargets::VaultEndpointId)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_index(
                Index::drop()
                    .name("idx_dgvt_vault_endpoint_id")
                    .table(DestinationGroupVaultTargets::Table)
                    .to_owned(),
            )
            .await?;

        manager
            .drop_index(
                Index::drop()
                    .name("idx_vault_sync_task_targets_target_vault_id")
                    .table(VaultSyncTaskTargets::Table)
                    .to_owned(),
            )
            .await?;

        manager
            .drop_index(
                Index::drop()
                    .name("idx_vault_sync_tasks_source_vault_id")
                    .table(VaultSyncTasks::Table)
                    .to_owned(),
            )
            .await?;

        manager
            .drop_index(
                Index::drop()
                    .name("idx_external_sources_destination_group_id")
                    .table(ExternalSources::Table)
                    .to_owned(),
            )
            .await?;

        manager
            .drop_index(
                Index::drop()
                    .name("idx_sync_logs_job_timestamp")
                    .table(SyncLogs::Table)
                    .to_owned(),
            )
            .await?;

        manager
            .drop_index(
                Index::drop()
                    .name("idx_sync_logs_timestamp_desc")
                    .table(SyncLogs::Table)
                    .to_owned(),
            )
            .await?;

        manager
            .drop_index(
                Index::drop()
                    .name("idx_audit_logs_api_key_id_timestamp")
                    .table(AuditLogs::Table)
                    .to_owned(),
            )
            .await?;

        manager
            .drop_index(
                Index::drop()
                    .name("idx_audit_logs_action_timestamp_desc")
                    .table(AuditLogs::Table)
                    .to_owned(),
            )
            .await?;

        manager
            .drop_index(
                Index::drop()
                    .name("idx_audit_logs_timestamp_desc")
                    .table(AuditLogs::Table)
                    .to_owned(),
            )
            .await
    }
}
