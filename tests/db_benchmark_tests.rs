//! Repeatable benchmarks comparing execution time Before vs After database query optimizations:
//! 1. Destination groups listing: N+1 per-entity queries vs Batched O(1) queries.
//! 2. Vault sync tasks listing: N+1 per-entity queries vs Batched O(1) queries.
//! 3. Active scheduler lookup on `destination_groups.is_active`: Sequential Scan vs Indexed Scan.
//! 4. Log status querying on `sync_logs(status, timestamp DESC)`: Sequential Scan vs Indexed Scan.

mod common;

use std::collections::HashMap;
use std::time::Instant;

use chrono::Utc;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, EntityTrait, QueryFilter, QueryOrder, Set,
};
use simply_ip_sync::entities::{
    destination_group, destination_group_vault_target, external_source, sync_log, vault_endpoint,
    vault_sync_task, vault_sync_task_target,
};
use uuid::Uuid;

#[tokio::test]
async fn benchmark_destination_groups_n_plus_one_vs_batched() {
    let (conn, _state, master) = common::setup().await;
    let now = Utc::now();

    // 1. Setup vault endpoint
    let vault_id = Uuid::new_v4();
    let v_model = vault_endpoint::ActiveModel {
        id: Set(vault_id),
        name: Set("BenchVault".to_owned()),
        target_url: Set("http://127.0.0.1:8000".to_owned()),
        api_key: Set("key".to_owned()),
        signing_secret: Set("v1.plain.616263".to_owned()),
        description: Set(None),
        owner_key_id: Set(Some(master.id)),
        created_at: Set(now),
        updated_at: Set(now),
    };
    v_model.insert(&conn).await.expect("insert vault");

    // 2. Seed 60 destination groups with targets and feeds
    let count = 60;
    let mut group_ids = Vec::with_capacity(count);
    for i in 0..count {
        let gid = Uuid::new_v4();
        group_ids.push(gid);
        let g = destination_group::ActiveModel {
            id: Set(gid),
            name: Set(format!("BenchGroup_{i}")),
            target_group_name: Set("targets".to_owned()),
            cron_schedule: Set("0 0 * * *".to_owned()),
            mode: Set("upsert".to_owned()),
            is_active: Set(true),
            skip_bogon_filtering: Set(false),
            last_run_at: Set(None),
            owner_key_id: Set(Some(master.id)),
            created_at: Set(now),
            updated_at: Set(now),
        };
        g.insert(&conn).await.expect("insert group");

        let target = destination_group_vault_target::ActiveModel {
            destination_group_id: Set(gid),
            vault_endpoint_id: Set(vault_id),
            target_group_name: Set(None),
        };
        target.insert(&conn).await.expect("insert target");

        let feed = external_source::ActiveModel {
            id: Set(Uuid::new_v4()),
            destination_group_id: Set(gid),
            name: Set(format!("BenchFeed_{i}")),
            source_url: Set("http://127.0.0.1/feed".to_owned()),
            parser_type: Set("REGEX_LINE".to_owned()),
            parser_config_json: Set(None),
            max_age_days: Set(None),
            skip_bogon_filtering: Set(None),
            created_at: Set(now),
            updated_at: Set(now),
        };
        feed.insert(&conn).await.expect("insert feed");
    }

    // ── BEFORE: N+1 sequential querying ─────────────────────────────────────
    let start_before = Instant::now();
    let all_groups = destination_group::Entity::find().all(&conn).await.expect("all");
    let mut before_results = Vec::new();
    for g in all_groups {
        let targets = destination_group_vault_target::Entity::find()
            .filter(destination_group_vault_target::Column::DestinationGroupId.eq(g.id))
            .all(&conn)
            .await
            .expect("targets");
        let feeds = external_source::Entity::find()
            .filter(external_source::Column::DestinationGroupId.eq(g.id))
            .all(&conn)
            .await
            .expect("feeds");
        before_results.push((g, targets, feeds));
    }
    let duration_before = start_before.elapsed();

    // ── AFTER: Batched O(1) round-trip querying ─────────────────────────────
    let start_after = Instant::now();
    let all_groups = destination_group::Entity::find().all(&conn).await.expect("all");
    let ids: Vec<Uuid> = all_groups.iter().map(|g| g.id).collect();

    let all_targets = destination_group_vault_target::Entity::find()
        .filter(destination_group_vault_target::Column::DestinationGroupId.is_in(ids.clone()))
        .all(&conn)
        .await
        .expect("all targets");
    let mut targets_map: HashMap<Uuid, Vec<_>> = HashMap::new();
    for t in all_targets {
        targets_map.entry(t.destination_group_id).or_default().push(t);
    }

    let all_feeds = external_source::Entity::find()
        .filter(external_source::Column::DestinationGroupId.is_in(ids))
        .all(&conn)
        .await
        .expect("all feeds");
    let mut feeds_map: HashMap<Uuid, Vec<_>> = HashMap::new();
    for f in all_feeds {
        feeds_map.entry(f.destination_group_id).or_default().push(f);
    }

    let mut after_results = Vec::new();
    for g in all_groups {
        let targets = targets_map.remove(&g.id).unwrap_or_default();
        let feeds = feeds_map.remove(&g.id).unwrap_or_default();
        after_results.push((g, targets, feeds));
    }
    let duration_after = start_after.elapsed();

    assert_eq!(before_results.len(), after_results.len());
    let speedup = duration_before.as_secs_f64() / duration_after.as_secs_f64();
    println!(
        "\n[BENCHMARK] Destination Groups ({count} items):\n  Before (N+1 queries) : {:.3} ms\n  After (Batched 3 queries): {:.3} ms\n  Speedup Ratio        : {:.2}x\n",
        duration_before.as_secs_f64() * 1000.0,
        duration_after.as_secs_f64() * 1000.0,
        speedup
    );
    assert!(
        duration_after <= duration_before,
        "Batched query must be as fast or faster than N+1 queries"
    );
}

#[tokio::test]
async fn benchmark_sync_tasks_n_plus_one_vs_batched() {
    let (conn, _state, master) = common::setup().await;
    let now = Utc::now();

    let v1 = Uuid::new_v4();
    let v2 = Uuid::new_v4();
    for (id, name) in [(v1, "V1"), (v2, "V2")] {
        vault_endpoint::ActiveModel {
            id: Set(id),
            name: Set(name.to_owned()),
            target_url: Set("http://127.0.0.1:8000".to_owned()),
            api_key: Set("key".to_owned()),
            signing_secret: Set("v1.plain.616263".to_owned()),
            description: Set(None),
            owner_key_id: Set(Some(master.id)),
            created_at: Set(now),
            updated_at: Set(now),
        }
        .insert(&conn)
        .await
        .expect("insert vault");
    }

    let count = 60;
    for i in 0..count {
        let tid = Uuid::new_v4();
        vault_sync_task::ActiveModel {
            id: Set(tid),
            name: Set(format!("Task_{i}")),
            source_vault_id: Set(v1),
            source_group_name: Set("src".to_owned()),
            target_group_name: Set("dst".to_owned()),
            cron_schedule: Set("0 0 * * *".to_owned()),
            last_sync_at: Set(None),
            mode: Set("upsert".to_owned()),
            is_active: Set(true),
            skip_bogon_filtering: Set(false),
            owner_key_id: Set(Some(master.id)),
            created_at: Set(now),
            updated_at: Set(now),
        }
        .insert(&conn)
        .await
        .expect("insert task");

        vault_sync_task_target::ActiveModel {
            vault_sync_task_id: Set(tid),
            target_vault_id: Set(v2),
            target_group_name: Set(None),
        }
        .insert(&conn)
        .await
        .expect("insert target");
    }

    // ── BEFORE: N+1 sequential loading ───────────────────────────────────────
    let start_before = Instant::now();
    let tasks = vault_sync_task::Entity::find().all(&conn).await.expect("tasks");
    let mut before_results = Vec::new();
    for t in tasks {
        let targets = vault_sync_task_target::Entity::find()
            .filter(vault_sync_task_target::Column::VaultSyncTaskId.eq(t.id))
            .all(&conn)
            .await
            .expect("targets");
        before_results.push((t, targets));
    }
    let duration_before = start_before.elapsed();

    // ── AFTER: Batched loading ───────────────────────────────────────────────
    let start_after = Instant::now();
    let tasks = vault_sync_task::Entity::find().all(&conn).await.expect("tasks");
    let tids: Vec<Uuid> = tasks.iter().map(|t| t.id).collect();
    let all_targets = vault_sync_task_target::Entity::find()
        .filter(vault_sync_task_target::Column::VaultSyncTaskId.is_in(tids))
        .all(&conn)
        .await
        .expect("targets");
    let mut map: HashMap<Uuid, Vec<_>> = HashMap::new();
    for t in all_targets {
        map.entry(t.vault_sync_task_id).or_default().push(t);
    }
    let mut after_results = Vec::new();
    for t in tasks {
        let targets = map.remove(&t.id).unwrap_or_default();
        after_results.push((t, targets));
    }
    let duration_after = start_after.elapsed();

    assert_eq!(before_results.len(), after_results.len());
    let speedup = duration_before.as_secs_f64() / duration_after.as_secs_f64();
    println!(
        "\n[BENCHMARK] Vault Sync Tasks ({count} items):\n  Before (N+1 queries) : {:.3} ms\n  After (Batched 2 queries): {:.3} ms\n  Speedup Ratio        : {:.2}x\n",
        duration_before.as_secs_f64() * 1000.0,
        duration_after.as_secs_f64() * 1000.0,
        speedup
    );
    assert!(
        duration_after <= duration_before,
        "Batched query must be as fast or faster than N+1 queries"
    );
}

#[tokio::test]
async fn benchmark_sync_logs_index_scan_vs_table_scan() {
    let (conn, _state, _master) = common::setup().await;
    let now = Utc::now();
    let job_id = Uuid::new_v4();

    // Seed 500 sync_logs rows with mixed statuses
    for i in 0..500 {
        let status = match i % 3 {
            0 => "SUCCESS",
            1 => "FAILED",
            _ => "PARTIAL",
        };
        sync_log::ActiveModel {
            id: Set(Uuid::new_v4()),
            job_type: Set("EXTERNAL_FEED".to_owned()),
            job_id: Set(job_id),
            job_name: Set(format!("Feed_{i}")),
            status: Set(status.to_owned()),
            items_processed: Set(100),
            chunks_sent: Set(1),
            duration_ms: Set(50),
            error_message: Set(None),
            timestamp: Set(now - chrono::Duration::seconds(i)),
        }
        .insert(&conn)
        .await
        .expect("insert log");
    }

    let iterations = 100;

    // ── WITH INDEX (After) ───────────────────────────────────────────────────
    let start_with_index = Instant::now();
    for _ in 0..iterations {
        let rows = sync_log::Entity::find()
            .filter(sync_log::Column::Status.eq("FAILED"))
            .order_by_desc(sync_log::Column::Timestamp)
            .all(&conn)
            .await
            .expect("query with index");
        assert_eq!(rows.len(), 167);
    }
    let duration_with_index = start_with_index.elapsed();

    // ── DROP INDEX (Simulate Before) ─────────────────────────────────────────
    conn.execute_unprepared("DROP INDEX IF EXISTS idx_sync_logs_status_timestamp")
        .await
        .expect("drop index");

    let start_without_index = Instant::now();
    for _ in 0..iterations {
        let rows = sync_log::Entity::find()
            .filter(sync_log::Column::Status.eq("FAILED"))
            .order_by_desc(sync_log::Column::Timestamp)
            .all(&conn)
            .await
            .expect("query without index");
        assert_eq!(rows.len(), 167);
    }
    let duration_without_index = start_without_index.elapsed();

    let speedup = duration_without_index.as_secs_f64() / duration_with_index.as_secs_f64();
    println!(
        "\n[BENCHMARK] Sync Logs Filtering ({iterations} iterations over 500 rows):\n  Without Index (Sequential Scan) : {:.3} ms\n  With Index (idx_sync_logs_status_timestamp): {:.3} ms\n  Speedup Ratio                   : {:.2}x\n",
        duration_without_index.as_secs_f64() * 1000.0,
        duration_with_index.as_secs_f64() * 1000.0,
        speedup
    );
}

#[tokio::test]
async fn benchmark_destination_groups_is_active_index_scan() {
    let (conn, _state, master) = common::setup().await;
    let now = Utc::now();

    // Seed 400 destination groups: 50 active, 350 inactive
    for i in 0..400 {
        destination_group::ActiveModel {
            id: Set(Uuid::new_v4()),
            name: Set(format!("Group_{i}")),
            target_group_name: Set("targets".to_owned()),
            cron_schedule: Set("0 0 * * *".to_owned()),
            mode: Set("upsert".to_owned()),
            is_active: Set(i < 50),
            skip_bogon_filtering: Set(false),
            last_run_at: Set(None),
            owner_key_id: Set(Some(master.id)),
            created_at: Set(now),
            updated_at: Set(now),
        }
        .insert(&conn)
        .await
        .expect("insert group");
    }

    let iterations = 100;

    // ── WITH INDEX (After) ───────────────────────────────────────────────────
    let start_with_index = Instant::now();
    for _ in 0..iterations {
        let active = destination_group::Entity::find()
            .filter(destination_group::Column::IsActive.eq(true))
            .all(&conn)
            .await
            .expect("query with index");
        assert_eq!(active.len(), 50);
    }
    let duration_with_index = start_with_index.elapsed();

    // ── DROP INDEX (Simulate Before) ─────────────────────────────────────────
    conn.execute_unprepared("DROP INDEX IF EXISTS idx_destination_groups_is_active")
        .await
        .expect("drop index");

    let start_without_index = Instant::now();
    for _ in 0..iterations {
        let active = destination_group::Entity::find()
            .filter(destination_group::Column::IsActive.eq(true))
            .all(&conn)
            .await
            .expect("query without index");
        assert_eq!(active.len(), 50);
    }
    let duration_without_index = start_without_index.elapsed();

    let speedup = duration_without_index.as_secs_f64() / duration_with_index.as_secs_f64();
    println!(
        "\n[BENCHMARK] Scheduler Boot (destination_groups WHERE is_active = true, {iterations} iterations over 400 rows):\n  Without Index (Sequential Scan) : {:.3} ms\n  With Index (idx_destination_groups_is_active): {:.3} ms\n  Speedup Ratio                   : {:.2}x\n",
        duration_without_index.as_secs_f64() * 1000.0,
        duration_with_index.as_secs_f64() * 1000.0,
        speedup
    );
}
