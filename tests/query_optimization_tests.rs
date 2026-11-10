//! Tests validating database query optimizations: batching/pre-fetching (eliminating N+1)
//! and log status filtering across destination groups, sync tasks, vault endpoints, and sync logs.

mod common;

use axum::http::StatusCode;
use chrono::Utc;
use sea_orm::{ActiveModelTrait, DatabaseConnection, Set};
use serde_json::Value;
use simply_ip_sync::entities::{
    api_key_sync_permission, destination_group, destination_group_vault_target, external_source,
    sync_log, vault_endpoint, vault_sync_task, vault_sync_task_target,
};
use uuid::Uuid;

async fn seed_vault(conn: &DatabaseConnection, name: &str, owner_key_id: Option<Uuid>) -> Uuid {
    let id = Uuid::new_v4();
    let now = Utc::now();
    let model = vault_endpoint::ActiveModel {
        id: Set(id),
        name: Set(name.to_owned()),
        target_url: Set(format!("http://127.0.0.1:{}", 8000)),
        api_key: Set("test_key".to_owned()),
        signing_secret: Set("v1.plain.616263".to_owned()),
        description: Set(None),
        owner_key_id: Set(owner_key_id),
        created_at: Set(now),
        updated_at: Set(now),
    };
    model.insert(conn).await.expect("insert vault");
    id
}

async fn seed_group(
    conn: &DatabaseConnection,
    name: &str,
    owner_key_id: Option<Uuid>,
    vault_id: Uuid,
) -> Uuid {
    let group_id = Uuid::new_v4();
    let now = Utc::now();
    let group = destination_group::ActiveModel {
        id: Set(group_id),
        name: Set(name.to_owned()),
        target_group_name: Set("targets".to_owned()),
        cron_schedule: Set("0 0 * * *".to_owned()),
        mode: Set("upsert".to_owned()),
        is_active: Set(true),
        skip_bogon_filtering: Set(false),
        last_run_at: Set(None),
        owner_key_id: Set(owner_key_id),
        created_at: Set(now),
        updated_at: Set(now),
    };
    group.insert(conn).await.expect("insert group");

    let target = destination_group_vault_target::ActiveModel {
        destination_group_id: Set(group_id),
        vault_endpoint_id: Set(vault_id),
        target_group_name: Set(Some("override_target".to_owned())),
    };
    target.insert(conn).await.expect("insert target");

    let feed = external_source::ActiveModel {
        id: Set(Uuid::new_v4()),
        destination_group_id: Set(group_id),
        name: Set(format!("feed_{name}")),
        source_url: Set("http://127.0.0.1/feed".to_owned()),
        parser_type: Set("REGEX_LINE".to_owned()),
        parser_config_json: Set(None),
        max_age_days: Set(None),
        skip_bogon_filtering: Set(None),
        created_at: Set(now),
        updated_at: Set(now),
    };
    feed.insert(conn).await.expect("insert feed");

    group_id
}

async fn seed_task(
    conn: &DatabaseConnection,
    name: &str,
    owner_key_id: Option<Uuid>,
    source_vault_id: Uuid,
    target_vault_id: Uuid,
) -> Uuid {
    let task_id = Uuid::new_v4();
    let now = Utc::now();
    let task = vault_sync_task::ActiveModel {
        id: Set(task_id),
        name: Set(name.to_owned()),
        source_vault_id: Set(source_vault_id),
        source_group_name: Set("source_grp".to_owned()),
        target_group_name: Set("target_grp".to_owned()),
        cron_schedule: Set("0 0 * * *".to_owned()),
        last_sync_at: Set(None),
        mode: Set("upsert".to_owned()),
        is_active: Set(true),
        skip_bogon_filtering: Set(false),
        owner_key_id: Set(owner_key_id),
        created_at: Set(now),
        updated_at: Set(now),
    };
    task.insert(conn).await.expect("insert task");

    let target = vault_sync_task_target::ActiveModel {
        vault_sync_task_id: Set(task_id),
        target_vault_id: Set(target_vault_id),
        target_group_name: Set(None),
    };
    target.insert(conn).await.expect("insert task target");

    task_id
}

#[tokio::test]
async fn test_destination_groups_batch_fetching_and_scoping() {
    let (conn, state, master) = common::setup().await;
    let router = simply_ip_sync::create_app(state);

    let v1 = seed_vault(&conn, "Vault1", Some(master.id)).await;
    let _g1 = seed_group(&conn, "Group1", Some(master.id), v1).await;
    let g2 = seed_group(&conn, "Group2", Some(master.id), v1).await;

    let user_key = common::insert_key(&conn, "Operator", false, false, false, false, None).await;

    // Grant user_key permission on Group2 only
    let perm = api_key_sync_permission::ActiveModel {
        id: Set(Uuid::new_v4()),
        api_key_id: Set(user_key.id),
        resource_type: Set("destination_group".to_owned()),
        resource_id: Set(g2),
        can_sync: Set(true),
        can_manage: Set(false),
        can_view_logs: Set(true),
        created_at: Set(Utc::now()),
    };
    perm.insert(&conn).await.expect("insert perm");

    // 1. Master sees both groups with targets and feeds nested
    let req = common::signed_request(&master, "GET", "/api/destination-groups", None);
    let resp = tower::ServiceExt::oneshot(router.clone(), req).await.expect("call");
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024).await.expect("bytes");
    let json: Vec<Value> = serde_json::from_slice(&body).expect("parse");
    assert_eq!(json.len(), 2);
    for group in &json {
        let targets = group["targets"].as_array().expect("targets array");
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0]["vault_endpoint_id"], v1.to_string());

        let feeds = group["feeds"].as_array().expect("feeds array");
        assert_eq!(feeds.len(), 1);
    }

    // 2. Operator key sees only Group2, with targets and feeds populated
    let req = common::signed_request(&user_key, "GET", "/api/destination-groups", None);
    let resp = tower::ServiceExt::oneshot(router.clone(), req).await.expect("call");
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024).await.expect("bytes");
    let json: Vec<Value> = serde_json::from_slice(&body).expect("parse");
    assert_eq!(json.len(), 1);
    assert_eq!(json[0]["id"], g2.to_string());
    assert_eq!(json[0]["targets"].as_array().unwrap().len(), 1);
    assert_eq!(json[0]["feeds"].as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn test_sync_tasks_batch_fetching_and_scoping() {
    let (conn, state, master) = common::setup().await;
    let router = simply_ip_sync::create_app(state);

    let v1 = seed_vault(&conn, "VaultA", Some(master.id)).await;
    let v2 = seed_vault(&conn, "VaultB", Some(master.id)).await;
    let t1 = seed_task(&conn, "Task1", Some(master.id), v1, v2).await;
    let _t2 = seed_task(&conn, "Task2", Some(master.id), v1, v2).await;

    let user_key = common::insert_key(&conn, "Viewer", false, false, false, false, None).await;

    // Grant user_key permission on Task1 only
    let perm = api_key_sync_permission::ActiveModel {
        id: Set(Uuid::new_v4()),
        api_key_id: Set(user_key.id),
        resource_type: Set("sync_task".to_owned()),
        resource_id: Set(t1),
        can_sync: Set(false),
        can_manage: Set(false),
        can_view_logs: Set(true),
        created_at: Set(Utc::now()),
    };
    perm.insert(&conn).await.expect("insert perm");

    // Master sees both tasks with targets
    let req = common::signed_request(&master, "GET", "/api/sync-tasks", None);
    let resp = tower::ServiceExt::oneshot(router.clone(), req).await.expect("call");
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024).await.expect("bytes");
    let json: Vec<Value> = serde_json::from_slice(&body).expect("parse");
    assert_eq!(json.len(), 2);
    for task in &json {
        let targets = task["targets"].as_array().expect("targets array");
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0]["vault_endpoint_id"], v2.to_string());
    }

    // Viewer sees only Task1
    let req = common::signed_request(&user_key, "GET", "/api/sync-tasks", None);
    let resp = tower::ServiceExt::oneshot(router.clone(), req).await.expect("call");
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024).await.expect("bytes");
    let json: Vec<Value> = serde_json::from_slice(&body).expect("parse");
    assert_eq!(json.len(), 1);
    assert_eq!(json[0]["id"], t1.to_string());
    assert_eq!(json[0]["targets"].as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn test_sync_logs_filtering_by_status_and_batch_scoping() {
    let (conn, state, master) = common::setup().await;
    let router = simply_ip_sync::create_app(state);

    let job1 = Uuid::new_v4();
    let job2 = Uuid::new_v4();
    let now = Utc::now();

    // Insert 3 logs: SUCCESS, FAILED, PARTIAL
    let log1 = sync_log::ActiveModel {
        id: Set(Uuid::new_v4()),
        job_type: Set("EXTERNAL_FEED".to_owned()),
        job_id: Set(job1),
        job_name: Set("Feed1".to_owned()),
        status: Set("SUCCESS".to_owned()),
        items_processed: Set(10),
        chunks_sent: Set(1),
        duration_ms: Set(100),
        error_message: Set(None),
        timestamp: Set(now),
    };
    log1.insert(&conn).await.expect("insert log 1");

    let log2 = sync_log::ActiveModel {
        id: Set(Uuid::new_v4()),
        job_type: Set("EXTERNAL_FEED".to_owned()),
        job_id: Set(job1),
        job_name: Set("Feed1".to_owned()),
        status: Set("FAILED".to_owned()),
        items_processed: Set(0),
        chunks_sent: Set(0),
        duration_ms: Set(50),
        error_message: Set(Some("connection error".to_owned())),
        timestamp: Set(now),
    };
    log2.insert(&conn).await.expect("insert log 2");

    let log3 = sync_log::ActiveModel {
        id: Set(Uuid::new_v4()),
        job_type: Set("VAULT_SYNC".to_owned()),
        job_id: Set(job2),
        job_name: Set("Sync1".to_owned()),
        status: Set("PARTIAL".to_owned()),
        items_processed: Set(5),
        chunks_sent: Set(1),
        duration_ms: Set(75),
        error_message: Set(Some("target 2 failed".to_owned())),
        timestamp: Set(now),
    };
    log3.insert(&conn).await.expect("insert log 3");

    // 1. Filter by status=SUCCESS
    let req = common::signed_request(&master, "GET", "/api/sync-logs?status=SUCCESS", None);
    let resp = tower::ServiceExt::oneshot(router.clone(), req).await.expect("call");
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024).await.expect("bytes");
    let json: Vec<Value> = serde_json::from_slice(&body).expect("parse");
    assert_eq!(json.len(), 1);
    assert_eq!(json[0]["status"], "SUCCESS");

    // 2. Filter by status=FAILED
    let req = common::signed_request(&master, "GET", "/api/sync-logs?status=FAILED", None);
    let resp = tower::ServiceExt::oneshot(router.clone(), req).await.expect("call");
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024).await.expect("bytes");
    let json: Vec<Value> = serde_json::from_slice(&body).expect("parse");
    assert_eq!(json.len(), 1);
    assert_eq!(json[0]["status"], "FAILED");

    // 3. Filter by status=PARTIAL
    let req = common::signed_request(&master, "GET", "/api/sync-logs?status=PARTIAL", None);
    let resp = tower::ServiceExt::oneshot(router.clone(), req).await.expect("call");
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024).await.expect("bytes");
    let json: Vec<Value> = serde_json::from_slice(&body).expect("parse");
    assert_eq!(json.len(), 1);
    assert_eq!(json[0]["status"], "PARTIAL");

    // 4. Non-master scoping: give user_key permission on job2 only
    let user_key = common::insert_key(&conn, "Auditor", false, false, false, false, None).await;
    let perm = api_key_sync_permission::ActiveModel {
        id: Set(Uuid::new_v4()),
        api_key_id: Set(user_key.id),
        resource_type: Set("sync_task".to_owned()),
        resource_id: Set(job2),
        can_sync: Set(false),
        can_manage: Set(false),
        can_view_logs: Set(true),
        created_at: Set(Utc::now()),
    };
    perm.insert(&conn).await.expect("insert perm");

    let req = common::signed_request(&user_key, "GET", "/api/sync-logs", None);
    let resp = tower::ServiceExt::oneshot(router.clone(), req).await.expect("call");
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024).await.expect("bytes");
    let json: Vec<Value> = serde_json::from_slice(&body).expect("parse");
    assert_eq!(json.len(), 1);
    assert_eq!(json[0]["job_id"], job2.to_string());
}
