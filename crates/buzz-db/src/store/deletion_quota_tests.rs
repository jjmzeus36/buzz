use super::postgres_tests::{inventoried_request, store};
use super::*;

#[tokio::test]
#[ignore = "requires Postgres"]
async fn quota_serving_lease_quiescing_and_tenant_purge() {
    assert!(
        matches!(
            std::env::var("BUZZ_TEST_SCHEMA_MODE").as_deref(),
            Ok("desired" | "migration")
        ),
        "use the isolated PostgreSQL runner"
    );
    let (db, store) = store().await;
    let (request, inventory) = inventoried_request(&db, &store).await;
    let community = request.community_id;
    let neighbor = db
        .ensure_configured_community(&format!("quota-neighbor-{}.example", Uuid::new_v4()))
        .await
        .unwrap()
        .id;
    let key = [61; 32];
    let old = "d".repeat(64);
    let pending = "e".repeat(64);
    let policy = crate::media_quota::QuotaPolicy {
        limit: 10,
        baseline_id: Uuid::new_v4(),
    };
    db.enroll_media_quota(
        community,
        &key,
        policy,
        "verified target history",
        &[crate::media_quota::BaselineObject {
            sha256: old.clone(),
            size_bytes: 4,
        }],
    )
    .await
    .unwrap();
    db.enroll_media_quota(
        neighbor,
        &key,
        policy,
        "verified neighbor history",
        &[
            crate::media_quota::BaselineObject {
                sha256: old,
                size_bytes: 4,
            },
            crate::media_quota::BaselineObject {
                sha256: pending.clone(),
                size_bytes: 6,
            },
        ],
    )
    .await
    .unwrap();
    let operation = db
        .reserve_media_quota(community, &key, &pending, 6, policy)
        .await
        .unwrap()
        .unwrap();
    let lease = store
        .acquire_serving_write_lease(
            community,
            "media_upload",
            "quota-test",
            DEFAULT_LEASE_DURATION,
        )
        .await
        .unwrap();
    store.approve(request.id, "approver", None).await.unwrap();
    let claim = store
        .claim_specific(request.id, "executor", DEFAULT_LEASE_DURATION)
        .await
        .unwrap()
        .unwrap();
    store.begin_quiescing(&claim.lease).await.unwrap();
    assert!(db
        .reserve_media_quota(community, &key, &"a".repeat(64), 1, policy)
        .await
        .is_err());
    assert!(db
        .enroll_media_quota(community, &[62; 32], policy, "fenced empty import", &[])
        .await
        .is_err());
    assert!(db
        .finish_media_quota(community, &key, &pending, operation)
        .await
        .is_err());
    db.finish_media_quota_with_lease(community, &key, &pending, operation, Some(&lease))
        .await
        .unwrap();
    assert!(
        db.reserve_media_quota_with_lease(neighbor, &key, &pending, 6, policy, Some(&lease))
            .await
            .is_err(),
        "lease cannot cross tenant boundary"
    );
    store.release_serving_write_lease(&lease).await.unwrap();
    let generation = store.fence(&claim.lease).await.unwrap();
    let token = LeaseToken {
        fence_generation: Some(generation),
        ..claim.lease
    };
    assert!(db
        .finish_media_quota_with_lease(community, &key, &pending, operation, Some(&lease))
        .await
        .is_err());
    store
        .freeze_destructive_storage_manifest(&token, &inventory.storage)
        .await
        .unwrap();
    store.mark_drained(&token).await.unwrap();
    store
        .mark_bindings_removed(&token, serde_json::json!({"keys":0}))
        .await
        .unwrap();
    let purged = store.purge_postgres(&token).await.unwrap();
    assert_eq!(purged["media_quota_objects"], 2);
    assert_eq!(purged["media_quota_accounts"], 1);
    let total:i64=sqlx::query_scalar("SELECT sum(size_bytes)::bigint FROM media_quota_objects WHERE community_id=$1 AND pubkey=$2").bind(neighbor.as_uuid()).bind(key.as_slice()).fetch_one(&db.pool).await.unwrap();
    assert_eq!(total, 10);
    let target: i64 =
        sqlx::query_scalar("SELECT count(*) FROM media_quota_objects WHERE community_id=$1")
            .bind(community.as_uuid())
            .fetch_one(&db.pool)
            .await
            .unwrap();
    assert_eq!(target, 0);
    assert!(db
        .recover_media_quota(
            community,
            &key,
            &pending,
            operation,
            "stale post-purge recovery"
        )
        .await
        .is_err());
    assert!(db
        .enroll_media_quota(community, &key, policy, "stale post-purge enrollment", &[])
        .await
        .is_err());
    store
        .mark_cache_purged(&token, serde_json::json!({"keys":0}))
        .await
        .unwrap();
    store
        .verify_postgres_logically_deleted(&token)
        .await
        .unwrap();
}
