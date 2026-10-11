use super::postgres_tests::{database_url, enroll, fixture};
use super::*;

#[tokio::test]
#[ignore = "requires Postgres"]
async fn quota_historical_baseline_counts_bytes_and_retains_pending() {
    let (db, c, p) = fixture().await;
    let key = [4; 32];
    let old = "e".repeat(64);
    let pending = "a".repeat(64);
    db.enroll_media_quota(
        c,
        &key,
        p,
        "verified pre-quota original and uploader attribution",
        &[BaselineObject {
            sha256: old.clone(),
            size_bytes: 7,
        }],
    )
    .await
    .unwrap();
    assert!(matches!(
        db.reserve_media_quota(c, &key, &"f".repeat(64), 4, p).await,
        Err(QuotaError::Exceeded)
    ));
    let token = db
        .reserve_media_quota(c, &key, &pending, 3, p)
        .await
        .unwrap()
        .unwrap();
    let fresh = QuotaPolicy {
        baseline_id: Uuid::new_v4(),
        ..p
    };
    let before: (Uuid,String,chrono::DateTime<chrono::Utc>)=sqlx::query_as("SELECT baseline_id,evidence,enrolled_at FROM media_quota_accounts WHERE community_id=$1 AND pubkey=$2").bind(c.as_uuid()).bind(key.as_slice()).fetch_one(&db.pool).await.unwrap();
    for objects in [
        vec![],
        vec![BaselineObject {
            sha256: old.clone(),
            size_bytes: 7,
        }],
        vec![
            BaselineObject {
                sha256: old.clone(),
                size_bytes: 6,
            },
            BaselineObject {
                sha256: pending.clone(),
                size_bytes: 3,
            },
        ],
    ] {
        assert!(db
            .enroll_media_quota(c, &key, fresh, "incomplete or altered baseline", &objects)
            .await
            .is_err());
        let after: (Uuid,String,chrono::DateTime<chrono::Utc>)=sqlx::query_as("SELECT baseline_id,evidence,enrolled_at FROM media_quota_accounts WHERE community_id=$1 AND pubkey=$2").bind(c.as_uuid()).bind(key.as_slice()).fetch_one(&db.pool).await.unwrap();
        assert_eq!(
            before, after,
            "rejected import rolls back all enrollment metadata"
        );
    }
    db.enroll_media_quota(
        c,
        &key,
        fresh,
        "complete renewed history including uncertain write",
        &[
            BaselineObject {
                sha256: old.clone(),
                size_bytes: 7,
            },
            BaselineObject {
                sha256: pending.clone(),
                size_bytes: 3,
            },
        ],
    )
    .await
    .unwrap();
    assert!(matches!(
        db.reserve_media_quota(c, &key, &pending, 3, fresh).await,
        Err(QuotaError::Pending)
    ));
    for hash in [&old, &"b".repeat(64)] {
        assert!(matches!(
            db.reserve_media_quota(c, &key, hash, 7, p).await,
            Err(QuotaError::UnknownBaseline)
        ));
    }
    assert!(matches!(
        db.reserve_media_quota(c, &key, &"b".repeat(64), 1, fresh)
            .await,
        Err(QuotaError::Exceeded)
    ));
    assert!(db
        .finish_media_quota(c, &key, &pending, Uuid::new_v4())
        .await
        .is_err());
    db.finish_media_quota(c, &key, &pending, token)
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn quota_numeric_boundaries_empty_original_and_policy_limit_fence() {
    let (db, c, p) = fixture().await;
    let key = [5; 32];
    for objects in [
        vec![BaselineObject {
            sha256: "a".repeat(64),
            size_bytes: i64::MAX as u64 + 1,
        }],
        vec![BaselineObject {
            sha256: "A".repeat(64),
            size_bytes: 1,
        }],
        vec![
            BaselineObject {
                sha256: "a".repeat(64),
                size_bytes: 1,
            },
            BaselineObject {
                sha256: "a".repeat(64),
                size_bytes: 1,
            },
        ],
    ] {
        assert!(db
            .enroll_media_quota(c, &key, p, "bad import", &objects)
            .await
            .is_err());
    }
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM media_quota_accounts WHERE community_id=$1 AND pubkey=$2",
    )
    .bind(c.as_uuid())
    .bind(key.as_slice())
    .fetch_one(&db.pool)
    .await
    .unwrap();
    assert_eq!(
        count, 0,
        "invalid first enrollment cannot leave an empty trusted baseline"
    );
    let max = QuotaPolicy {
        limit: i64::MAX,
        ..p
    };
    db.enroll_media_quota(
        c,
        &key,
        max,
        "verified historical over-limit account",
        &[
            BaselineObject {
                sha256: "a".repeat(64),
                size_bytes: i64::MAX as u64,
            },
            BaselineObject {
                sha256: "b".repeat(64),
                size_bytes: i64::MAX as u64,
            },
        ],
    )
    .await
    .unwrap();
    assert!(matches!(
        db.reserve_media_quota(c, &key, &"c".repeat(64), 1, max)
            .await,
        Err(QuotaError::Exceeded)
    ));
    assert!(db
        .reserve_media_quota(c, &key, &"a".repeat(64), i64::MAX as u64, max)
        .await
        .unwrap()
        .is_none());
    let empty_key = [6; 32];
    enroll(&db, c, p, &empty_key).await;
    let empty = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    let operation = db
        .reserve_media_quota(c, &empty_key, empty, 0, p)
        .await
        .unwrap()
        .unwrap();
    db.finish_media_quota(c, &empty_key, empty, operation)
        .await
        .unwrap();
    assert!(db
        .reserve_media_quota(c, &empty_key, empty, 0, p)
        .await
        .unwrap()
        .is_none());
    let stale_limit = QuotaPolicy { limit: 100, ..p };
    assert!(
        matches!(
            db.reserve_media_quota(c, &empty_key, &"c".repeat(64), 6, stale_limit)
                .await,
            Err(QuotaError::UnknownBaseline)
        ),
        "same epoch with a stale limit is never admitted"
    );
    assert!(db
        .reserve_media_quota(c, &empty_key, &"c".repeat(64), 10, p)
        .await
        .unwrap()
        .is_some());
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn quota_exact_tuple_recovery_is_durable_and_retryable() {
    let (db, c, p) = fixture().await;
    let key = [7; 32];
    enroll(&db, c, p, &key).await;
    let hash = "d".repeat(64);
    let operation = db
        .reserve_media_quota(c, &key, &hash, 6, p)
        .await
        .unwrap()
        .unwrap();
    sqlx::query("UPDATE media_quota_objects SET created_at=now()-interval '30 days' WHERE community_id=$1 AND pubkey=$2").bind(c.as_uuid()).bind(key.as_slice()).execute(&db.pool).await.unwrap();
    let restarted = Db::from_pool(sqlx::PgPool::connect(&database_url()).await.unwrap());
    assert!(matches!(
        restarted.reserve_media_quota(c, &key, &hash, 6, p).await,
        Err(QuotaError::Pending)
    ));
    assert!(restarted
        .finish_media_quota(c, &[8; 32], &hash, operation)
        .await
        .is_err());
    assert!(restarted
        .recover_media_quota(c, &[8; 32], &hash, operation, "wrong owner")
        .await
        .is_err());
    assert!(restarted
        .recover_media_quota(c, &key, &hash, Uuid::new_v4(), "wrong token")
        .await
        .is_err());
    restarted
        .recover_media_quota(c, &key, &hash, operation, "retain exact uncertain charge")
        .await
        .unwrap();
    restarted
        .recover_media_quota(c, &key, &hash, operation, "retain exact uncertain charge")
        .await
        .unwrap();
    assert!(restarted
        .recover_media_quota(c, &key, &hash, operation, "different evidence")
        .await
        .is_err());
    let row:(i64,Uuid,String)=sqlx::query_as("SELECT size_bytes,operation_id,state FROM media_quota_objects WHERE community_id=$1 AND pubkey=$2").bind(c.as_uuid()).bind(key.as_slice()).fetch_one(&db.pool).await.unwrap();
    assert_eq!(row, (6, operation, "charged".into()));
    assert!(restarted
        .reserve_media_quota(c, &key, &hash, 6, p)
        .await
        .unwrap()
        .is_none());
    assert!(matches!(
        restarted
            .reserve_media_quota(c, &key, &"e".repeat(64), 5, p)
            .await,
        Err(QuotaError::Exceeded)
    ));
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn migration_schema_quota_starts_unknown_and_constraints_are_enforced() {
    let (db, c, p) = fixture().await;
    let key = [9; 32];
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM media_quota_accounts")
        .fetch_one(&db.pool)
        .await
        .unwrap();
    assert_eq!(count, 0, "migration never invents historical baselines");
    assert!(matches!(
        db.reserve_media_quota(c, &key, &"a".repeat(64), 1, p).await,
        Err(QuotaError::UnknownBaseline)
    ));
    enroll(&db, c, p, &key).await;
    for (hash, size, state) in [
        ("a".repeat(64), -1, "charged"),
        ("A".repeat(64), 1, "charged"),
        ("a".repeat(64), 1, "other"),
    ] {
        let error=sqlx::query("INSERT INTO media_quota_objects (community_id,pubkey,sha256,size_bytes,operation_id,state) VALUES ($1,$2,$3,$4,$5,$6)").bind(c.as_uuid()).bind(key.as_slice()).bind(hash).bind(size as i64).bind(Uuid::new_v4()).bind(state).execute(&db.pool).await.unwrap_err();
        assert_eq!(
            error.as_database_error().unwrap().code().as_deref(),
            Some("23514")
        );
    }
    let triggers:i64=sqlx::query_scalar("SELECT count(*) FROM pg_trigger WHERE tgname IN ('community_write_fence_media_quota_accounts','community_write_fence_media_quota_objects') AND NOT tgisinternal").fetch_one(&db.pool).await.unwrap();
    assert_eq!(triggers, 2);
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn quota_serialization_forces_overlap_and_rolls_back_canceled_reservation() {
    use std::time::Duration;
    for cancel in [false, true] {
        let (db, c, p) = fixture().await;
        let key = [10; 32];
        enroll(&db, c, p, &key).await;
        let gate = (Uuid::new_v4().as_u128() & 0x7fff_ffff) as i64;
        let mut blocker = db.pool.begin().await.unwrap();
        sqlx::query("SELECT pg_advisory_xact_lock($1)")
            .bind(gate)
            .execute(&mut *blocker)
            .await
            .unwrap();
        let function = format!("quota_gate_{gate}");
        // Identifiers and lock key are generated solely from bounded integers;
        // the hash is a constant. No input can contribute SQL syntax.
        sqlx::query(sqlx::AssertSqlSafe(format!("CREATE FUNCTION {function}() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.sha256='{}' THEN PERFORM pg_advisory_xact_lock({gate}); END IF; RETURN NEW; END $$", "a".repeat(64)))).execute(&db.pool).await.unwrap();
        sqlx::query(sqlx::AssertSqlSafe(format!("CREATE TRIGGER {function} BEFORE INSERT ON media_quota_objects FOR EACH ROW EXECUTE FUNCTION {function}()" ))).execute(&db.pool).await.unwrap();
        let first_db = db.clone();
        let first = tokio::spawn(async move {
            first_db
                .reserve_media_quota(c, &key, &"a".repeat(64), 6, p)
                .await
        });
        let pid=tokio::time::timeout(Duration::from_secs(5),async {
            loop {
                let pid:Option<i32>=sqlx::query_scalar("SELECT pid FROM pg_locks WHERE locktype='advisory' AND objid=$1::bigint::oid AND NOT granted LIMIT 1").bind(gate).fetch_optional(&db.pool).await.unwrap();
                if let Some(pid)=pid {break pid;}
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }).await.unwrap();
        let second_db = db.clone();
        let mut second = tokio::spawn(async move {
            second_db
                .reserve_media_quota(c, &key, &"b".repeat(64), 6, p)
                .await
        });
        assert!(
            tokio::time::timeout(Duration::from_millis(100), &mut second)
                .await
                .is_err(),
            "second replica must wait for owner lock before reading usage"
        );
        if cancel {
            sqlx::query("SELECT pg_cancel_backend($1)")
                .bind(pid)
                .execute(&db.pool)
                .await
                .unwrap();
        }
        blocker.commit().await.unwrap();
        let a = first.await.unwrap();
        let b = second.await.unwrap();
        if cancel {
            assert!(a.is_err());
            assert!(b.unwrap().is_some());
        } else {
            assert!(a.unwrap().is_some());
            assert!(matches!(b, Err(QuotaError::Exceeded)));
        }
        let total:i64=sqlx::query_scalar("SELECT sum(size_bytes)::bigint FROM media_quota_objects WHERE community_id=$1 AND pubkey=$2").bind(c.as_uuid()).bind(key.as_slice()).fetch_one(&db.pool).await.unwrap();
        assert_eq!(total, 6);
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "DROP TRIGGER {function} ON media_quota_objects"
        )))
        .execute(&db.pool)
        .await
        .unwrap();
        sqlx::query(sqlx::AssertSqlSafe(format!("DROP FUNCTION {function}()")))
            .execute(&db.pool)
            .await
            .unwrap();
    }
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn quota_baseline_batches_rollback_atomically_and_preserve_pending() {
    let (db, c, p) = fixture().await;
    let key = [12; 32];
    enroll(&db, c, p, &key).await;
    let pending_hash = "e".repeat(64);
    let operation = db
        .reserve_media_quota(c, &key, &pending_hash, 6, p)
        .await
        .unwrap()
        .unwrap();
    let before: (Uuid, i64, String, chrono::DateTime<chrono::Utc>) = sqlx::query_as("SELECT baseline_id,limit_bytes,evidence,enrolled_at FROM media_quota_accounts WHERE community_id=$1 AND pubkey=$2")
        .bind(c.as_uuid()).bind(key.as_slice()).fetch_one(&db.pool).await.unwrap();
    let mut objects = vec![BaselineObject {
        sha256: pending_hash.clone(),
        size_bytes: 6,
    }];
    objects.extend((0..500).map(|index| BaselineObject {
        sha256: format!("{index:064x}"),
        size_bytes: 1,
    }));
    objects.push(BaselineObject {
        sha256: "f".repeat(64),
        size_bytes: 1,
    });
    let renewed = QuotaPolicy {
        baseline_id: Uuid::new_v4(),
        limit: 1000,
    };
    sqlx::query("CREATE FUNCTION quota_baseline_batch_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.sha256=repeat('f',64) THEN RAISE EXCEPTION 'synthetic second batch failure'; END IF; RETURN NEW; END $$").execute(&db.pool).await.unwrap();
    sqlx::query("CREATE TRIGGER quota_baseline_batch_failure BEFORE INSERT ON media_quota_objects FOR EACH ROW EXECUTE FUNCTION quota_baseline_batch_failure()").execute(&db.pool).await.unwrap();
    assert!(db
        .enroll_media_quota(c, &key, renewed, "synthetic complete renewal", &objects)
        .await
        .is_err());
    let after: (Uuid, i64, String, chrono::DateTime<chrono::Utc>) = sqlx::query_as("SELECT baseline_id,limit_bytes,evidence,enrolled_at FROM media_quota_accounts WHERE community_id=$1 AND pubkey=$2")
        .bind(c.as_uuid()).bind(key.as_slice()).fetch_one(&db.pool).await.unwrap();
    assert_eq!(
        before, after,
        "failed second batch must roll back account renewal too"
    );
    let rows: Vec<(String, i64, Uuid, String)> = sqlx::query_as("SELECT sha256,size_bytes,operation_id,state FROM media_quota_objects WHERE community_id=$1 AND pubkey=$2")
        .bind(c.as_uuid()).bind(key.as_slice()).fetch_all(&db.pool).await.unwrap();
    assert_eq!(
        rows,
        vec![(pending_hash.clone(), 6, operation, "pending".into())],
        "earlier insert batches must roll back without releasing pending liability"
    );
    sqlx::query("DROP TRIGGER quota_baseline_batch_failure ON media_quota_objects")
        .execute(&db.pool)
        .await
        .unwrap();
    sqlx::query("DROP FUNCTION quota_baseline_batch_failure()")
        .execute(&db.pool)
        .await
        .unwrap();
    db.enroll_media_quota(c, &key, renewed, "synthetic complete renewal", &objects)
        .await
        .unwrap();
    let totals: (i64, i64) = sqlx::query_as("SELECT count(*),sum(size_bytes)::bigint FROM media_quota_objects WHERE community_id=$1 AND pubkey=$2")
        .bind(c.as_uuid()).bind(key.as_slice()).fetch_one(&db.pool).await.unwrap();
    assert_eq!(totals, (502, 507));
    let pending: (Uuid, String) = sqlx::query_as("SELECT operation_id,state FROM media_quota_objects WHERE community_id=$1 AND pubkey=$2 AND sha256=$3")
        .bind(c.as_uuid()).bind(key.as_slice()).bind(&pending_hash).fetch_one(&db.pool).await.unwrap();
    assert_eq!(pending, (operation, "pending".into()));
    assert!(matches!(
        db.reserve_media_quota(c, &key, &pending_hash, 6, renewed)
            .await,
        Err(QuotaError::Pending)
    ));
}
