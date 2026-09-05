//! Process-isolated proof that keyed miss → reserve → complete hashes semantic intent once.
//!
//! A distinct integration-test binary has its own process-global reservation
//! semaphore, so this cannot collide with the `buzz-db` unit-test binary.

use buzz_core::idempotency::SemanticIntentHashWatch;
use buzz_core::CommunityId;
use buzz_db::idempotency::KeyedReserveOutcome;
use buzz_db::Db;
use nostr::{Event, EventBuilder, Keys, Kind, Timestamp};
use sqlx::PgPool;
use uuid::Uuid;

const TEST_DB_URL: &str = "postgres://buzz:buzz_dev@localhost:5432/buzz"; // sadscan:disable np.postgres.1

struct ObservedProduction {
    hash_after_install: u64,
    hash_after_prepare: u64,
    classified_miss: bool,
    hash_after_classify: u64,
    hash_after_begin: u64,
    hash_after_complete: u64,
    should_dispatch: bool,
    key_count: i64,
    event_count: i64,
}

async fn setup_pool() -> PgPool {
    let database_url = std::env::var("BUZZ_TEST_DATABASE_URL")
        .or_else(|_| std::env::var("TEST_DATABASE_URL"))
        .or_else(|_| std::env::var("DATABASE_URL"))
        .unwrap_or_else(|_| TEST_DB_URL.to_owned());
    PgPool::connect(&database_url)
        .await
        .expect("connect to test DB")
}

async fn make_test_community(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    let host = format!("semantic-intent-once-{}.example", id.simple());
    sqlx::query("INSERT INTO communities (id, host) VALUES ($1, $2)")
        .bind(id)
        .bind(host)
        .execute(pool)
        .await
        .expect("insert test community");
    id
}

fn unique_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    key[..16].copy_from_slice(Uuid::new_v4().as_bytes());
    key[16..].copy_from_slice(Uuid::new_v4().as_bytes());
    key
}

fn stream_event(keys: &Keys, content: &str, created_at: u64) -> Event {
    EventBuilder::new(Kind::Custom(9), content)
        .custom_created_at(Timestamp::from(created_at))
        .sign_with_keys(keys)
        .expect("sign")
}

async fn key_count(pool: &PgPool, community: Uuid) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar("SELECT count(*) FROM event_idempotency_keys WHERE community_id = $1")
        .bind(community)
        .fetch_one(pool)
        .await
}

async fn event_count(pool: &PgPool, community: Uuid) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar("SELECT count(*) FROM events WHERE community_id = $1")
        .bind(community)
        .fetch_one(pool)
        .await
}

async fn community_count(pool: &PgPool, community: Uuid) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar("SELECT count(*) FROM communities WHERE id = $1")
        .bind(community)
        .fetch_one(pool)
        .await
}

async fn mention_count(pool: &PgPool, community: Uuid) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar("SELECT count(*) FROM event_mentions WHERE community_id = $1")
        .bind(community)
        .fetch_one(pool)
        .await
}

async fn cleanup(pool: &PgPool, community: Uuid) -> Result<(), String> {
    let mut failures = Vec::new();

    if let Err(error) = sqlx::query("DELETE FROM event_mentions WHERE community_id = $1")
        .bind(community)
        .execute(pool)
        .await
    {
        failures.push(format!("delete event_mentions: {error}"));
    }
    if let Err(error) = sqlx::query("DELETE FROM event_idempotency_keys WHERE community_id = $1")
        .bind(community)
        .execute(pool)
        .await
    {
        failures.push(format!("delete event_idempotency_keys: {error}"));
    }
    if let Err(error) = sqlx::query("DELETE FROM events WHERE community_id = $1")
        .bind(community)
        .execute(pool)
        .await
    {
        failures.push(format!("delete events: {error}"));
    }
    if let Err(error) = sqlx::query("DELETE FROM communities WHERE id = $1")
        .bind(community)
        .execute(pool)
        .await
    {
        failures.push(format!("delete communities: {error}"));
    }

    match mention_count(pool, community).await {
        Ok(0) => {}
        Ok(remaining) => failures.push(format!(
            "event_mentions rows remain for community: {remaining}"
        )),
        Err(error) => failures.push(format!("count event_mentions: {error}")),
    }
    match key_count(pool, community).await {
        Ok(0) => {}
        Ok(remaining) => failures.push(format!(
            "event_idempotency_keys rows remain for community: {remaining}"
        )),
        Err(error) => failures.push(format!("count event_idempotency_keys: {error}")),
    }
    match event_count(pool, community).await {
        Ok(0) => {}
        Ok(remaining) => failures.push(format!("events rows remain for community: {remaining}")),
        Err(error) => failures.push(format!("count events: {error}")),
    }
    match community_count(pool, community).await {
        Ok(0) => {}
        Ok(remaining) => failures.push(format!("communities rows remain for id: {remaining}")),
        Err(error) => failures.push(format!("count communities: {error}")),
    }

    if failures.is_empty() {
        Ok(())
    } else {
        Err(failures.join("; "))
    }
}

fn join_error_message(error: tokio::task::JoinError) -> String {
    if error.is_cancelled() {
        return "production oracle task cancelled".to_owned();
    }
    let payload = error.into_panic();
    if let Some(message) = payload.downcast_ref::<&str>() {
        return format!("production oracle panicked: {message}");
    }
    if let Some(message) = payload.downcast_ref::<String>() {
        return format!("production oracle panicked: {message}");
    }
    "production oracle panicked".to_owned()
}

mod postgres_tests {
    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn keyed_miss_reserve_complete_hashes_semantic_intent_once() {
        super::keyed_miss_reserve_complete_hashes_semantic_intent_once().await;
    }
}

async fn keyed_miss_reserve_complete_hashes_semantic_intent_once() {
    let pool = setup_pool().await;
    let community_uuid = make_test_community(&pool).await;
    let community = CommunityId::from_uuid(community_uuid);
    let keys = Keys::generate();
    let key = unique_key();
    let event = stream_event(&keys, "prepare-once", 1_700_000_440);

    let pool_for_exercise = pool.clone();
    let production = match tokio::spawn(async move {
        let db = Db::from_pool(pool_for_exercise.clone());
        let watch = SemanticIntentHashWatch::install(*event.id.as_bytes());
        let hash_after_install = watch.count();
        let prepared = Db::prepare_keyed_stream_intent(key, &event).map_err(|e| e.to_string())?;
        let hash_after_prepare = watch.count();

        let classified = db
            .classify_keyed_stream_before_admission(community, &prepared, &event, None, None)
            .await
            .map_err(|e| e.to_string())?;
        let classified_miss = classified.is_none();
        let hash_after_classify = watch.count();

        let reservation = match db
            .begin_keyed_stream_reservation(community, &prepared, &event, None, None)
            .await
            .map_err(|e| e.to_string())?
        {
            KeyedReserveOutcome::Reserved(reservation) => *reservation,
            KeyedReserveOutcome::Replay { .. } => {
                return Err("fresh key must reserve, got replay".to_owned());
            }
            KeyedReserveOutcome::Conflict { .. } => {
                return Err("fresh key must reserve, got conflict".to_owned());
            }
        };
        let hash_after_begin = watch.count();

        let inserted = reservation
            .complete(&prepared, &event, None)
            .await
            .map_err(|e| e.to_string())?;
        let hash_after_complete = watch.count();
        Ok::<ObservedProduction, String>(ObservedProduction {
            hash_after_install,
            hash_after_prepare,
            classified_miss,
            hash_after_classify,
            hash_after_begin,
            hash_after_complete,
            should_dispatch: inserted.should_dispatch(),
            key_count: key_count(&pool_for_exercise, community_uuid)
                .await
                .map_err(|e| e.to_string())?,
            event_count: event_count(&pool_for_exercise, community_uuid)
                .await
                .map_err(|e| e.to_string())?,
        })
    })
    .await
    {
        Ok(Ok(observed)) => Ok(observed),
        Ok(Err(error)) => Err(error),
        Err(join) => Err(join_error_message(join)),
    };

    let cleanup = cleanup(&pool, community_uuid).await;
    pool.close().await;

    if let Err(error) = cleanup {
        match production {
            Ok(_) => panic!("scoped cleanup failed: {error}"),
            Err(prod) => panic!("{prod}; scoped cleanup also failed: {error}"),
        }
    }

    let observed = match production {
        Ok(observed) => observed,
        Err(error) => panic!("{error}"),
    };

    assert_eq!(observed.hash_after_install, 0);
    assert_eq!(
        observed.hash_after_prepare, 1,
        "prepare_keyed_stream_intent must hash semantic intent exactly once"
    );
    assert!(
        observed.classified_miss,
        "fresh key must miss before admission"
    );
    assert_eq!(
        observed.hash_after_classify, 1,
        "classify must reuse the prepared value"
    );
    assert_eq!(
        observed.hash_after_begin, 1,
        "begin must reuse the prepared value"
    );
    assert_eq!(
        observed.hash_after_complete, 1,
        "complete must reuse the prepared value"
    );
    assert!(observed.should_dispatch);
    assert_eq!(observed.key_count, 1);
    assert_eq!(observed.event_count, 1);
}
