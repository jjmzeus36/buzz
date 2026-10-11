use super::*;
use crate::Db;
use nostr::{EventBuilder, Keys, Kind, Timestamp};
use sqlx::PgPool;
use uuid::Uuid;

async fn fixture() -> (PgPool, Db, CommunityId, Keys) {
    let pool = PgPool::connect(&crate::test_support::database_url())
        .await
        .expect("database");
    let community = CommunityId::from_uuid(Uuid::new_v4());
    sqlx::query("INSERT INTO communities (id, host) VALUES ($1, $2)")
        .bind(community.as_uuid())
        .bind(format!("profile-{}.example", community))
        .execute(&pool)
        .await
        .expect("community");
    (
        pool.clone(),
        Db::from_pool(pool),
        community,
        Keys::generate(),
    )
}

fn event(keys: &Keys, name: &str, timestamp: u64) -> nostr::Event {
    EventBuilder::new(
        Kind::Metadata,
        serde_json::json!({"display_name": name}).to_string(),
    )
    .custom_created_at(Timestamp::from(timestamp))
    .sign_with_keys(keys)
    .expect("event")
}

fn profile(name: &str) -> ProfileMetadata {
    ProfileMetadata {
        display_name: Some(name.to_owned()),
        ..Default::default()
    }
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn profile_failure_rolls_back_event_and_retry_completes_atomically() {
    let (pool, db, community, keys) = fixture().await;
    let first = event(&keys, "first", 1780000000);
    db.replace_profile_event(community, &first, &profile("first"))
        .await
        .expect("first");
    sqlx::raw_sql("CREATE FUNCTION reject_profile_probe() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected profile failure'; END $$; CREATE TRIGGER reject_profile_probe BEFORE UPDATE ON users FOR EACH ROW EXECUTE FUNCTION reject_profile_probe();")
        .execute(&pool).await.expect("install failure");
    let next = event(&keys, "next", 1780000001);
    assert!(db
        .replace_profile_event(community, &next, &profile("next"))
        .await
        .is_err());
    let live: Vec<u8> =
        sqlx::query_scalar("SELECT id FROM events WHERE community_id=$1 AND deleted_at IS NULL")
            .bind(community.as_uuid())
            .fetch_one(&pool)
            .await
            .expect("live event");
    assert_eq!(live, first.id.to_bytes());
    sqlx::raw_sql(
        "DROP TRIGGER reject_profile_probe ON users; DROP FUNCTION reject_profile_probe();",
    )
    .execute(&pool)
    .await
    .expect("remove failure");
    assert!(
        db.replace_profile_event(community, &next, &profile("next"))
            .await
            .expect("retry")
            .1
    );
    let row: (String, Vec<u8>) =
        sqlx::query_as("SELECT display_name, metadata_event_id FROM users WHERE community_id=$1")
            .bind(community.as_uuid())
            .fetch_one(&pool)
            .await
            .expect("projection");
    assert_eq!(row, ("next".to_owned(), next.id.to_bytes().to_vec()));
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn concurrent_and_stale_profiles_always_match_winning_event() {
    let (pool, db, community, keys) = fixture().await;
    let old = event(&keys, "old", 1780000000);
    let new = event(&keys, "new", 1780000001);
    let old_profile = profile("old");
    let new_profile = profile("new");
    let (a, b) = tokio::join!(
        db.replace_profile_event(community, &old, &old_profile),
        db.replace_profile_event(community, &new, &new_profile)
    );
    a.expect("old request");
    b.expect("new request");
    assert!(
        !db.replace_profile_event(community, &old, &old_profile)
            .await
            .expect("stale retry")
            .1
    );
    let row: (String, Vec<u8>) =
        sqlx::query_as("SELECT display_name, metadata_event_id FROM users WHERE community_id=$1")
            .bind(community.as_uuid())
            .fetch_one(&pool)
            .await
            .expect("projection");
    assert_eq!(row, ("new".to_owned(), new.id.to_bytes().to_vec()));
    let too_long = "x".repeat(256);
    assert!(db
        .replace_profile_event(
            community,
            &event(&keys, &too_long, 1780000002),
            &profile(&too_long)
        )
        .await
        .is_err());
    let head: Vec<u8> =
        sqlx::query_scalar("SELECT id FROM events WHERE community_id=$1 AND deleted_at IS NULL")
            .bind(community.as_uuid())
            .fetch_one(&pool)
            .await
            .expect("head");
    assert_eq!(head, new.id.to_bytes());
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn contested_nip05_preserves_handle_but_commits_other_profile_fields() {
    let (pool, db, community, keys) = fixture().await;
    let other = Keys::generate();
    let claimed = ProfileMetadata {
        nip05_handle: Some("taken@example.com".into()),
        ..profile("owner")
    };
    db.replace_profile_event(community, &event(&other, "owner", 1780000000), &claimed)
        .await
        .expect("claim");
    let old = ProfileMetadata {
        nip05_handle: Some("mine@example.com".into()),
        ..profile("old")
    };
    db.replace_profile_event(community, &event(&keys, "old", 1780000000), &old)
        .await
        .expect("own handle");
    let contested = ProfileMetadata {
        display_name: Some("new".into()),
        ..claimed
    };
    db.replace_profile_event(community, &event(&keys, "new", 1780000001), &contested)
        .await
        .expect("contested");
    let row: (String, String) = sqlx::query_as(
        "SELECT display_name,nip05_handle FROM users WHERE community_id=$1 AND pubkey=$2",
    )
    .bind(community.as_uuid())
    .bind(keys.public_key().to_bytes().as_slice())
    .fetch_one(&pool)
    .await
    .expect("projection");
    assert_eq!(row, ("new".to_owned(), "mine@example.com".to_owned()));
    db.replace_profile_event(
        community,
        &event(&keys, "", 1780000002),
        &ProfileMetadata::default(),
    )
    .await
    .expect("clear");
    let cleared: bool = sqlx::query_scalar("SELECT display_name IS NULL AND nip05_handle IS NULL FROM users WHERE community_id=$1 AND pubkey=$2")
        .bind(community.as_uuid()).bind(keys.public_key().to_bytes().as_slice()).fetch_one(&pool).await.expect("cleared");
    assert!(cleared);
}
