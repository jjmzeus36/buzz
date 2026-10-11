use crate::handlers::ingest::{ingest_event, IngestAuth, IngestError};
use buzz_auth::Scope;
use buzz_core::{CommunityId, TenantContext};
use nostr::{EventBuilder, Keys, Kind, Timestamp};
use uuid::Uuid;

#[tokio::test]
#[ignore = "requires Postgres"]
async fn ingest_profile_rolls_back_failed_projection_and_retries_signed_event() {
    let redis_url = std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".into());
    let state = crate::test_support::app_state(&redis_url).await;
    let pool = sqlx::PgPool::connect(&crate::test_support::database_url())
        .await
        .expect("database");
    let community = CommunityId::from_uuid(Uuid::new_v4());
    let host = format!("profile-{}.example", community);
    sqlx::query("INSERT INTO communities (id,host) VALUES ($1,$2)")
        .bind(community.as_uuid())
        .bind(&host)
        .execute(&pool)
        .await
        .expect("community");
    let tenant = TenantContext::resolved(community, &host);
    let keys = Keys::generate();
    let auth = || IngestAuth::Nip42 {
        moderation_owner: None,
        pubkey: keys.public_key(),
        scopes: Scope::all_non_admin(),
        channel_ids: None,
        conn_id: Uuid::new_v4(),
    };
    let now = Timestamp::now().as_secs();
    let make = |name: &str, time: u64| {
        EventBuilder::new(
            Kind::Metadata,
            serde_json::json!({"display_name":name,"nip05":format!("Alice@{host}")}).to_string(),
        )
        .custom_created_at(Timestamp::from(time))
        .sign_with_keys(&keys)
        .expect("signed profile")
    };
    let first = make("first", now);
    assert!(
        ingest_event(&state, &tenant, first.clone(), auth())
            .await
            .expect("first profile")
            .accepted
    );
    sqlx::raw_sql("CREATE FUNCTION reject_ingest_profile_probe() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected projection outage'; END $$; CREATE TRIGGER reject_ingest_profile_probe BEFORE UPDATE ON users FOR EACH ROW EXECUTE FUNCTION reject_ingest_profile_probe();")
        .execute(&pool).await.expect("inject outage");
    let next = make("next", now + 1);
    assert!(matches!(
        ingest_event(&state, &tenant, next.clone(), auth()).await,
        Err(IngestError::Internal(_))
    ));
    let head: Vec<u8> = sqlx::query_scalar(
        "SELECT id FROM events WHERE community_id=$1 AND kind=0 AND deleted_at IS NULL",
    )
    .bind(community.as_uuid())
    .fetch_one(&pool)
    .await
    .expect("winning event");
    assert_eq!(head, first.id.to_bytes());
    sqlx::raw_sql("DROP TRIGGER reject_ingest_profile_probe ON users; DROP FUNCTION reject_ingest_profile_probe();")
        .execute(&pool).await.expect("recover");
    assert!(
        ingest_event(&state, &tenant, next.clone(), auth())
            .await
            .expect("retry")
            .accepted
    );
    assert!(
        ingest_event(&state, &tenant, first, auth())
            .await
            .expect("old retry")
            .accepted
    );
    let row:(String,String,Vec<u8>)=sqlx::query_as("SELECT display_name,nip05_handle,metadata_event_id FROM users WHERE community_id=$1 AND pubkey=$2")
        .bind(community.as_uuid()).bind(keys.public_key().to_bytes().as_slice()).fetch_one(&pool).await.expect("profile");
    assert_eq!(
        row,
        (
            "next".into(),
            format!("alice@{host}"),
            next.id.to_bytes().to_vec()
        )
    );
    let invalid = make(&"x".repeat(256), now + 2);
    assert!(matches!(
        ingest_event(&state, &tenant, invalid, auth()).await,
        Err(IngestError::Rejected(_))
    ));
}
