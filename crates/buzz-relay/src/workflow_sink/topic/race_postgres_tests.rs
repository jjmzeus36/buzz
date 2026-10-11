use super::*;
use std::time::Duration;

// Observe the production statement waiting on a real database lock. Unlike a
// fixed sleep, this proves the contender has reached the authorization seam.
async fn wait_for_topic_lock(
    state: &AppState,
    task: &tokio::task::JoinHandle<Result<(), ActionSinkError>>,
) {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let mut probe = state.db.begin_event_write_transaction().await.unwrap();
            assert!(
                !task.is_finished(),
                "topic write bypassed the held authority fence"
            );
            let blocked: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM pg_stat_activity \
                 WHERE datname = current_database() AND pid <> pg_backend_pid() \
                 AND wait_event_type = 'Lock')",
            )
            .fetch_one(&mut *probe)
            .await
            .unwrap();
            if blocked {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("topic statement reached the held lock");
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn workflow_topic_rechecks_member_removal_committed_during_authorization() {
    let (state, community, channel, owner) = super::postgres_tests::fixture().await;
    let mut removal = state.db.begin_event_write_transaction().await.unwrap();
    sqlx::query(
        "UPDATE channel_members SET removed_at = NOW() \
         WHERE community_id = $1 AND channel_id = $2 AND pubkey = $3",
    )
    .bind(community.as_uuid())
    .bind(channel)
    .bind(owner.public_key().to_bytes().as_slice())
    .execute(&mut *removal)
    .await
    .unwrap();
    let contender = Arc::clone(&state);
    let task = tokio::spawn(async move {
        RelayActionSink::new(&contender)
            .set_channel_topic(
                community,
                &channel.to_string(),
                "revoked in flight",
                &owner.public_key().to_hex(),
            )
            .await
    });
    wait_for_topic_lock(&state, &task).await;
    removal.commit().await.unwrap();
    assert!(tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .unwrap()
        .unwrap()
        .is_err());
    assert!(state
        .db
        .get_channel(community, channel)
        .await
        .unwrap()
        .topic
        .is_none());
    let mut probe = state.db.begin_event_write_transaction().await.unwrap();
    let notices: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM events WHERE community_id = $1 AND channel_id = $2 AND kind = $3",
    )
    .bind(community.as_uuid())
    .bind(channel)
    .bind(KIND_SYSTEM_MESSAGE as i32)
    .fetch_one(&mut *probe)
    .await
    .unwrap();
    assert_eq!(notices, 0);
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn workflow_topic_takes_ttl_fence_before_channel_row() {
    let (state, community, channel, owner) = super::postgres_tests::fixture().await;
    let mut ttl_change = state.db.begin_event_write_transaction().await.unwrap();
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind(format!(
            "buzz_channel_ttl:{}:{}",
            community.as_uuid(),
            channel
        ))
        .execute(&mut *ttl_change)
        .await
        .unwrap();
    let contender = Arc::clone(&state);
    let task = tokio::spawn(async move {
        RelayActionSink::new(&contender)
            .set_channel_topic(
                community,
                &channel.to_string(),
                "after ttl",
                &owner.public_key().to_hex(),
            )
            .await
    });
    wait_for_topic_lock(&state, &task).await;
    // A TTL writer holds the advisory fence before updating the channel. The
    // topic writer must not already hold that row while waiting for the fence.
    tokio::time::timeout(
        Duration::from_secs(5),
        sqlx::query("UPDATE channels SET ttl_seconds = 3600 WHERE community_id = $1 AND id = $2")
            .bind(community.as_uuid())
            .bind(channel)
            .execute(&mut *ttl_change),
    )
    .await
    .expect("TTL update must not deadlock with topic event insertion")
    .unwrap();
    ttl_change.commit().await.unwrap();
    tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let saved = state.db.get_channel(community, channel).await.unwrap();
    assert_eq!(saved.topic.as_deref(), Some("after ttl"));
    assert!(saved.ttl_deadline.is_some());
}

fn metadata_lock_key(community: CommunityId, channel: Uuid, relay_pubkey: &[u8]) -> i64 {
    // Same canonical coordinate as the real replacement lock. The blocking
    // barrier below also proves that production writers acquire this key.
    let mut hash = 0xcbf29ce484222325u64;
    for bytes in [
        community.as_uuid().as_bytes().as_slice(),
        &39000i32.to_le_bytes(),
        relay_pubkey,
        channel.as_bytes(),
    ] {
        for byte in bytes {
            hash = (hash ^ u64::from(*byte)).wrapping_mul(0x100000001b3);
        }
    }
    hash as i64
}

fn topic_metadata(state: &AppState, channel: Uuid, topic: &str, timestamp: u64) -> nostr::Event {
    EventBuilder::new(Kind::Custom(39000), "")
        .tags([
            Tag::parse(["d", &channel.to_string()]).unwrap(),
            Tag::parse(["name", "topic-test"]).unwrap(),
            Tag::parse(["public"]).unwrap(),
            Tag::parse(["closed"]).unwrap(),
            Tag::parse(["t", "stream"]).unwrap(),
            Tag::parse(["topic", topic]).unwrap(),
        ])
        .custom_created_at(nostr::Timestamp::from(timestamp))
        .sign_with_keys(&state.relay_keypair)
        .unwrap()
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn workflow_topic_metadata_capture_waits_for_replacement_lock_and_cannot_overwrite_newer_topic(
) {
    let (state, community, channel, owner) = super::postgres_tests::fixture().await;
    let timestamp = nostr::Timestamp::now().as_secs() + 600;
    let topic_b = "newer topic B";
    let event_b = topic_metadata(&state, channel, topic_b, timestamp);
    // Against the old capture-before-lock path, both writers would allocate
    // this same timestamp and the stale A would win regardless of lock order.
    let topic_a = (0..256)
        .map(|index| format!("older topic A {index}"))
        .find(|topic| topic_metadata(&state, channel, topic, timestamp).id < event_b.id)
        .expect("a lower-ID stale candidate");
    let seed = topic_metadata(&state, channel, "seed", timestamp - 1);
    state
        .db
        .replace_addressable_event(community, &seed, Some(channel))
        .await
        .unwrap();
    let mut guard = state.db.begin_event_write_transaction().await.unwrap();
    let guard_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *guard)
        .await
        .unwrap();
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(metadata_lock_key(
            community,
            channel,
            &state.relay_keypair.public_key().to_bytes(),
        ))
        .execute(&mut *guard)
        .await
        .unwrap();
    let mut tasks = Vec::new();
    for (index, topic) in [topic_a, topic_b.to_string()].into_iter().enumerate() {
        let contender = Arc::clone(&state);
        let author = owner.public_key().to_hex();
        tasks.push(tokio::spawn(async move {
            RelayActionSink::new(&contender)
                .set_channel_topic(community, &channel.to_string(), &topic, &author)
                .await
        }));
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                assert!(tasks.iter().all(|task| !task.is_finished()), "metadata writer bypassed the canonical replacement guard");
                let mut probe = state.db.begin_event_write_transaction().await.unwrap();
                let waiting: i64 = sqlx::query_scalar(
                    "SELECT COUNT(*) FROM pg_stat_activity WHERE datname = current_database() AND $1 = ANY(pg_blocking_pids(pid))",
                ).bind(guard_pid).fetch_one(&mut *probe).await.unwrap();
                if waiting == (index + 1) as i64 { break; }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        }).await.expect("production metadata publishers reached the held canonical lock");
    }
    assert_eq!(
        state
            .db
            .get_channel(community, channel)
            .await
            .unwrap()
            .topic
            .as_deref(),
        Some(topic_b)
    );
    guard.commit().await.unwrap();
    for task in tasks {
        tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }
    let metadata = super::postgres_tests::events(&state, community, channel, 39000).await;
    assert_eq!(metadata.len(), 1);
    assert!(
        metadata[0]
            .event
            .tags
            .iter()
            .any(|tag| tag.as_slice() == ["topic", topic_b]),
        "stale metadata replaced the current topic"
    );
}
