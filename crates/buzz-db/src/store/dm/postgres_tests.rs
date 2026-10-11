use super::*;

#[tokio::test]
#[ignore = "requires Postgres"]
async fn concurrent_open_returns_one_complete_dm_and_one_created_flag() {
    let pool = PgPool::connect(&crate::test_support::database_url())
        .await
        .expect("database");
    let community = CommunityId::from_uuid(Uuid::new_v4());
    sqlx::query("INSERT INTO communities (id,host) VALUES ($1,$2)")
        .bind(community.as_uuid())
        .bind(format!("dm-{}.example", community))
        .execute(&pool)
        .await
        .expect("community");
    // Hold each insert long enough that unfenced SELECT/INSERT callers overlap.
    sqlx::raw_sql("CREATE FUNCTION delay_dm_probe() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_sleep(0.1); RETURN NEW; END $$; CREATE TRIGGER delay_dm_probe BEFORE INSERT ON channels FOR EACH ROW EXECUTE FUNCTION delay_dm_probe();")
        .execute(&pool).await.expect("delay trigger");
    let a = [1u8; 32];
    let b = [2u8; 32];
    let participants: &[&[u8]] = &[&a, &b];
    let (first, second) = tokio::join!(
        open_dm(&pool, community, participants, &a),
        open_dm(&pool, community, participants, &b)
    );
    let first = first.expect("first open");
    let second = second.expect("second open");
    assert_eq!(first.0.id, second.0.id);
    assert_ne!(first.1, second.1, "exactly one request created the DM");
    let count:i64 = sqlx::query_scalar("SELECT count(*) FROM channel_members WHERE community_id=$1 AND channel_id=$2 AND removed_at IS NULL")
        .bind(community.as_uuid()).bind(first.0.id).fetch_one(&pool).await.expect("roster");
    assert_eq!(count, 2);
    assert_eq!(
        open_dm(&pool, community, &[&a, &a, &b], &a)
            .await
            .expect("duplicate input")
            .0
            .id,
        first.0.id
    );
    assert!(create_dm(&pool, community, participants, &[3u8; 32])
        .await
        .is_err());
    sqlx::raw_sql("DROP TRIGGER delay_dm_probe ON channels; DROP FUNCTION delay_dm_probe();")
        .execute(&pool)
        .await
        .expect("remove trigger");
}
