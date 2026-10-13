//! Live destructive versioned-bucket deletion coverage against a local S3 fixture.
//!
//! This exercises the S3-compatible path that community deletion relies on when
//! a bucket has versioning enabled: list object versions/delete markers with
//! dual markers, delete exact `(Key, VersionId)` identifiers, retry an already
//! deleted version, and prove final `ListObjectVersions` emptiness.
//!
//! Run it against the docker-compose MinIO (creds `buzz_dev`/`buzz_dev_secret`):
//!
//! ```bash
//! docker compose up -d minio minio-init
//! cargo test -p buzz-media --test versioned_minio -- --ignored --nocapture
//! ```
//!
//! The test creates and removes its own bucket using the AWS CLI (`aws` on PATH).
//! Credentials/endpoint/region/addressing use the same `BUZZ_S3_*` env vars as
//! `static_creds_minio`. No vendor-specific client or container name is required.

use std::process::Command;

use buzz_media::config::MediaConfig;
use buzz_media::storage::{MediaStorage, ObjectVersionKind, ObjectVersionRef};

fn env_or(name: &str, default: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| default.to_string())
}

fn minio_config(bucket: String) -> MediaConfig {
    MediaConfig {
        s3_endpoint: env_or("BUZZ_S3_ENDPOINT", "http://localhost:9000"),
        s3_access_key: env_or("BUZZ_S3_ACCESS_KEY", "buzz_dev"),
        s3_secret_key: env_or("BUZZ_S3_SECRET_KEY", "buzz_dev_secret"),
        s3_bucket: bucket,
        s3_region: env_or("BUZZ_S3_REGION", "us-east-1"),
        s3_addressing_style: env_or("BUZZ_S3_ADDRESSING_STYLE", "path")
            .parse()
            .expect("BUZZ_S3_ADDRESSING_STYLE must be path or virtual"),
        max_image_bytes: 50 * 1024 * 1024,
        max_gif_bytes: 10 * 1024 * 1024,
        max_video_bytes: 524_288_000,
        max_file_bytes: 104_857_600,
        public_base_url: "http://localhost:3000/media".to_string(),
        upload_records_enabled: false,
        upload_ip_header: None,
        upload_port_header: None,
    }
}

// Use the public S3 administration API instead of executing MinIO's bundled
// client inside a particular container. This also exercises maintained S3
// fixtures such as RustFS. Only synthetic test buckets are created here.
fn run_s3_admin(config: &MediaConfig, args: &[&str]) -> Result<(), String> {
    let output = Command::new("aws")
        .args([
            "--endpoint-url",
            &config.s3_endpoint,
            "--region",
            &config.s3_region,
        ])
        .args([
            "--no-cli-pager",
            "--cli-connect-timeout",
            "10",
            "--cli-read-timeout",
            "30",
            "s3api",
        ])
        .args(args)
        .env("AWS_ACCESS_KEY_ID", &config.s3_access_key)
        .env("AWS_SECRET_ACCESS_KEY", &config.s3_secret_key)
        .env_remove("AWS_SESSION_TOKEN")
        .env("AWS_EC2_METADATA_DISABLED", "true")
        .output()
        .map_err(|err| format!("failed to execute AWS CLI: {err}"))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(format!(
            "S3 administration failed with status {}\nstdout:\n{}\nstderr:\n{}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ))
    }
}

async fn list_all_versions(
    storage: &MediaStorage,
    prefix: &str,
    max_keys: usize,
) -> Vec<buzz_media::storage::ObjectVersionEntry> {
    let mut entries = Vec::new();
    let mut key_marker = None;
    let mut version_id_marker = None;
    loop {
        let page = storage
            .list_prefix_versions_page(
                prefix,
                key_marker.take(),
                version_id_marker.take(),
                max_keys,
            )
            .await
            .expect("list object versions page");
        if page.is_truncated {
            assert!(
                page.next_key_marker.is_some(),
                "truncated ListObjectVersions page must include NextKeyMarker"
            );
            assert!(
                page.next_version_id_marker.is_some(),
                "truncated ListObjectVersions page must include NextVersionIdMarker"
            );
        }
        entries.extend(page.entries);
        if !page.is_truncated {
            break;
        }
        key_marker = page.next_key_marker;
        version_id_marker = page.next_version_id_marker;
    }
    entries
}

fn refs_from(entries: &[buzz_media::storage::ObjectVersionEntry]) -> Vec<ObjectVersionRef> {
    entries
        .iter()
        .map(|entry| ObjectVersionRef {
            key: entry.key.clone(),
            version_id: entry.version_id.clone(),
        })
        .collect()
}

#[tokio::test]
#[ignore = "requires local S3 fixture and AWS CLI; permanently deletes exact test object versions"]
async fn never_versioned_bucket_lists_null_versions_and_exact_delete_empties_listing() {
    let bucket = format!("buzz-media-never-versioned-{}", std::process::id());
    let config = minio_config(bucket.clone());
    run_s3_admin(&config, &["create-bucket", "--bucket", &bucket])
        .expect("create isolated never-versioned test bucket");

    let storage = MediaStorage::new(&config).expect("static MinIO storage client");
    let prefix = format!("_test/never-versioned-{}/", uuid::Uuid::new_v4());
    let key = format!("{prefix}plain.bin");
    storage
        .put(&key, b"plain", "application/octet-stream")
        .await
        .expect("put never-versioned object");

    let listed = list_all_versions(&storage, &prefix, 2).await;
    assert_eq!(
        listed,
        vec![buzz_media::storage::ObjectVersionEntry {
            key: key.clone(),
            version_id: "null".to_string(),
            kind: ObjectVersionKind::Object,
            size: 5,
        }],
        "never-versioned buckets must still enumerate exact null-version objects"
    );

    let delete = storage
        .delete_object_versions(&refs_from(&listed))
        .await
        .expect("delete exact null-version object");
    assert!(delete.failed.is_empty(), "{delete:?}");
    assert!(delete.versioned_keys.is_empty(), "{delete:?}");
    assert_eq!(
        delete.deleted + delete.already_missing,
        1,
        "exact null-version delete must account for the listed object"
    );
    assert!(
        list_all_versions(&storage, &prefix, 2).await.is_empty(),
        "final ListObjectVersions must be empty after deleting the exact null version"
    );

    run_s3_admin(&config, &["delete-bucket", "--bucket", &bucket])
        .expect("remove isolated never-versioned test bucket");
}

#[tokio::test]
#[ignore = "requires local S3 fixture and AWS CLI; permanently deletes exact test object versions"]
async fn versioned_bucket_exact_version_delete_reaches_final_list_versions_emptiness() {
    let bucket = format!("buzz-media-versioned-{}", std::process::id());
    let config = minio_config(bucket.clone());
    run_s3_admin(&config, &["create-bucket", "--bucket", &bucket])
        .expect("create isolated versioned test bucket");
    run_s3_admin(
        &config,
        &[
            "put-bucket-versioning",
            "--bucket",
            &bucket,
            "--versioning-configuration",
            "Status=Enabled",
        ],
    )
    .expect("enable bucket versioning");

    let storage = MediaStorage::new(&config).expect("static MinIO storage client");
    let prefix = format!("_test/versioned-{}/", uuid::Uuid::new_v4());
    let historical_key = format!("{prefix}historical.bin");
    let marker_only_key = format!("{prefix}marker-only.bin");
    let paginated_key = format!("{prefix}paginated.bin");

    storage
        .put(&historical_key, b"v1", "application/octet-stream")
        .await
        .expect("put historical v1");
    storage
        .put(&historical_key, b"v2", "application/octet-stream")
        .await
        .expect("put historical v2");
    storage
        .delete(&historical_key)
        .await
        .expect("delete historical current version creates delete marker");
    storage
        .put(&marker_only_key, b"marker-base", "application/octet-stream")
        .await
        .expect("put marker-only base version");
    storage
        .delete(&marker_only_key)
        .await
        .expect("delete current version creates marker-only delete marker");
    let marker_versions = list_all_versions(&storage, &marker_only_key, 2).await;
    let marker_objects: Vec<ObjectVersionRef> = marker_versions
        .iter()
        .filter(|entry| entry.kind == ObjectVersionKind::Object)
        .map(|entry| ObjectVersionRef {
            key: entry.key.clone(),
            version_id: entry.version_id.clone(),
        })
        .collect();
    assert_eq!(
        marker_objects.len(),
        1,
        "marker-only setup should have one object version: {marker_versions:?}"
    );
    let marker_object_delete = storage
        .delete_object_versions(&marker_objects)
        .await
        .expect("delete marker-only base object version");
    assert!(
        marker_object_delete.failed.is_empty(),
        "{marker_object_delete:?}"
    );
    assert!(
        marker_object_delete.versioned_keys.is_empty(),
        "{marker_object_delete:?}"
    );
    storage
        .put(&paginated_key, b"page-a", "application/octet-stream")
        .await
        .expect("put paginated v1");
    storage
        .put(&paginated_key, b"page-b", "application/octet-stream")
        .await
        .expect("put paginated v2");

    let listed = list_all_versions(&storage, &prefix, 2).await;
    assert!(
        listed.len() >= 6,
        "expected multiple versions/delete markers across small pages, got {listed:?}"
    );
    assert!(listed.iter().any(|entry| {
        entry.key == historical_key && entry.kind == ObjectVersionKind::Object && entry.size == 2
    }));
    assert!(listed.iter().any(|entry| {
        entry.key == historical_key && entry.kind == ObjectVersionKind::DeleteMarker
    }));
    assert!(listed.iter().any(|entry| {
        entry.key == marker_only_key && entry.kind == ObjectVersionKind::DeleteMarker
    }));

    let refs = refs_from(&listed);
    let first_chunk = &refs[..2.min(refs.len())];
    let first_delete = storage
        .delete_object_versions(first_chunk)
        .await
        .expect("delete first explicit version chunk");
    assert!(first_delete.failed.is_empty(), "{first_delete:?}");
    assert!(first_delete.versioned_keys.is_empty(), "{first_delete:?}");
    assert_eq!(
        first_delete.deleted + first_delete.already_missing,
        first_chunk.len() as u64,
        "explicit version delete should account for every requested identifier"
    );

    let retry = storage
        .delete_object_versions(&first_chunk[..1])
        .await
        .expect("retry already-deleted explicit version");
    assert!(retry.failed.is_empty(), "{retry:?}");
    assert!(retry.versioned_keys.is_empty(), "{retry:?}");
    assert_eq!(
        retry.deleted + retry.already_missing,
        1,
        "retry should be idempotently accounted as deleted/already missing"
    );

    let rest_delete = storage
        .delete_object_versions(&refs[first_chunk.len()..])
        .await
        .expect("delete remaining explicit versions");
    assert!(rest_delete.failed.is_empty(), "{rest_delete:?}");
    assert!(rest_delete.versioned_keys.is_empty(), "{rest_delete:?}");
    assert_eq!(
        rest_delete.deleted + rest_delete.already_missing,
        (refs.len() - first_chunk.len()) as u64,
        "remaining explicit version delete should account for every requested identifier"
    );

    let remaining = list_all_versions(&storage, &prefix, 2).await;
    assert!(
        remaining.is_empty(),
        "final ListObjectVersions must be empty after exact-version deletion: {remaining:?}"
    );

    if run_s3_admin(
        &config,
        &[
            "put-bucket-versioning",
            "--bucket",
            &bucket,
            "--versioning-configuration",
            "Status=Suspended",
        ],
    )
    .is_ok()
    {
        let suspended_key = format!("{prefix}suspended.bin");
        storage
            .put(&suspended_key, b"suspended", "application/octet-stream")
            .await
            .expect("put suspended-versioning object");
        storage
            .delete(&suspended_key)
            .await
            .expect("delete suspended-versioning object");
        let suspended_entries = list_all_versions(&storage, &prefix, 2).await;
        assert!(
            suspended_entries
                .iter()
                .any(|entry| entry.key == suspended_key),
            "suspended-versioning write/delete should be visible to ListObjectVersions"
        );
        let suspended_delete = storage
            .delete_object_versions(&refs_from(&suspended_entries))
            .await
            .expect("delete suspended-versioning entries by explicit version id");
        assert!(suspended_delete.failed.is_empty(), "{suspended_delete:?}");
        assert!(
            suspended_delete.versioned_keys.is_empty(),
            "{suspended_delete:?}"
        );
        let suspended_remaining = list_all_versions(&storage, &prefix, 2).await;
        assert!(
            suspended_remaining.is_empty(),
            "suspended entries {suspended_entries:?}; delete {suspended_delete:?}; remaining {suspended_remaining:?}"
        );
    } else {
        eprintln!("S3 fixture did not support version suspend; enabled-versioning coverage passed");
    }

    run_s3_admin(&config, &["delete-bucket", "--bucket", &bucket])
        .expect("remove isolated versioned test bucket");
}
