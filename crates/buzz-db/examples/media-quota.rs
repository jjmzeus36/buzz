//! Offline-verified media baseline/recovery tool. Dry run is the default.
use buzz_core::CommunityId;
use buzz_db::{media_quota::BaselineObject, Db};
use serde::Deserialize;
use uuid::Uuid;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    community_id: Uuid,
    pubkey: String,
    evidence: String,
    /// Human attestation, never synthesized from an empty ledger.
    complete_history_verified: bool,
    /// All upload writers stopped throughout enrollment and activation.
    upload_writers_stopped: bool,
    baseline_id: Uuid,
    /// Exact approved per-owner limit; bound to this epoch in the ledger.
    limit_bytes: i64,
    objects: Vec<BaselineObject>,
}
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() || args.len() > 3 || !matches!(args[0].as_str(), "enroll" | "recover") {
        return Err("usage: media-quota enroll|recover MANIFEST.json [--apply]".into());
    }
    let path = args.get(1).ok_or("manifest path required")?;
    let apply = match args.get(2).map(String::as_str) {
        None => false,
        Some("--apply") => true,
        _ => return Err("only --apply is supported".into()),
    };
    use std::io::Read;
    let mut bytes = Vec::new();
    std::fs::File::open(path)?
        .take(8 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > 8 * 1024 * 1024 {
        return Err("manifest exceeds 8 MiB".into());
    }
    if args[0] == "recover" {
        let r: Recovery = serde_json::from_slice(&bytes)?;
        let key = key(&r.pubkey)?;
        if r.evidence.trim().is_empty() || r.evidence.len() > 4096 || !hash_valid(&r.sha256) {
            return Err("invalid recovery manifest".into());
        }
        println!(
            "{}: retain charge and permit retry for exact operation {}",
            if apply { "APPLY" } else { "DRY RUN" },
            r.operation_id
        );
        if apply {
            db().await?
                .recover_media_quota(
                    CommunityId::from_uuid(r.community_id),
                    &key,
                    &r.sha256,
                    r.operation_id,
                    &r.evidence,
                )
                .await?;
        }
        return Ok(());
    }
    let m: Manifest = serde_json::from_slice(&bytes)?;
    let key = key(&m.pubkey)?;
    if !m.complete_history_verified
        || !m.upload_writers_stopped
        || m.baseline_id.is_nil()
        || m.limit_bytes <= 0
        || m.evidence.trim().is_empty()
        || m.evidence.len() > 4096
    {
        return Err("explicit complete-history and stopped-writer attestations, epoch, and evidence required".into());
    }
    let mut hashes = std::collections::HashSet::new();
    let mut total: u128 = 0;
    for o in &m.objects {
        if !hash_valid(&o.sha256) || o.size_bytes > i64::MAX as u64 || !hashes.insert(&o.sha256) {
            return Err("invalid or duplicate baseline object".into());
        }
        total += u128::from(o.size_bytes);
    }
    println!(
        "{}: operator-attested baseline has {} unique hashes / {} logical bytes; epoch {}",
        if apply { "APPLY" } else { "DRY RUN" },
        m.objects.len(),
        total,
        m.baseline_id
    );
    if apply {
        db().await?
            .enroll_media_quota(
                CommunityId::from_uuid(m.community_id),
                &key,
                buzz_db::media_quota::QuotaPolicy {
                    baseline_id: m.baseline_id,
                    limit: m.limit_bytes,
                },
                &m.evidence,
                &m.objects,
            )
            .await?;
    }
    Ok(())
}
fn key(value: &str) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    Ok(hex::decode(value)?
        .try_into()
        .map_err(|_| "pubkey must contain 32 bytes")?)
}
fn hash_valid(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
async fn db() -> Result<Db, Box<dyn std::error::Error>> {
    // Deliberately no .env loading, migrations, or default database address.
    let url = std::env::var("BUZZ_QUOTA_DATABASE_URL")?;
    Ok(Db::from_pool(
        sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .connect(&url)
            .await?,
    ))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Recovery {
    community_id: Uuid,
    pubkey: String,
    sha256: String,
    operation_id: Uuid,
    evidence: String,
}
