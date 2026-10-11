# Local S3 compatibility fixture

Compose uses the maintained [RustFS 1.0.1 release](https://github.com/rustfs/rustfs/releases/tag/1.0.1), pinned by image digest. The `minio` and `minio-init`
service names remain compatible with existing development and CI commands. The
initializer uses the official AWS CLI 2.37.12 image, also pinned by digest. The
S3 endpoint remains `http://localhost:9000`, with the synthetic development keys
`buzz_dev` / `buzz_dev_secret` and private `buzz-media` bucket.

The fixture uses `buzz-s3-fixture-data`. Existing `buzz-minio-data` is left intact
and is never opened by RustFS. This is a fresh development fixture, not a
production storage migration. Existing local media can be re-seeded after startup.
The localhost:9001 interface is now the RustFS console, with the same
development username and password.

```sh
docker compose up -d minio minio-init
cargo test -p buzz-media --test static_creds_minio -- --ignored
cargo test -p buzz-media --test versioned_minio -- --ignored --nocapture
```

The versioned suite and `scripts/seed-admin-dashboard.sh` require AWS CLI v2
(`aws` on PATH). Administration uses the public S3 API instead of relying on a
vendor-specific `mc` binary inside the server container. The Rust test filenames
remain unchanged for existing callers. Override `BUZZ_S3_ENDPOINT` and the other
documented `BUZZ_S3_*` settings to test a separate disposable S3 fixture.

The replacement must support PUT/GET/HEAD, ranges, presigned reads, private
buckets, null versions, versioning and suspension, delete markers, dual-marker
pagination, and repeat exact-version bulk deletion. Both Rust suites remain the
acceptance gate; do not run the destructive version suite against production.

The [previous upstream MinIO repository](https://github.com/minio/minio) is
archived and no longer publishes maintained community images; rebuilding its
source does not resolve that support lifecycle gap.
