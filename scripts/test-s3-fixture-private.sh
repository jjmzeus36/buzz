#!/usr/bin/env bash
# Destructive synthetic policy regression for the local Compose fixture only.
set -euo pipefail
endpoint=${BUZZ_S3_FIXTURE_ENDPOINT:-http://127.0.0.1:9000}
if [[ ! "$endpoint" =~ ^http://127\.0\.0\.1:[0-9]+$ ]]; then
    echo 'private-policy test requires a loopback Compose fixture' >&2
    exit 1
fi
bucket=buzz-media
key="_test/fixture-private-$$-${RANDOM}"

s3() {
    aws --endpoint-url "$endpoint" --region us-east-1 --no-cli-pager s3api "$@"
}

cleanup() {
    s3 delete-bucket-policy --bucket "$bucket" >/dev/null || true
    s3 delete-object --bucket "$bucket" --key "$key" >/dev/null || true
}
trap cleanup EXIT

# Omit the optional body to create an empty object without host/container mounts.
s3 put-object --bucket "$bucket" --key "$key" >/dev/null
policy=$(printf '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::%s/%s"}]}' "$bucket" "$key")
s3 put-bucket-policy --bucket "$bucket" --policy "$policy"
test "$(curl --silent --output /dev/null --write-out '%{http_code}' "$endpoint/$bucket/$key")" = 200

# Preserve the running backend and its data across initializer invocations.
# The first rerun must remove the public policy; the second must be idempotent.
for attempt in 1 2; do
    docker compose run --rm minio-init
    test "$(curl --silent --output /dev/null --write-out '%{http_code}' "$endpoint/$bucket/$key")" = 403
done
echo 'S3 fixture private-policy persistence contract passed'
