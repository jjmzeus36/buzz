#!/usr/bin/env bash
# Reconcile the retained local S3 fixture and require private-bucket init success.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

docker compose up -d minio
healthy=false
for attempt in $(seq 1 60); do
  health=$(docker inspect --format '{{.State.Health.Status}}' buzz-minio 2>/dev/null || echo not_found)
  if [[ "$health" == healthy ]]; then
    healthy=true
    break
  fi
  sleep 2
done
if [[ "$healthy" != true ]]; then
  echo 'S3 fixture did not become healthy within 120s' >&2
  docker logs --tail 100 buzz-minio >&2 || true
  exit 1
fi

# Rerun policy restoration even if a previous initializer exited successfully.
# Recreate only the one-shot container; leave service containers and data intact.
docker compose up -d --no-deps --force-recreate minio-init
for attempt in $(seq 1 60); do
  state=$(docker inspect --format '{{.State.Status}} {{.State.ExitCode}}' buzz-minio-init 2>/dev/null || echo not_found)
  case "$state" in
    'exited 0')
      echo 'S3 fixture initialized'
      exit 0
      ;;
    exited\ *|dead\ *)
      echo "S3 fixture initializer failed: $state" >&2
      docker logs --tail 100 buzz-minio-init >&2 || true
      exit 1
      ;;
  esac
  sleep 2
done
echo 'S3 fixture initializer did not finish within 120s' >&2
docker logs --tail 100 buzz-minio-init >&2 || true
exit 1
