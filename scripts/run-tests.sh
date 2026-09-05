#!/usr/bin/env bash
# =============================================================================
# run-tests.sh — Run Buzz test suite
# =============================================================================
# Usage:
#   ./scripts/run-tests.sh              # run all tests (default)
#   ./scripts/run-tests.sh unit         # unit tests only (no infra needed)
#   ./scripts/run-tests.sh integration  # integration tests only
#   ./scripts/run-tests.sh all          # explicit all
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
MODE="${1:-all}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

log()    { echo -e "${BLUE}[run-tests]${NC} $*"; }
success(){ echo -e "${GREEN}[run-tests]${NC} $*"; }
warn()   { echo -e "${YELLOW}[run-tests]${NC} $*"; }
error()  { echo -e "${RED}[run-tests]${NC} $*" >&2; }
section(){ echo -e "\n${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"; echo -e "${CYAN}  $*${NC}"; echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"; }

cd "${REPO_ROOT}"

# ---- Load .env if present ---------------------------------------------------

if [[ -f ".env" ]]; then
  log "Loading .env..."
  set -o allexport
  # shellcheck disable=SC1091
  source .env
  set +o allexport
else
  # Use defaults matching docker-compose.yml
  export DATABASE_URL="postgres://buzz:buzz_dev@localhost:5432/buzz" # sadscan:disable np.postgres.1
  export PGHOST=localhost
  export PGPORT=5432
  export PGUSER=buzz
  export PGPASSWORD=buzz_dev
  export PGDATABASE=buzz
  export REDIS_URL="redis://localhost:6379"
fi

export PGHOST="${PGHOST:-localhost}"
export PGPORT="${PGPORT:-5432}"
export PGUSER="${PGUSER:-buzz}"
export PGPASSWORD="${PGPASSWORD:-buzz_dev}"
export REDIS_URL="${REDIS_URL:-redis://localhost:6379}"
export BUZZ_POSTGRES_ADMIN_URL="${BUZZ_POSTGRES_ADMIN_URL:-postgres://${PGUSER}:${PGPASSWORD}@${PGHOST}:${PGPORT}/postgres}"

# ---- Track results ----------------------------------------------------------

declare -a PASSED=()
declare -a FAILED=()

run_test_step() {
  local name="$1"
  shift
  log "Running: ${name}"
  if "$@"; then
    success "${name} passed"
    PASSED+=("${name}")
  else
    error "${name} FAILED"
    FAILED+=("${name}")
  fi
}

# postgres-test-run.sh already applies --profile postgres-ci and
# --run-ignored ignored-only, owns template cleanup, and accepts extra nextest
# arguments. Pass --no-tests=fail so a missing Goal 1 selector cannot stay green.
run_required_postgres() {
  local name="$1"
  shift
  run_test_step "${name}" \
    "${SCRIPT_DIR}/postgres-test-run.sh" --no-tests=fail "$@"
}

# cargo test exits 0 when a name filter matches nothing. Required Goal 1
# selectors must fail visibly in that case rather than reporting a green skip.
run_required_cargo_test() {
  local name="$1"
  shift
  log "Running: ${name}"
  local output rc
  set +e
  output=$("$@" 2>&1)
  rc=$?
  set -e
  printf '%s\n' "${output}"
  if printf '%s\n' "${output}" | grep -qE '^running 0 tests$'; then
    error "${name} FAILED (selector matched 0 tests)"
    FAILED+=("${name}")
    return 0
  fi
  if [[ "${rc}" -ne 0 ]]; then
    error "${name} FAILED"
    FAILED+=("${name}")
    return 0
  fi
  success "${name} passed"
  PASSED+=("${name}")
}

# ---- Check / start infra (for integration tests) ----------------------------

ensure_infra() {
  "${REPO_ROOT}/bin/just" _ensure-migrations
}

# ---- Unit tests (no infra needed) -------------------------------------------

run_unit_tests() {
  section "Unit Tests (no infra required)"

  run_test_step "buzz-core tests" \
    cargo test -p buzz-core --lib -- --nocapture

  run_test_step "buzz-auth unit tests" \
    cargo test -p buzz-auth --lib -- --nocapture

  run_test_step "buzz-voice tests" \
    cargo test -p buzz-voice --lib -- --nocapture

  run_test_step "buzz-cli tests" \
    cargo test -p buzz-cli -- --nocapture

  # Keep the relay-to-agent trust-boundary regressions in the fallback path
  # when cargo-nextest is unavailable.
  run_test_step "buzz-acp tests" \
    cargo test -p buzz-acp -- --nocapture

  # buzz-db migrator/lint unit tests (no infra): guard the embedded-migrator
  # invariant (exactly the consolidated 0001; cutover/backfill stays an operator
  # script, not startup state) and the tenant-scoping lints. The Postgres-backed
  # buzz-db tests are #[ignore]d; --lib keeps this step infra-free. Goal 1
  # idempotency/reaper + live catalog-parity tests run in integration mode
  # below with --ignored.
  run_test_step "buzz-db unit tests" \
    cargo test -p buzz-db --lib -- --nocapture

  # Paired/hierarchical admission constructor/script unit tests (no Redis).
  # Mirrors `just test-unit`. Real-Redis paired_* and hierarchical_* tests
  # are #[ignore]d and run only in integration / Backend Integration.
  # Unfiltered --lib (no name filter) so doctest harnesses are allowed;
  # do not use run_required_cargo_test here, which treats "running 0 tests"
  # from an empty doctest harness as a selector failure.
  run_test_step "buzz-pubsub unit tests" \
    cargo test -p buzz-pubsub --lib -- --nocapture

  # Multi-tenant conformance gate: independent replay checker + golden
  # fixtures (buzz-conformance). Pure in-process trace replay, no infra.
  run_test_step "buzz-conformance tests" \
    cargo test -p buzz-conformance -- --nocapture

  run_test_step "buzz-push-gateway tests" \
    cargo test -p buzz-push-gateway -- --nocapture

  # Kubernetes backend provider: pure decision layers driven by a fake
  # substrate, no cluster. Mirrors the nextest path in `just test-unit` —
  # the two lists must stay in step or the fallback silently covers less.
  run_test_step "buzz-backend-kubernetes tests" \
    cargo test -p buzz-backend-kubernetes -- --nocapture

  # buzz-agent model-capabilities corpus: the Rust half of the cross-language
  # drift guard. model_capabilities.rs embeds scripts/model-capabilities.json +
  # scripts/normative-corpus.json via include_str! and replays the full locked
  # corpus as pure in-process tests (no infra). Mirrors the nextest path in
  # `just test-unit` — the two lists must stay in step.
  run_test_step "buzz-agent unit tests" \
    cargo test -p buzz-agent --lib -- --nocapture

  # ACP author-gate and queue tests are pure unit tests. Keep this fallback in
  # step with `just test-unit`; ignored lifecycle tests run elsewhere.
  run_test_step "buzz-acp unit tests" \
    cargo test -p buzz-acp --lib -- --nocapture

  # Mirror the three infra-free relay handler modules in `just test-unit`'s
  # nextest expression. Keep the side-effects filter pinned to `::tests::` so
  # it does not select the sibling Postgres-backed test module.
  run_test_step "buzz-relay channel authorization tests" \
    cargo test -p buzz-relay --lib handlers::channel_authz:: -- --nocapture

  run_test_step "buzz-relay moderation authorization tests" \
    cargo test -p buzz-relay --lib handlers::moderation_authz:: -- --nocapture

  run_test_step "buzz-relay side-effects helper tests" \
    cargo test -p buzz-relay --lib handlers::side_effects::tests:: -- --nocapture

  # Goal 1 NIP-MI / paired-admission relay library + binary unit tests.
  # Same name filters as `just test-unit` (nextest) and the Unit Tests CI
  # job. Do not use `buzz-relay --lib` unfiltered: api::media has non-ignored
  # tests that require Postgres. Bridge and ingest coverage are the complete
  # api::bridge::postgres_tests:: and handlers::ingest::postgres_tests::
  # modules (not function-name prefixes); cargo test without --ignored leaves
  # #[ignore]d Postgres/Redis cases for integration.
  run_required_cargo_test "buzz-relay Goal 1 admission unit tests" \
    cargo test -p buzz-relay --lib admission:: -- --nocapture
  run_required_cargo_test "buzz-relay Goal 1 NIP-11 idempotency unit tests" \
    cargo test -p buzz-relay --lib nip11::tests::idempotency_ -- --nocapture
  run_required_cargo_test "buzz-relay Goal 1 NIP-11 served_nip11 unit tests" \
    cargo test -p buzz-relay --lib nip11::tests::served_nip11_ -- --nocapture
  run_required_cargo_test "buzz-relay Goal 1 NIP-11 relay_info unit tests" \
    cargo test -p buzz-relay --lib nip11::tests::relay_info_ -- --nocapture
  run_required_cargo_test "buzz-relay Goal 1 NIP-11 optional_fields unit tests" \
    cargo test -p buzz-relay --lib nip11::tests::optional_fields_keep_historical -- --nocapture
  run_required_cargo_test "buzz-relay Goal 1 NIP-11 served_relay_info unit tests" \
    cargo test -p buzz-relay --lib nip11::tests::served_relay_info_serializes -- --nocapture
  run_required_cargo_test "buzz-relay Goal 1 bridge unit tests" \
    cargo test -p buzz-relay --lib api::bridge::postgres_tests:: -- --nocapture
  run_required_cargo_test "buzz-relay Goal 1 ingest unit tests" \
    cargo test -p buzz-relay --lib handlers::ingest::tests:: -- --nocapture
  run_required_cargo_test "buzz-relay Goal 1 binary reap_tick unit tests" \
    cargo test -p buzz-relay --bin buzz-relay reap_tick_tests:: -- --nocapture
  run_required_cargo_test "buzz-relay Goal 1 binary idempotency reaper unit tests" \
    cargo test -p buzz-relay --bin buzz-relay idempotency_reaper -- --nocapture
}

# ---- DB / integration tests (infra required) --------------------------------

run_integration_tests() {
  section "Integration Tests (requires running services)"

  ensure_infra

  run_test_step "buzz-db tests" \
    cargo test -p buzz-db -- --nocapture

  # Goal 1 real-Redis paired-admission tests (#[ignore = "requires Redis"]).
  # Unique tenant/IP keys, but TTL/Lua suites mutate the shared Redis
  # instance; run serially. Matches Backend Integration. cargo test name
  # filters are substrings, not regexes.
  run_required_cargo_test "buzz-pubsub paired Redis admission tests" \
    cargo test -p buzz-pubsub --lib rate_limiter::tests::paired_ -- --ignored --test-threads=1 --nocapture

  # Goal 1 real-Redis hierarchical-admission tests (#[ignore = "requires Redis"]).
  # Substring filter hierarchical_ selects rate_limiter::tests::hierarchical_*
  # ignored tests; --ignored excludes the non-ignored constructor/script
  # cases. Serial on the shared Redis instance. run_required_cargo_test
  # fails if the selector matches zero tests.
  run_required_cargo_test "buzz-pubsub hierarchical Redis admission tests" \
    cargo test -p buzz-pubsub --lib rate_limiter::tests::hierarchical_ -- --ignored --test-threads=1 --nocapture

  # postgres-ci excludes external_infra* modules. Run the bridge Redis
  # wrappers here so they keep an execution lane. Shared fleet sentinel
  # still requires serial execution.
  run_required_cargo_test "buzz-relay Goal 1 bridge external Redis tests" \
    cargo test -p buzz-relay --lib api::bridge::postgres_tests::external_infra_redis_tests:: -- --ignored --test-threads=1 --nocapture

  # Discovered PostgreSQL suite with per-test isolation. Extra nextest args
  # skip package discovery inside postgres-test-run.sh, so pass -p lists
  # from the same discovery script CI archives. Exclude bridge postgres_tests
  # here; they share the fleet sentinel and run once, serially, next.
  postgres_package_args=()
  while IFS= read -r package; do
    postgres_package_args+=(-p "$package")
  done < <("${SCRIPT_DIR}/postgres-test-packages.sh")
  if [[ "${#postgres_package_args[@]}" -eq 0 ]]; then
    error "no PostgreSQL test packages were discovered"
    FAILED+=("PostgreSQL test discovery")
  else
    run_required_postgres "PostgreSQL discovered suite" \
      "${postgres_package_args[@]}" --lib --tests \
      -E 'not test(/^api::bridge::postgres_tests::/)'
    run_required_postgres "buzz-relay Goal 1 bridge fleet-sentinel PostgreSQL tests" \
      -p buzz-relay --lib \
      -E 'test(/^api::bridge::postgres_tests::/)' \
      --test-threads=1
  fi

  run_required_postgres "buzz-db idempotency/reaper PostgreSQL tests" \
    -p buzz-db --lib \
    -E 'test(/^store::idempotency::postgres_tests::/)' \
    --test-threads=1

  run_required_postgres "buzz-db live migration/catalog-parity test" \
    -p buzz-db --lib \
    -E 'test(/admin_schema_parity_between_desired_state_and_migrations/)'

  run_required_postgres "buzz-relay Goal 1 ingest ignored PostgreSQL tests" \
    -p buzz-relay --lib \
    -E 'test(/^handlers::ingest::postgres_tests::/)'

  # Goal 1 ignored semantic-intent-once integration binary and each
  # mention/atomicity/kind-9 cap PostgreSQL test. One exact full-name
  # nextest expression plus --no-tests=fail per test so a prefix or a
  # sibling match cannot stay green. Isolation comes from the wrapper.
  run_required_postgres "buzz-db keyed semantic-intent-once PostgreSQL test" \
    -p buzz-db --test semantic_intent_once \
    -E 'binary(semantic_intent_once) and test(=postgres_tests::keyed_miss_reserve_complete_hashes_semantic_intent_once)'
  run_required_postgres "buzz-db mention p-tag bind-cap PostgreSQL test" \
    -p buzz-db --lib \
    -E 'test(=store::feed::postgres_tests::insert_mentions_indexes_p_tags_past_bind_parameter_cap)'
  run_required_postgres "buzz-db mixed-case mention PostgreSQL test" \
    -p buzz-db --lib \
    -E 'test(=runtime::postgres_tests::duplicate_mixed_case_p_tags_store_one_canonical_mention_row)'
  run_required_postgres "buzz-db mention chunk PostgreSQL test" \
    -p buzz-db --lib \
    -E 'test(=runtime::postgres_tests::mention_insert_chunks_five_thousand_one_occurrences)'
  run_required_postgres "buzz-db serving_write_commits_event_and_mentions_together" \
    -p buzz-db --lib \
    -E 'test(=runtime::postgres_tests::serving_write_commits_event_and_mentions_together)'
  run_required_postgres "buzz-db serving_write_mention_failure_rolls_back_event_and_mentions" \
    -p buzz-db --lib \
    -E 'test(=runtime::postgres_tests::serving_write_mention_failure_rolls_back_event_and_mentions)'
  run_required_postgres "buzz-db serving_write_duplicate_retry_skips_mention_insert" \
    -p buzz-db --lib \
    -E 'test(=runtime::postgres_tests::serving_write_duplicate_retry_skips_mention_insert)'
  run_required_postgres "buzz-db ordinary_insert_event_mention_failure_rolls_back_coupled_state" \
    -p buzz-db --lib \
    -E 'test(=runtime::postgres_tests::ordinary_insert_event_mention_failure_rolls_back_coupled_state)'
  run_required_postgres "buzz-db ordinary_insert_event_retry_succeeds_after_mention_trigger_removed" \
    -p buzz-db --lib \
    -E 'test(=runtime::postgres_tests::ordinary_insert_event_retry_succeeds_after_mention_trigger_removed)'
  run_required_postgres "buzz-db ordinary_insert_event_duplicate_does_not_rerun_mention_insert" \
    -p buzz-db --lib \
    -E 'test(=runtime::postgres_tests::ordinary_insert_event_duplicate_does_not_rerun_mention_insert)'
  run_required_postgres "buzz-db ordinary_insert_event_unrelated_community_unaffected_by_mention_trigger" \
    -p buzz-db --lib \
    -E 'test(=runtime::postgres_tests::ordinary_insert_event_unrelated_community_unaffected_by_mention_trigger)'
  run_required_postgres "buzz-db ordinary_insert_event_no_indexed_p_tags_succeeds_under_mention_trigger" \
    -p buzz-db --lib \
    -E 'test(=runtime::postgres_tests::ordinary_insert_event_no_indexed_p_tags_succeeds_under_mention_trigger)'
  run_required_postgres "buzz-db ordinary_insert_event_with_thread_metadata_mention_failure_rolls_back_coupled_state" \
    -p buzz-db --lib \
    -E 'test(=runtime::postgres_tests::ordinary_insert_event_with_thread_metadata_mention_failure_rolls_back_coupled_state)'
  run_required_postgres "buzz-db kind9_write_p_tag_limit_accepts_sixty_four_actual_tags" \
    -p buzz-db --lib \
    -E 'test(=runtime::postgres_tests::kind9_write_p_tag_limit_accepts_sixty_four_actual_tags)'
  run_required_postgres "buzz-db kind9_write_p_tag_limit_rejects_sixty_five_actual_tags" \
    -p buzz-db --lib \
    -E 'test(=runtime::postgres_tests::kind9_write_p_tag_limit_rejects_sixty_five_actual_tags)'
  run_required_postgres "buzz-db kind9_write_p_tag_limit_counts_malformed_and_duplicate_actual_p_tags" \
    -p buzz-db --lib \
    -E 'test(=runtime::postgres_tests::kind9_write_p_tag_limit_counts_malformed_and_duplicate_actual_p_tags)'
  run_required_postgres "buzz-db kind9_write_p_tag_limit_ignores_uppercase_kind_and_non_p_tags" \
    -p buzz-db --lib \
    -E 'test(=runtime::postgres_tests::kind9_write_p_tag_limit_ignores_uppercase_kind_and_non_p_tags)'
  run_required_postgres "buzz-db kind9_write_p_tag_limit_does_not_apply_to_other_kinds" \
    -p buzz-db --lib \
    -E 'test(=runtime::postgres_tests::kind9_write_p_tag_limit_does_not_apply_to_other_kinds)'
  run_required_postgres "buzz-db kind9_write_p_tag_limit_insert_event_in_transaction_rejects_sixty_five" \
    -p buzz-db --lib \
    -E 'test(=runtime::postgres_tests::kind9_write_p_tag_limit_insert_event_in_transaction_rejects_sixty_five)'
  run_required_postgres "buzz-db kind9_write_p_tag_limit_thread_writer_rejects_sixty_five" \
    -p buzz-db --lib \
    -E 'test(=runtime::postgres_tests::kind9_write_p_tag_limit_thread_writer_rejects_sixty_five)'
  run_required_postgres "buzz-db reaction_mention_failure_rolls_back_coupled_state" \
    -p buzz-db --lib \
    -E 'test(=store::reaction::postgres_tests::reaction_mention_failure_rolls_back_coupled_state)'
  run_required_postgres "buzz-db reaction_mention_retry_succeeds_after_trigger_removed" \
    -p buzz-db --lib \
    -E 'test(=store::reaction::postgres_tests::reaction_mention_retry_succeeds_after_trigger_removed)'
  run_required_postgres "buzz-db reaction_mention_duplicate_does_not_rerun_mention_insert" \
    -p buzz-db --lib \
    -E 'test(=store::reaction::postgres_tests::reaction_mention_duplicate_does_not_rerun_mention_insert)'

  if find crates/buzz-auth/tests -maxdepth 1 -name '*.rs' -print -quit 2>/dev/null | grep -q .; then
    run_test_step "buzz-auth integration tests" \
      cargo test -p buzz-auth --test '*' -- --nocapture
  else
    run_test_step "buzz-auth (no integration tests found)" true
  fi

  run_test_step "workspace integration tests" \
    cargo test --test '*' -- --nocapture 2>/dev/null || \
    run_test_step "workspace integration tests (none found)" true
}

# ---- Main -------------------------------------------------------------------

START_TIME=$(date +%s)

case "${MODE}" in
  unit)
    run_unit_tests
    ;;
  integration)
    run_integration_tests
    ;;
  all|*)
    run_unit_tests
    run_integration_tests
    ;;
esac

END_TIME=$(date +%s)
ELAPSED=$((END_TIME - START_TIME))

# ---- Summary ----------------------------------------------------------------

section "Test Summary"
echo ""
echo -e "  Duration: ${ELAPSED}s"
echo ""

if [[ ${#PASSED[@]} -gt 0 ]]; then
  echo -e "  ${GREEN}Passed (${#PASSED[@]}):${NC}"
  for t in "${PASSED[@]}"; do
    echo -e "    ${GREEN}pass${NC} ${t}"
  done
fi

if [[ ${#FAILED[@]} -gt 0 ]]; then
  echo ""
  echo -e "  ${RED}Failed (${#FAILED[@]}):${NC}"
  for t in "${FAILED[@]}"; do
    echo -e "    ${RED}fail${NC} ${t}"
  done
  echo ""
  exit 1
fi

echo ""
success "All tests passed!"
exit 0
