//! Redis-backed rate limiter using atomic Lua script (INCR + EXPIRE).
//!
//! Implements the [`RateLimiter`] trait from `buzz-auth`.
//! Uses a single Lua script to atomically INCR and conditionally EXPIRE,
//! eliminating the crash window where a key could exist without a TTL.
//!
//! ⚠️ Fixed windows allow up to 2× burst at boundaries. Upgrade to sliding
//! window or token bucket for strict limiting.

use std::net::IpAddr;
use std::num::NonZeroU64;

use buzz_auth::{
    error::AuthError,
    rate_limit::{
        HierarchicalAdmissionLimits, HierarchicalAdmissionOutcome, HierarchicalAdmissionRequest,
        HierarchicalIdentityDenialPeekOutcome, HierarchicalIdentityDenialPeekRequest,
        KeyedAdmissionErrorClass, KeyedAdmissionFailure, LimitType, PairedAdmissionOutcome,
        PairedAdmissionRequest, RateLimitResult, RateLimiter,
    },
};
use buzz_core::TenantContext;
use nostr::PublicKey;
use redis::Script;

/// Atomically INCR the key, set EXPIRE on first call, and return (count, ttl).
///
/// Using a Lua script ensures INCR and EXPIRE are executed atomically —
/// a crash between them can no longer leave a key without a TTL.
const RATE_LIMIT_SCRIPT: &str = r#"
local count = redis.call('INCR', KEYS[1])
if count == 1 then
    redis.call('EXPIRE', KEYS[1], ARGV[1])
end
local ttl = redis.call('TTL', KEYS[1])
return {count, ttl}
"#;

/// Atomically decide tenant+fleet admission without a partial charge.
///
/// KEYS[1] tenant key, KEYS[2] fleet key.
/// ARGV: tenant_window, tenant_limit, fleet_window, fleet_limit.
/// Returns {code, t_current, t_limit, t_reset, f_current, f_limit, f_reset}
/// where code is 0=allowed, 1=tenant denied, 2=fleet denied, 3=unequal/zero
/// windows, 4=corrupt stored counter (no mutation).
///
/// Stored values must be Redis-INCR integers before either charged mutation.
/// Accepted nonnegative spelling is exactly `"0"` or a nonzero digit followed
/// by digits, inside signed-64 range. Leading zeros, negatives, non-integers,
/// and overflow fail closed without INCR. A live fleet key with PTTL == -1
/// keeps its count, receives a bounded expiry, and then follows ordinary limit
/// denial — never a fresh-window reset. Live allow and deny pin the tenant to
/// the fleet key's exact `PEXPIRETIME` via `PEXPIREAT`/`PXAT` and never
/// refresh the fleet deadline on denial (no tenant +1 ms tail). Denial skips
/// `PEXPIREAT` when the tenant's current absolute deadline already equals the
/// freshly read live fleet deadline: deny never `INCR`/`SET`, so that stamp
/// cannot have been recreated by this script. Allow does not use that
/// shortcut — `INCR` of a missing or crossed-window key recreates a
/// persistent counter that must still receive post-mutation expiry. After the
/// fleet `INCR`, live allow rechecks `PTTL` and `PEXPIRETIME` against that
/// captured stamp; a crossed window opens a fresh 1/1 bounded deadline.
const PAIRED_ADMISSION_SCRIPT: &str = r#"
local tenant_window = tonumber(ARGV[1])
local tenant_limit = tonumber(ARGV[2])
local fleet_window = tonumber(ARGV[3])
local fleet_limit = tonumber(ARGV[4])

if tenant_window ~= fleet_window or tenant_window == nil or tenant_window < 1 then
    return {3, 0, tenant_limit or 0, 0, 0, fleet_limit or 0, 0}
end

local window = tenant_window

local function reset_secs(pttl_ms, win)
    if pttl_ms < 0 then
        return win
    end
    if pttl_ms == 0 then
        return 0
    end
    return math.floor((pttl_ms + 999) / 1000)
end

local function window_ms()
    local ms = math.floor(window * 1000)
    if ms < 1 then
        return 1
    end
    return ms
end

local function absolute_now_ms()
    local t = redis.call('TIME')
    return tonumber(t[1]) * 1000 + math.floor(tonumber(t[2]) / 1000)
end

local function expire_at(key)
    return tonumber(redis.call('PEXPIRETIME', key)) or -2
end

-- Redis-INCR canonical nonnegative signed-64: "0" or [1-9][0-9]*.
local function parse_counter(raw)
    if raw == false then
        return 0, 'missing'
    end
    if type(raw) ~= 'string' then
        return nil, 'corrupt'
    end
    if raw:match('^%-%d+$') then
        return nil, 'negative'
    end
    if raw == '0' then
        return 0, 'ok'
    end
    if not raw:match('^[1-9]%d*$') then
        return nil, 'corrupt'
    end
    if #raw > 19 then
        return nil, 'overflow'
    end
    if #raw == 19 and raw > '9223372036854775807' then
        return nil, 'overflow'
    end
    if raw == '9223372036854775807' then
        return tonumber(raw), 'max'
    end
    local n = tonumber(raw)
    if n == nil then
        return nil, 'corrupt'
    end
    return n, 'ok'
end

local function corrupt()
    return {4, 0, tenant_limit, 0, 0, fleet_limit, 0}
end

local function pin_keys_at(at)
    if at < 1 then
        return
    end
    redis.call('PEXPIREAT', KEYS[1], at)
    redis.call('PEXPIREAT', KEYS[2], at)
end

local function pin_tenant_at(at, tenant_count)
    if at < 1 or tenant_count <= 0 then
        return
    end
    if redis.call('PEXPIREAT', KEYS[1], at) == 0 then
        redis.call('SET', KEYS[1], tenant_count, 'PXAT', at)
    end
end

local function restore_tenant(raw, at)
    if raw == false then
        redis.call('DEL', KEYS[1])
        return
    end
    if at > 0 then
        redis.call('SET', KEYS[1], raw, 'PXAT', at)
        return
    end
    redis.call('SET', KEYS[1], raw)
    if at == -1 then
        redis.call('PERSIST', KEYS[1])
    end
end

local function admit_fresh_window()
    local ms = window_ms()
    redis.call('SET', KEYS[2], 1, 'PX', ms)
    local at = expire_at(KEYS[2])
    if at < 1 then
        redis.call('SET', KEYS[2], 1, 'PX', ms)
        at = expire_at(KEYS[2])
        if at < 1 then
            at = absolute_now_ms() + ms
            redis.call('PEXPIREAT', KEYS[2], at)
            at = expire_at(KEYS[2])
            if at < 1 then
                at = absolute_now_ms() + ms
            end
        end
    end
    redis.call('SET', KEYS[1], 1, 'PXAT', at)
    pin_keys_at(at)
    at = expire_at(KEYS[2])
    if at < 1 then
        redis.call('SET', KEYS[2], 1, 'PX', ms)
        at = expire_at(KEYS[2])
        if at < 1 then
            at = absolute_now_ms() + ms
            redis.call('PEXPIREAT', KEYS[2], at)
            at = expire_at(KEYS[2])
            if at < 1 then
                at = absolute_now_ms() + ms
            end
        end
        redis.call('SET', KEYS[1], 1, 'PXAT', at)
        pin_keys_at(at)
    end
    local reset = reset_secs(redis.call('PTTL', KEYS[2]), window)
    return {0, 1, tenant_limit, reset, 1, fleet_limit, reset}
end

-- Pin a positive tenant counter to the live fleet's exact absolute expiry.
-- Clamp both a shorter tenant and a legacy +1 ms tail. Never change fleet.
-- Skip PEXPIREAT when the tenant's current absolute deadline already equals
-- the freshly read live fleet deadline. Deny never INCR or SET, so that
-- stamp cannot have been recreated by this script. Allow cannot use this
-- shortcut. Missing keys stay missing; persistent or misaligned positive
-- tenant keys are repaired to the live fleet deadline.
local function align_tenant_expiry(tenant_count)
    local live_at = expire_at(KEYS[2])
    local tenant_at = expire_at(KEYS[1])
    if tenant_at == live_at then
        return
    end
    pin_tenant_at(live_at, tenant_count)
end

local function deny(code, tenant_count, fleet_count)
    align_tenant_expiry(tenant_count)
    local t_reset = reset_secs(redis.call('PTTL', KEYS[1]), window)
    local f_reset = reset_secs(redis.call('PTTL', KEYS[2]), window)
    return {code, tenant_count, tenant_limit, t_reset, fleet_count, fleet_limit, f_reset}
end

local traw = redis.call('GET', KEYS[1])
local fraw = redis.call('GET', KEYS[2])
local tcount, tstat = parse_counter(traw)
local fcount, fstat = parse_counter(fraw)
if tstat == 'corrupt' or tstat == 'negative' or tstat == 'overflow'
    or fstat == 'corrupt' or fstat == 'negative' or fstat == 'overflow' then
    return corrupt()
end

local tpttl = redis.call('PTTL', KEYS[1])
local fpttl = redis.call('PTTL', KEYS[2])
local ms = window_ms()

-- PTTL == -1 is a live key with no expiry: preserve the count, repair a
-- bounded window, then apply ordinary limit denial. Never treat it as inactive.
if fraw ~= false and fpttl == -1 then
    redis.call('PEXPIRE', KEYS[2], ms)
    fpttl = redis.call('PTTL', KEYS[2])
    if fpttl < 1 then
        redis.call('PEXPIRE', KEYS[2], ms)
        fpttl = redis.call('PTTL', KEYS[2])
    end
end
if traw ~= false and tpttl == -1 then
    local fat = expire_at(KEYS[2])
    if fat > 0 then
        redis.call('PEXPIREAT', KEYS[1], fat)
    else
        local repair = fpttl
        if repair < 1 then
            repair = ms
        end
        redis.call('PEXPIRE', KEYS[1], repair)
    end
    tpttl = redis.call('PTTL', KEYS[1])
end

local fleet_active = fpttl > 0
if not fleet_active then
    tcount = 0
    fcount = 0
end

if (tstat == 'max' or fstat == 'max') and fleet_active then
    if tcount >= tenant_limit then
        return deny(1, tcount, fcount)
    end
    if fcount >= fleet_limit then
        return deny(2, tcount, fcount)
    end
    return corrupt()
end

if tcount >= tenant_limit then
    return deny(1, tcount, fcount)
end
if fcount >= fleet_limit then
    return deny(2, tcount, fcount)
end

if not fleet_active then
    return admit_fresh_window()
end

local restore_raw = traw
local restore_at = expire_at(KEYS[1])
local new_t = redis.call('INCR', KEYS[1])
local live_ms = redis.call('PTTL', KEYS[2])
if live_ms < 1 then
    return admit_fresh_window()
end
local live_at = expire_at(KEYS[2])
if live_at < 1 then
    return admit_fresh_window()
end
local ok, new_f = pcall(function()
    return redis.call('INCR', KEYS[2])
end)
if not ok then
    restore_tenant(restore_raw, restore_at)
    return corrupt()
end
-- INCR of an expired fleet recreates a persistent 1. Revalidate the captured
-- absolute deadline before treating this as a live-window charge.
local post_ms = redis.call('PTTL', KEYS[2])
local post_at = expire_at(KEYS[2])
if post_ms < 1 or post_at < 1 or post_at ~= live_at then
    return admit_fresh_window()
end
pin_tenant_at(live_at, new_t)
local reset = reset_secs(redis.call('PTTL', KEYS[2]), window)
return {0, new_t, tenant_limit, reset, new_f, fleet_limit, reset}
"#;

/// Atomically decide identity+community+fleet admission without a partial charge.
///
/// KEYS[1] identity key, KEYS[2] community key, KEYS[3] fleet key.
/// ARGV: window, identity_limit, community_limit, fleet_limit.
/// Returns {code, i_current, i_limit, i_reset, c_current, c_limit, c_reset,
/// f_current, f_limit, f_reset} where code is 0=allowed, 1=identity denied,
/// 2=community denied, 3=fleet denied, 4=window/alias contract, 5=corrupt
/// stored counter or invalid TTL (no counter mutation).
///
/// Stored values must be Redis-INCR integers before either charged mutation.
/// Accepted nonnegative spelling is exactly `"0"` or a nonzero digit followed
/// by digits, inside signed-64 range. Leading zeros, negatives, non-integers,
/// and overflow fail closed without INCR and without creating a missing
/// identity key. A live fleet key with PTTL == -1 keeps its count, receives a
/// bounded expiry, and then follows ordinary limit denial — never a
/// fresh-window reset. A malformed, negative, overflowing, or WRONGTYPE
/// fleet value with PTTL == -1 keeps its exact bytes/type, receives one
/// bounded quarantine expiry no longer than the supplied window, and still
/// fails closed as corrupt. A later request does not move that deadline.
/// Finite-TTL corrupt fleet keys keep their deadline. Identity and community
/// keys are not created or mutated on that path. Well-formed persistent
/// integers still use the ordinary repair-and-deny path. Live allow and deny
/// pin existing identity/community keys to the fleet key's exact
/// `PEXPIRETIME` via `PEXPIREAT` and never refresh the fleet deadline on
/// denial. Denial skips `PEXPIREAT` when a present identity/community key's
/// captured absolute deadline already equals the freshly read live fleet
/// deadline: deny never `INCR`/`SET`, so that stamp cannot have been
/// recreated by this script. Allow does not use that shortcut — `INCR` of a
/// missing or crossed-window key recreates a persistent counter that must
/// still receive post-mutation expiry. A missing identity key is created
/// only on the allow path. After the fleet `INCR`, live allow rechecks
/// `PTTL` and `PEXPIRETIME` against that captured stamp; a crossed window
/// opens a fresh 1/1/1 bounded deadline.
const HIERARCHICAL_ADMISSION_SCRIPT: &str = r#"
local window = tonumber(ARGV[1])
local identity_limit = tonumber(ARGV[2])
local community_limit = tonumber(ARGV[3])
local fleet_limit = tonumber(ARGV[4])

if window == nil or window < 1 or KEYS[1] == KEYS[2] or KEYS[1] == KEYS[3] or KEYS[2] == KEYS[3] then
    return {4, 0, identity_limit or 0, 0, 0, community_limit or 0, 0, 0, fleet_limit or 0, 0}
end

if identity_limit == nil or community_limit == nil or fleet_limit == nil
    or identity_limit < 0 or community_limit < 0 or fleet_limit < 0 then
    return {5, 0, identity_limit or 0, 0, 0, community_limit or 0, 0, 0, fleet_limit or 0, 0}
end

local function reset_secs(pttl_ms, win)
    if pttl_ms < 0 then
        return win
    end
    if pttl_ms == 0 then
        return 0
    end
    return math.floor((pttl_ms + 999) / 1000)
end

local function window_ms()
    local ms = math.floor(window * 1000)
    if ms < 1 then
        return 1
    end
    return ms
end

local function absolute_now_ms()
    local t = redis.call('TIME')
    return tonumber(t[1]) * 1000 + math.floor(tonumber(t[2]) / 1000)
end

local function expire_at(key)
    return tonumber(redis.call('PEXPIRETIME', key)) or -2
end

-- Redis-INCR canonical nonnegative signed-64: "0" or [1-9][0-9]*.
local function parse_counter(raw)
    if raw == false then
        return 0, 'missing'
    end
    if type(raw) ~= 'string' then
        return nil, 'corrupt'
    end
    if raw:match('^%-%d+$') then
        return nil, 'negative'
    end
    if raw == '0' then
        return 0, 'ok'
    end
    if not raw:match('^[1-9]%d*$') then
        return nil, 'corrupt'
    end
    if #raw > 19 then
        return nil, 'overflow'
    end
    if #raw == 19 and raw > '9223372036854775807' then
        return nil, 'overflow'
    end
    if raw == '9223372036854775807' then
        return tonumber(raw), 'max'
    end
    local n = tonumber(raw)
    if n == nil then
        return nil, 'corrupt'
    end
    return n, 'ok'
end

local function corrupt()
    return {5, 0, identity_limit, 0, 0, community_limit, 0, 0, fleet_limit, 0}
end

local function pin_keys_at(at)
    if at < 1 then
        return
    end
    redis.call('PEXPIREAT', KEYS[1], at)
    redis.call('PEXPIREAT', KEYS[2], at)
    redis.call('PEXPIREAT', KEYS[3], at)
end

-- Never SET a missing identity/community key on the deny/repair path.
-- Allow still uses this after INCR: a missing key recreated by INCR must
-- receive the live fleet stamp. Deny does not use this helper.
local function pin_existing_at(key, at)
    if at < 1 then
        return
    end
    if redis.call('EXISTS', key) == 1 then
        redis.call('PEXPIREAT', key, at)
    end
end

local function restore_key(key, raw, at)
    if raw == false then
        redis.call('DEL', key)
        return
    end
    if at > 0 then
        redis.call('SET', key, raw, 'PXAT', at)
        return
    end
    redis.call('SET', key, raw)
    if at == -1 then
        redis.call('PERSIST', key)
    end
end

local function read_ttl(key, raw)
    local pttl = redis.call('PTTL', key)
    local at = expire_at(key)
    if raw == false then
        if pttl ~= -2 or at ~= -2 then
            return nil, nil, 'corrupt'
        end
        return pttl, at, 'missing'
    end
    if pttl == -2 or pttl < -1 then
        return nil, nil, 'corrupt'
    end
    if pttl == -1 then
        if at ~= -1 then
            return nil, nil, 'corrupt'
        end
        return pttl, at, 'persistent'
    end
    if pttl == 0 then
        return pttl, at, 'inactive'
    end
    if at < 1 then
        return nil, nil, 'corrupt'
    end
    return pttl, at, 'live'
end

local function admit_fresh_window()
    local ms = window_ms()
    redis.call('SET', KEYS[3], 1, 'PX', ms)
    local at = expire_at(KEYS[3])
    if at < 1 then
        redis.call('SET', KEYS[3], 1, 'PX', ms)
        at = expire_at(KEYS[3])
        if at < 1 then
            at = absolute_now_ms() + ms
            redis.call('PEXPIREAT', KEYS[3], at)
            at = expire_at(KEYS[3])
            if at < 1 then
                at = absolute_now_ms() + ms
            end
        end
    end
    redis.call('SET', KEYS[1], 1, 'PXAT', at)
    redis.call('SET', KEYS[2], 1, 'PXAT', at)
    pin_keys_at(at)
    at = expire_at(KEYS[3])
    if at < 1 then
        redis.call('SET', KEYS[3], 1, 'PX', ms)
        at = expire_at(KEYS[3])
        if at < 1 then
            at = absolute_now_ms() + ms
            redis.call('PEXPIREAT', KEYS[3], at)
            at = expire_at(KEYS[3])
            if at < 1 then
                at = absolute_now_ms() + ms
            end
        end
        redis.call('SET', KEYS[1], 1, 'PXAT', at)
        redis.call('SET', KEYS[2], 1, 'PXAT', at)
        pin_keys_at(at)
    end
    local reset = reset_secs(redis.call('PTTL', KEYS[3]), window)
    return {0, 1, identity_limit, reset, 1, community_limit, reset, 1, fleet_limit, reset}
end

-- Denial may skip PEXPIREAT when a present key's captured absolute
-- deadline already equals the freshly read live fleet deadline. Deny never
-- INCR or SET, so the captured identity/community stamp cannot have been
-- recreated by this script. Allow cannot use that shortcut: INCR of a
-- missing or crossed-window key recreates a persistent counter that must
-- still receive and verify post-mutation expiry against the live fleet stamp.
-- Absent keys stay absent (PEXPIREAT never creates). Present misaligned or
-- persistent keys are repaired to the live fleet deadline, never beyond it.
-- An invalid fleet deadline fails closed without counter mutation.
local function deny(code, icount, ccount, fcount, iraw, iat, craw, cat)
    local live_fat = expire_at(KEYS[3])
    if live_fat < 1 then
        return corrupt()
    end
    if iraw ~= false and iat ~= live_fat then
        redis.call('PEXPIREAT', KEYS[1], live_fat)
    end
    if craw ~= false and cat ~= live_fat then
        redis.call('PEXPIREAT', KEYS[2], live_fat)
    end
    local i_reset = reset_secs(redis.call('PTTL', KEYS[1]), window)
    local c_reset = reset_secs(redis.call('PTTL', KEYS[2]), window)
    local f_reset = reset_secs(redis.call('PTTL', KEYS[3]), window)
    return {code, icount, identity_limit, i_reset, ccount, community_limit, c_reset, fcount, fleet_limit, f_reset}
end

local function safe_get(key)
    local ok, raw = pcall(function()
        return redis.call('GET', key)
    end)
    if not ok then
        return nil, 'wrongtype'
    end
    return raw, 'ok'
end

local function parse_or_wrongtype(raw, get_stat)
    if get_stat == 'wrongtype' then
        return nil, 'wrongtype'
    end
    return parse_counter(raw)
end

-- Persistent corrupt fleet would otherwise fail closed forever. PEXPIRE
-- only when PTTL == -1. Never SET/INCR/DEL the value, never touch
-- identity/community, never replace an already finite fleet TTL.
-- WRONGTYPE is caught so a raw Lua error cannot skip this attempt.
local function quarantine_persistent_corrupt_fleet()
    local fpttl = redis.call('PTTL', KEYS[3])
    if fpttl == -1 then
        local ms = window_ms()
        pcall(function()
            redis.call('PEXPIRE', KEYS[3], ms)
        end)
    end
end

-- Fleet first so WRONGTYPE/garbage cannot skip quarantine via a raw GET error.
local fraw, fget = safe_get(KEYS[3])
local fcount, fstat = parse_or_wrongtype(fraw, fget)
if fstat == 'corrupt' or fstat == 'negative' or fstat == 'overflow' or fstat == 'wrongtype' then
    quarantine_persistent_corrupt_fleet()
    return corrupt()
end

local iraw, iget = safe_get(KEYS[1])
local craw, cget = safe_get(KEYS[2])
local icount, istat = parse_or_wrongtype(iraw, iget)
local ccount, cstat = parse_or_wrongtype(craw, cget)
if istat == 'corrupt' or istat == 'negative' or istat == 'overflow' or istat == 'wrongtype'
    or cstat == 'corrupt' or cstat == 'negative' or cstat == 'overflow' or cstat == 'wrongtype' then
    return corrupt()
end

local ipttl, iat, ittl = read_ttl(KEYS[1], iraw)
local cpttl, cat, cttl = read_ttl(KEYS[2], craw)
local fpttl, fat, fttl = read_ttl(KEYS[3], fraw)
if ittl == 'corrupt' or cttl == 'corrupt' or fttl == 'corrupt' then
    return corrupt()
end

local ms = window_ms()

-- PTTL == -1 is a live key with no expiry: preserve the count, repair a
-- bounded window, then apply ordinary limit denial. Never treat it as inactive.
-- Identity/community persistent repair is deferred to deny (captured -1 is
-- not equal to the live fleet deadline) or to post-INCR pin on allow.
if fttl == 'persistent' then
    redis.call('PEXPIRE', KEYS[3], ms)
    fpttl, fat, fttl = read_ttl(KEYS[3], fraw)
    if fttl == 'persistent' then
        redis.call('PEXPIRE', KEYS[3], ms)
        fpttl, fat, fttl = read_ttl(KEYS[3], fraw)
    end
    if fttl ~= 'live' then
        return corrupt()
    end
end

local fleet_active = fttl == 'live'
if not fleet_active then
    icount = 0
    ccount = 0
    fcount = 0
end

if (istat == 'max' or cstat == 'max' or fstat == 'max') and fleet_active then
    if icount >= identity_limit then
        return deny(1, icount, ccount, fcount, iraw, iat, craw, cat)
    end
    if ccount >= community_limit then
        return deny(2, icount, ccount, fcount, iraw, iat, craw, cat)
    end
    if fcount >= fleet_limit then
        return deny(3, icount, ccount, fcount, iraw, iat, craw, cat)
    end
    return corrupt()
end

if icount >= identity_limit then
    return deny(1, icount, ccount, fcount, iraw, iat, craw, cat)
end
if ccount >= community_limit then
    return deny(2, icount, ccount, fcount, iraw, iat, craw, cat)
end
if fcount >= fleet_limit then
    return deny(3, icount, ccount, fcount, iraw, iat, craw, cat)
end

if not fleet_active then
    return admit_fresh_window()
end

local i_restore_raw = iraw
local i_restore_at = expire_at(KEYS[1])
local c_restore_raw = craw
local c_restore_at = expire_at(KEYS[2])
local ok_i, new_i = pcall(function()
    return redis.call('INCR', KEYS[1])
end)
if not ok_i then
    restore_key(KEYS[1], i_restore_raw, i_restore_at)
    return corrupt()
end
local live_ms = redis.call('PTTL', KEYS[3])
if live_ms < 1 then
    return admit_fresh_window()
end
local live_at = expire_at(KEYS[3])
if live_at < 1 then
    return admit_fresh_window()
end
local ok_c, new_c = pcall(function()
    return redis.call('INCR', KEYS[2])
end)
if not ok_c then
    restore_key(KEYS[1], i_restore_raw, i_restore_at)
    restore_key(KEYS[2], c_restore_raw, c_restore_at)
    return corrupt()
end
live_ms = redis.call('PTTL', KEYS[3])
if live_ms < 1 then
    return admit_fresh_window()
end
local live_at2 = expire_at(KEYS[3])
if live_at2 < 1 or live_at2 ~= live_at then
    return admit_fresh_window()
end
local ok_f, new_f = pcall(function()
    return redis.call('INCR', KEYS[3])
end)
if not ok_f then
    restore_key(KEYS[1], i_restore_raw, i_restore_at)
    restore_key(KEYS[2], c_restore_raw, c_restore_at)
    return corrupt()
end
local post_ms = redis.call('PTTL', KEYS[3])
local post_at = expire_at(KEYS[3])
if post_ms < 1 or post_at < 1 or post_at ~= live_at then
    return admit_fresh_window()
end
-- Do not skip these from a pre-INCR captured deadline. INCR of a missing
-- or crossed-window identity/community recreates a persistent counter that
-- must still receive the live fleet stamp after mutation.
pin_existing_at(KEYS[1], live_at)
pin_existing_at(KEYS[2], live_at)
local reset = reset_secs(redis.call('PTTL', KEYS[3]), window)
return {0, new_i, identity_limit, reset, new_c, community_limit, reset, new_f, fleet_limit, reset}
"#;

/// Read-only identity+fleet peek for a proven hierarchical identity denial.
///
/// KEYS[1] identity key, KEYS[2] fleet key. ARGV: identity_limit.
/// Returns {code, current, limit, reset} where code is 0=not proven,
/// 1=proven identity denial, 2=window/alias/limit contract.
///
/// This script MUST NOT write, MUST NOT read a community key, and MUST NOT
/// create or move a deadline. Proven denial requires a canonical nonnegative
/// Redis-INCR identity integer at or above the nonzero identity limit, live
/// finite identity `PTTL`/`PEXPIRETIME`, a canonical nonnegative fleet
/// integer with a live finite TTL and the same absolute expiry, and distinct
/// keys. Missing, under-limit, stale, persistent, misaligned, or semantically
/// corrupt state returns code 0. WRONGTYPE is treated as not-proven, not as
/// a raw Lua error. Command/response-contract failures still fail closed
/// in Rust.
const IDENTITY_DENIAL_PEEK_SCRIPT: &str = r#"
local identity_limit = tonumber(ARGV[1])
if KEYS[1] == KEYS[2] or identity_limit == nil or identity_limit < 1 then
    return {2, 0, identity_limit or 0, 0}
end

local function reset_secs(pttl_ms)
    if pttl_ms < 1 then
        return 0
    end
    return math.floor((pttl_ms + 999) / 1000)
end

local function expire_at(key)
    return tonumber(redis.call('PEXPIRETIME', key)) or -2
end

-- Redis-INCR canonical nonnegative signed-64: "0" or [1-9][0-9]*.
local function parse_counter(raw)
    if raw == false then
        return 0, 'missing'
    end
    if type(raw) ~= 'string' then
        return nil, 'corrupt'
    end
    if raw:match('^%-%d+$') then
        return nil, 'negative'
    end
    if raw == '0' then
        return 0, 'ok'
    end
    if not raw:match('^[1-9]%d*$') then
        return nil, 'corrupt'
    end
    if #raw > 19 then
        return nil, 'overflow'
    end
    if #raw == 19 and raw > '9223372036854775807' then
        return nil, 'overflow'
    end
    if raw == '9223372036854775807' then
        return tonumber(raw), 'max'
    end
    local n = tonumber(raw)
    if n == nil then
        return nil, 'corrupt'
    end
    return n, 'ok'
end

local function safe_get(key)
    local ok, raw = pcall(function()
        return redis.call('GET', key)
    end)
    if not ok then
        return nil, 'wrongtype'
    end
    return raw, 'ok'
end

local function fallthrough()
    return {0, 0, identity_limit, 0}
end

local iraw, iget = safe_get(KEYS[1])
local fraw, fget = safe_get(KEYS[2])
if iget ~= 'ok' or fget ~= 'ok' then
    return fallthrough()
end

local icount, istat = parse_counter(iraw)
local fcount, fstat = parse_counter(fraw)
if (istat ~= 'ok' and istat ~= 'max') or (fstat ~= 'ok' and fstat ~= 'max') then
    return fallthrough()
end
if istat ~= 'max' and icount < identity_limit then
    return fallthrough()
end

local ipttl = redis.call('PTTL', KEYS[1])
local iat = expire_at(KEYS[1])
local fpttl = redis.call('PTTL', KEYS[2])
local fat = expire_at(KEYS[2])
if ipttl < 1 or iat < 1 or fpttl < 1 or fat < 1 or iat ~= fat then
    return fallthrough()
end

return {1, icount, identity_limit, reset_secs(ipttl)}
"#;

/// Sound paired accounting uses one shared window. [`PairedAdmissionRequest`]
/// cannot store a split clock; this remains a fail-closed belt for the Lua
/// ARGV path and zero windows.
fn require_shared_paired_window(
    tenant_window_secs: u64,
    fleet_window_secs: u64,
) -> Result<(), AuthError> {
    if tenant_window_secs == 0 || fleet_window_secs == 0 || tenant_window_secs != fleet_window_secs
    {
        Err(AuthError::Internal(
            "paired admission requires a shared tenant/fleet window".into(),
        ))
    } else {
        Ok(())
    }
}

/// Run the atomic rate-limit Lua script against `key` and return a
/// [`RateLimitResult`].
///
/// If the TTL comes back negative (key exists without expiry — broken state
/// from a prior crash), the key is repaired with a fresh EXPIRE and a warning
/// is logged.
async fn run_rate_limit(
    pool: &deadpool_redis::Pool,
    key: &str,
    window_secs: u64,
    limit: u64,
) -> Result<RateLimitResult, AuthError> {
    let mut conn = pool
        .get()
        .await
        .map_err(|e| AuthError::Internal(format!("Redis pool: {e}")))?;

    let script = Script::new(RATE_LIMIT_SCRIPT);
    let (count, ttl): (u64, i64) = script
        .key(key)
        .arg(window_secs as i64)
        .invoke_async(&mut *conn)
        .await
        .map_err(|e| AuthError::Internal(format!("Redis rate limit script: {e}")))?;

    // ttl == -1 means the key exists but has no expiry — broken state from a
    // prior crash between INCR and EXPIRE. Repair it now.
    let reset_in_secs = if ttl < 0 {
        tracing::warn!(key = %key, "rate limit key has no TTL — repairing");
        let _: () = redis::cmd("EXPIRE")
            .arg(key)
            .arg(window_secs as i64)
            .query_async(&mut *conn)
            .await
            .map_err(|e| AuthError::Internal(format!("Redis EXPIRE repair: {e}")))?;
        // After repair, the window resets to the full duration.
        window_secs
    } else {
        ttl.max(0) as u64
    };

    if count <= limit {
        Ok(RateLimitResult::allowed(count, limit, reset_in_secs))
    } else {
        Ok(RateLimitResult::denied(count, limit, reset_in_secs))
    }
}

/// Redis-backed rate limiter using fixed-window counters.
///
/// Pubkey keys are community-scoped via `&TenantContext`:
/// `buzz:{community}:ratelimit:{pubkey_hex}:{suffix}`. IP keys remain
/// operator-global: `buzz:ratelimit:ip:{ip}:conn`. The counter and its TTL are
/// managed atomically via a Lua script to prevent keys from persisting without
/// expiry.
pub struct RedisRateLimiter {
    pool: deadpool_redis::Pool,
}

impl RedisRateLimiter {
    /// Create a new `RedisRateLimiter` backed by the given connection pool.
    pub fn new(pool: deadpool_redis::Pool) -> Self {
        Self { pool }
    }
}

impl RateLimiter for RedisRateLimiter {
    async fn check_and_increment(
        &self,
        ctx: &TenantContext,
        pubkey: &PublicKey,
        limit_type: LimitType,
        window_secs: u64,
        limit: u64,
    ) -> Result<RateLimitResult, AuthError> {
        let key = buzz_auth::rate_limit::rate_limit_key(ctx, pubkey, &limit_type);
        run_rate_limit(&self.pool, &key, window_secs, limit).await
    }

    async fn check_ip_connection(
        &self,
        ip: &IpAddr,
        window_secs: u64,
        limit: u64,
    ) -> Result<RateLimitResult, AuthError> {
        let key = buzz_auth::rate_limit::ip_rate_limit_key(ip);
        run_rate_limit(&self.pool, &key, window_secs, limit).await
    }

    async fn check_paired_admission(
        &self,
        request: PairedAdmissionRequest<'_>,
    ) -> Result<PairedAdmissionOutcome, AuthError> {
        let tenant_key = buzz_auth::rate_limit::rate_limit_key(
            request.tenant,
            request.pubkey,
            &request.limit_type,
        );
        let fleet_key = buzz_auth::rate_limit::ip_rate_limit_key(request.fleet_ip);
        let window_secs = request.window_secs();
        run_paired_admission(
            &self.pool,
            &tenant_key,
            &fleet_key,
            window_secs,
            request.tenant_limit,
            window_secs,
            request.fleet_limit,
        )
        .await
    }

    async fn check_hierarchical_admission(
        &self,
        request: HierarchicalAdmissionRequest<'_>,
    ) -> Result<HierarchicalAdmissionOutcome, AuthError> {
        self.check_hierarchical_admission_classified(request)
            .await
            .map_err(KeyedAdmissionFailure::into_error)
    }

    async fn peek_hierarchical_identity_denial(
        &self,
        request: HierarchicalIdentityDenialPeekRequest<'_>,
    ) -> Result<HierarchicalIdentityDenialPeekOutcome, AuthError> {
        self.peek_hierarchical_identity_denial_classified(request)
            .await
            .map_err(KeyedAdmissionFailure::into_error)
    }

    /// One identity+community+fleet decision. The optional identity-denial
    /// peek is read-only and never creates or increments a key. Proven
    /// identity denial returns without the mutating script. Otherwise the
    /// Lua script is the single atomic mutating operation: Allowed
    /// increments all three once; explicit denial and known pre-mutation
    /// corruption increment none. An ambiguous timeout or lost reply is
    /// returned once and MUST NOT be blindly retried by the caller — this
    /// method never retries internally, so a subset charge cannot be
    /// completed by a second dispatch.
    async fn check_hierarchical_admission_classified(
        &self,
        request: HierarchicalAdmissionRequest<'_>,
    ) -> Result<HierarchicalAdmissionOutcome, KeyedAdmissionFailure> {
        let identity_key = buzz_auth::rate_limit::rate_limit_key(
            request.tenant,
            request.identity,
            &request.limit_type,
        );
        let community_key = buzz_auth::rate_limit::rate_limit_key(
            request.tenant,
            request.community,
            &request.limit_type,
        );
        let fleet_key = buzz_auth::rate_limit::ip_rate_limit_key(request.fleet_ip);
        require_hierarchical_contract(
            &identity_key,
            &community_key,
            &fleet_key,
            request.window_secs(),
        )?;
        if let Some(identity_limit) = NonZeroU64::new(request.limits.identity)
            .filter(|identity_limit| identity_limit.get() <= i64::MAX as u64)
        {
            match run_identity_denial_peek(
                &self.pool,
                &identity_key,
                &fleet_key,
                identity_limit.get(),
            )
            .await?
            {
                HierarchicalIdentityDenialPeekOutcome::Denied(result) => {
                    return Ok(HierarchicalAdmissionOutcome::IdentityDenied(result));
                }
                HierarchicalIdentityDenialPeekOutcome::NotDenied => {}
            }
        }
        run_hierarchical_admission(
            &self.pool,
            &identity_key,
            &community_key,
            &fleet_key,
            request.window_secs(),
            request.limits,
        )
        .await
    }

    async fn peek_hierarchical_identity_denial_classified(
        &self,
        request: HierarchicalIdentityDenialPeekRequest<'_>,
    ) -> Result<HierarchicalIdentityDenialPeekOutcome, KeyedAdmissionFailure> {
        let identity_key = buzz_auth::rate_limit::rate_limit_key(
            request.tenant,
            request.identity,
            &request.limit_type,
        );
        let fleet_key = buzz_auth::rate_limit::ip_rate_limit_key(request.fleet_ip);
        run_identity_denial_peek(
            &self.pool,
            &identity_key,
            &fleet_key,
            request.identity_limit(),
        )
        .await
    }
}

async fn run_paired_admission(
    pool: &deadpool_redis::Pool,
    tenant_key: &str,
    fleet_key: &str,
    tenant_window_secs: u64,
    tenant_limit: u64,
    fleet_window_secs: u64,
    fleet_limit: u64,
) -> Result<PairedAdmissionOutcome, AuthError> {
    require_shared_paired_window(tenant_window_secs, fleet_window_secs)?;
    let mut conn = pool
        .get()
        .await
        .map_err(|e| AuthError::Internal(format!("Redis pool: {e}")))?;
    let script = Script::new(PAIRED_ADMISSION_SCRIPT);
    let row: Vec<i64> = script
        .key(tenant_key)
        .key(fleet_key)
        .arg(tenant_window_secs as i64)
        .arg(tenant_limit as i64)
        .arg(fleet_window_secs as i64)
        .arg(fleet_limit as i64)
        .invoke_async(&mut *conn)
        .await
        .map_err(|e| AuthError::Internal(format!("Redis paired admission script: {e}")))?;
    outcome_from_script_row(row)
}

fn outcome_from_script_row(row: Vec<i64>) -> Result<PairedAdmissionOutcome, AuthError> {
    if row.len() != 7 {
        return Err(AuthError::Internal(
            "Redis paired admission script returned an unexpected result".into(),
        ));
    }
    let code = row[0];
    let tenant = decode_counter(row[1], row[2], row[3], code != 1);
    let fleet = decode_counter(row[4], row[5], row[6], code != 2);
    match code {
        0 => Ok(PairedAdmissionOutcome::Allowed { tenant, fleet }),
        1 => Ok(PairedAdmissionOutcome::TenantDenied(tenant)),
        2 => Ok(PairedAdmissionOutcome::FleetDenied(fleet)),
        3 => Err(AuthError::Internal(
            "paired admission requires a shared tenant/fleet window".into(),
        )),
        4 => Err(AuthError::Internal(
            "paired admission counter is corrupt".into(),
        )),
        _ => Err(AuthError::Internal(
            "Redis paired admission script returned an unknown code".into(),
        )),
    }
}

fn decode_counter(current: i64, limit: i64, reset_in_secs: i64, allowed: bool) -> RateLimitResult {
    let current = current.max(0) as u64;
    let limit = limit.max(0) as u64;
    let reset_in_secs = reset_in_secs.max(0) as u64;
    if allowed {
        RateLimitResult::allowed(current, limit, reset_in_secs)
    } else {
        RateLimitResult::denied(current, limit, reset_in_secs)
    }
}

fn classify_redis_error(error: &redis::RedisError) -> KeyedAdmissionErrorClass {
    if error.is_timeout() {
        KeyedAdmissionErrorClass::BackendTimeout
    } else {
        KeyedAdmissionErrorClass::BackendUnavailable
    }
}

fn keyed_pool_failure(error: deadpool_redis::PoolError) -> KeyedAdmissionFailure {
    let class = match &error {
        deadpool_redis::PoolError::Timeout(_) => KeyedAdmissionErrorClass::BackendTimeout,
        deadpool_redis::PoolError::Backend(backend) => classify_redis_error(backend),
        _ => KeyedAdmissionErrorClass::BackendUnavailable,
    };
    KeyedAdmissionFailure::new(AuthError::Internal(format!("Redis pool: {error}")), class)
}

fn keyed_script_failure(prefix: &'static str, error: redis::RedisError) -> KeyedAdmissionFailure {
    KeyedAdmissionFailure::new(
        AuthError::Internal(format!("{prefix}: {error}")),
        classify_redis_error(&error),
    )
}

fn require_hierarchical_contract(
    identity_key: &str,
    community_key: &str,
    fleet_key: &str,
    window_secs: u64,
) -> Result<(), KeyedAdmissionFailure> {
    if window_secs == 0
        || identity_key == community_key
        || identity_key == fleet_key
        || community_key == fleet_key
    {
        Err(KeyedAdmissionFailure::new(
            AuthError::Internal(
                "hierarchical admission requires a shared identity/community/fleet window".into(),
            ),
            KeyedAdmissionErrorClass::Contract,
        ))
    } else {
        Ok(())
    }
}

async fn run_hierarchical_admission(
    pool: &deadpool_redis::Pool,
    identity_key: &str,
    community_key: &str,
    fleet_key: &str,
    window_secs: u64,
    limits: HierarchicalAdmissionLimits,
) -> Result<HierarchicalAdmissionOutcome, KeyedAdmissionFailure> {
    require_hierarchical_contract(identity_key, community_key, fleet_key, window_secs)?;
    let mut conn = pool.get().await.map_err(keyed_pool_failure)?;
    let script = Script::new(HIERARCHICAL_ADMISSION_SCRIPT);
    let row: Vec<i64> = script
        .key(identity_key)
        .key(community_key)
        .key(fleet_key)
        .arg(window_secs as i64)
        .arg(limits.identity as i64)
        .arg(limits.community as i64)
        .arg(limits.fleet as i64)
        .invoke_async(&mut *conn)
        .await
        .map_err(|error| keyed_script_failure("Redis hierarchical admission script", error))?;
    hierarchical_outcome_from_script_row(row)
}

fn hierarchical_outcome_from_script_row(
    row: Vec<i64>,
) -> Result<HierarchicalAdmissionOutcome, KeyedAdmissionFailure> {
    if row.len() != 10 {
        return Err(KeyedAdmissionFailure::new(
            AuthError::Internal(
                "Redis hierarchical admission script returned an unexpected result".into(),
            ),
            KeyedAdmissionErrorClass::Contract,
        ));
    }
    let code = row[0];
    let identity = decode_counter(row[1], row[2], row[3], code != 1);
    let community = decode_counter(row[4], row[5], row[6], code != 2);
    let fleet = decode_counter(row[7], row[8], row[9], code != 3);
    match code {
        0 => Ok(HierarchicalAdmissionOutcome::Allowed {
            identity,
            community,
            fleet,
        }),
        1 => Ok(HierarchicalAdmissionOutcome::IdentityDenied(identity)),
        2 => Ok(HierarchicalAdmissionOutcome::CommunityDenied(community)),
        3 => Ok(HierarchicalAdmissionOutcome::FleetDenied(fleet)),
        4 => Err(KeyedAdmissionFailure::new(
            AuthError::Internal(
                "hierarchical admission requires a shared identity/community/fleet window".into(),
            ),
            KeyedAdmissionErrorClass::Contract,
        )),
        5 => Err(KeyedAdmissionFailure::new(
            AuthError::Internal("hierarchical admission counter is corrupt".into()),
            KeyedAdmissionErrorClass::CounterCorrupt,
        )),
        _ => Err(KeyedAdmissionFailure::new(
            AuthError::Internal(
                "Redis hierarchical admission script returned an unknown code".into(),
            ),
            KeyedAdmissionErrorClass::Contract,
        )),
    }
}

fn require_identity_denial_peek_contract(
    identity_key: &str,
    fleet_key: &str,
    identity_limit: u64,
) -> Result<(), KeyedAdmissionFailure> {
    if identity_limit == 0 || identity_limit > i64::MAX as u64 || identity_key == fleet_key {
        Err(KeyedAdmissionFailure::new(
            AuthError::Internal(
                "hierarchical identity denial peek requires a nonzero identity limit and distinct identity/fleet keys".into(),
            ),
            KeyedAdmissionErrorClass::Contract,
        ))
    } else {
        Ok(())
    }
}

async fn run_identity_denial_peek(
    pool: &deadpool_redis::Pool,
    identity_key: &str,
    fleet_key: &str,
    identity_limit: u64,
) -> Result<HierarchicalIdentityDenialPeekOutcome, KeyedAdmissionFailure> {
    require_identity_denial_peek_contract(identity_key, fleet_key, identity_limit)?;
    let mut conn = pool.get().await.map_err(keyed_pool_failure)?;
    let script = Script::new(IDENTITY_DENIAL_PEEK_SCRIPT);
    let row: Vec<i64> = script
        .key(identity_key)
        .key(fleet_key)
        .arg(identity_limit as i64)
        .invoke_async(&mut *conn)
        .await
        .map_err(|error| keyed_script_failure("Redis identity denial peek script", error))?;
    identity_denial_peek_from_script_row(row)
}

fn identity_denial_peek_from_script_row(
    row: Vec<i64>,
) -> Result<HierarchicalIdentityDenialPeekOutcome, KeyedAdmissionFailure> {
    if row.len() != 4 {
        return Err(KeyedAdmissionFailure::new(
            AuthError::Internal(
                "Redis identity denial peek script returned an unexpected result".into(),
            ),
            KeyedAdmissionErrorClass::Contract,
        ));
    }
    match row[0] {
        0 => Ok(HierarchicalIdentityDenialPeekOutcome::NotDenied),
        1 => Ok(HierarchicalIdentityDenialPeekOutcome::Denied(decode_counter(
            row[1], row[2], row[3], false,
        ))),
        2 => Err(KeyedAdmissionFailure::new(
            AuthError::Internal(
                "hierarchical identity denial peek requires a nonzero identity limit and distinct identity/fleet keys".into(),
            ),
            KeyedAdmissionErrorClass::Contract,
        )),
        _ => Err(KeyedAdmissionFailure::new(
            AuthError::Internal(
                "Redis identity denial peek script returned an unknown code".into(),
            ),
            KeyedAdmissionErrorClass::Contract,
        )),
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv6Addr};
    use std::num::NonZeroU64;
    use std::sync::Arc;

    use buzz_auth::rate_limit::{ip_rate_limit_key, rate_limit_key};
    use buzz_core::{CommunityId, TenantContext};
    use futures_util::StreamExt;
    use nostr::Keys;
    use redis::AsyncCommands;
    use uuid::Uuid;

    use super::*;

    async fn redis_pool() -> Option<deadpool_redis::Pool> {
        let url = std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".into());
        deadpool_redis::Config::from_url(url)
            .create_pool(Some(deadpool_redis::Runtime::Tokio1))
            .ok()
    }

    fn unique_tenant() -> TenantContext {
        TenantContext::resolved(
            CommunityId::from_uuid(Uuid::new_v4()),
            "paired-admission.test",
        )
    }

    fn unique_ip() -> IpAddr {
        let id = Uuid::new_v4().as_u128();
        let addr = (0x2001_0db8u128 << 96) | (id & ((1u128 << 96) - 1));
        IpAddr::V6(Ipv6Addr::from(addr))
    }

    /// UUID-backed high-entropy IPv6 documentation-prefix (`2001:db8::/32`)
    /// address distinct from `other`, including when `other` is IPv6. A draw
    /// equal to `other` is deterministically altered in-prefix.
    fn unique_ip_distinct_from(other: IpAddr) -> IpAddr {
        let id = Uuid::new_v4().as_u128();
        let mut addr = (0x2001_0db8u128 << 96) | (id & ((1u128 << 96) - 1));
        if IpAddr::V6(Ipv6Addr::from(addr)) == other {
            addr ^= 1;
        }
        IpAddr::V6(Ipv6Addr::from(addr))
    }

    async fn get_count(pool: &deadpool_redis::Pool, key: &str) -> i64 {
        let mut conn = pool.get().await.expect("redis conn");
        let value: Option<i64> = conn.get(key).await.expect("get");
        value.unwrap_or(0)
    }

    async fn get_ttl(pool: &deadpool_redis::Pool, key: &str) -> i64 {
        let mut conn = pool.get().await.expect("redis conn");
        redis::cmd("TTL")
            .arg(key)
            .query_async(&mut *conn)
            .await
            .expect("ttl")
    }

    async fn get_pttl(pool: &deadpool_redis::Pool, key: &str) -> i64 {
        let mut conn = pool.get().await.expect("redis conn");
        redis::cmd("PTTL")
            .arg(key)
            .query_async(&mut *conn)
            .await
            .expect("pttl")
    }

    async fn get_pexpiretime(pool: &deadpool_redis::Pool, key: &str) -> i64 {
        let mut conn = pool.get().await.expect("redis conn");
        redis::cmd("PEXPIRETIME")
            .arg(key)
            .query_async(&mut *conn)
            .await
            .expect("pexpiretime")
    }

    fn assert_absolute_deadline_unmoved(label: &str, before: i64, after: i64) {
        assert!(
            before > 0 && after > 0,
            "{label} lost expiry: before={before} after={after}"
        );
        assert_eq!(
            after, before,
            "{label} absolute deadline moved: before={before} after={after}"
        );
    }

    fn assert_same_deadline(tenant_at: i64, fleet_at: i64) {
        assert!(
            tenant_at > 0 && fleet_at > 0,
            "keys must keep a positive absolute expiry: tenant={tenant_at} fleet={fleet_at}"
        );
        assert_eq!(
            tenant_at, fleet_at,
            "charged keys must share one exact absolute deadline: tenant={tenant_at} fleet={fleet_at}"
        );
    }

    async fn assert_exact_shared_deadline(
        pool: &deadpool_redis::Pool,
        tenant_key: &str,
        fleet_key: &str,
    ) {
        let tenant_at = get_pexpiretime(pool, tenant_key).await;
        let fleet_at = get_pexpiretime(pool, fleet_key).await;
        assert_same_deadline(tenant_at, fleet_at);
    }

    async fn assert_admitted_bounded_pttl(
        pool: &deadpool_redis::Pool,
        tenant_key: &str,
        fleet_key: &str,
        window_secs: u64,
    ) {
        let tpttl = get_pttl(pool, tenant_key).await;
        let fpttl = get_pttl(pool, fleet_key).await;
        assert!(
            tpttl > 0,
            "admitted tenant must have a positive bounded PTTL, got {tpttl}"
        );
        assert!(
            fpttl > 0,
            "admitted fleet must have a positive bounded PTTL, got {fpttl}"
        );
        assert_ne!(fpttl, -1, "fleet INCR must not recreate a persistent key");
        assert_ne!(tpttl, -1, "tenant must not be left without expiry");
        let window_ms = (window_secs as i64).saturating_mul(1000) + 50;
        assert!(
            fpttl <= window_ms,
            "fleet PTTL {fpttl} exceeds window {window_ms}ms"
        );
        assert_exact_shared_deadline(pool, tenant_key, fleet_key).await;
    }

    async fn run_paired_admission_with_fleet_del_between(
        pool: &deadpool_redis::Pool,
        tenant_key: &str,
        fleet_key: &str,
        window_secs: u64,
        tenant_limit: u64,
        fleet_limit: u64,
        injection_fragments: (&str, &str),
    ) -> PairedAdmissionOutcome {
        require_shared_paired_window(window_secs, window_secs).expect("shared window");
        let (before, after) = injection_fragments;
        let needle = format!("{before}{after}");
        assert_eq!(
            PAIRED_ADMISSION_SCRIPT.matches(&needle).count(),
            1,
            "expected production-script fragment for fleet-expiry injection was not found"
        );
        let injected = PAIRED_ADMISSION_SCRIPT.replacen(
            &needle,
            &format!("{before}redis.call('DEL', KEYS[2])\n{after}"),
            1,
        );
        let mut conn = pool.get().await.expect("redis conn");
        let script = Script::new(&injected);
        let row: Vec<i64> = script
            .key(tenant_key)
            .key(fleet_key)
            .arg(window_secs as i64)
            .arg(tenant_limit as i64)
            .arg(window_secs as i64)
            .arg(fleet_limit as i64)
            .invoke_async(&mut *conn)
            .await
            .expect("injected paired script");
        outcome_from_script_row(row).expect("injected outcome")
    }

    async fn run_paired_admission_injecting_fleet_expiry(
        pool: &deadpool_redis::Pool,
        tenant_key: &str,
        fleet_key: &str,
        window_secs: u64,
        tenant_limit: u64,
        fleet_limit: u64,
    ) -> PairedAdmissionOutcome {
        run_paired_admission_with_fleet_del_between(
            pool,
            tenant_key,
            fleet_key,
            window_secs,
            tenant_limit,
            fleet_limit,
            (
                "local new_t = redis.call('INCR', KEYS[1])\n",
                "local live_ms = redis.call('PTTL', KEYS[2])",
            ),
        )
        .await
    }

    async fn run_paired_admission_injecting_fleet_expiry_after_live_at(
        pool: &deadpool_redis::Pool,
        tenant_key: &str,
        fleet_key: &str,
        window_secs: u64,
        tenant_limit: u64,
        fleet_limit: u64,
    ) -> PairedAdmissionOutcome {
        run_paired_admission_with_fleet_del_between(
            pool,
            tenant_key,
            fleet_key,
            window_secs,
            tenant_limit,
            fleet_limit,
            (
                "local live_at = expire_at(KEYS[2])\nif live_at < 1 then\n    return admit_fresh_window()\nend\n",
                "local ok, new_f = pcall(function()\n    return redis.call('INCR', KEYS[2])\nend)",
            ),
        )
        .await
    }

    async fn seed_count(pool: &deadpool_redis::Pool, key: &str, count: i64, ttl: i64) {
        let mut conn = pool.get().await.expect("redis conn");
        let _: () = redis::cmd("SET")
            .arg(key)
            .arg(count)
            .arg("EX")
            .arg(ttl)
            .query_async(&mut *conn)
            .await
            .expect("seed");
    }

    async fn seed_count_px(pool: &deadpool_redis::Pool, key: &str, count: i64, ttl_ms: i64) {
        let mut conn = pool.get().await.expect("redis conn");
        let _: () = redis::cmd("SET")
            .arg(key)
            .arg(count)
            .arg("PX")
            .arg(ttl_ms)
            .query_async(&mut *conn)
            .await
            .expect("seed px");
    }

    async fn seed_count_pxat(pool: &deadpool_redis::Pool, key: &str, count: i64, expire_at: i64) {
        let mut conn = pool.get().await.expect("redis conn");
        let _: () = redis::cmd("SET")
            .arg(key)
            .arg(count)
            .arg("PXAT")
            .arg(expire_at)
            .query_async(&mut *conn)
            .await
            .expect("seed pxat");
    }

    async fn del(pool: &deadpool_redis::Pool, key: &str) {
        let mut conn = pool.get().await.expect("redis conn");
        let _: () = redis::cmd("DEL")
            .arg(key)
            .query_async(&mut *conn)
            .await
            .expect("del");
    }

    fn request<'a>(
        tenant: &'a TenantContext,
        pubkey: &'a nostr::PublicKey,
        fleet_ip: &'a IpAddr,
        tenant_limit: u64,
        fleet_limit: u64,
        window: u64,
    ) -> PairedAdmissionRequest<'a> {
        PairedAdmissionRequest::new(
            tenant,
            pubkey,
            LimitType::IpConnections,
            NonZeroU64::new(window).expect("test window is nonzero"),
            tenant_limit,
            fleet_ip,
            fleet_limit,
        )
    }

    async fn get_raw(pool: &deadpool_redis::Pool, key: &str) -> Option<String> {
        let mut conn = pool.get().await.expect("redis conn");
        conn.get(key).await.expect("get raw")
    }

    async fn seed_raw(pool: &deadpool_redis::Pool, key: &str, value: &str, ttl: Option<i64>) {
        let mut conn = pool.get().await.expect("redis conn");
        let mut cmd = redis::cmd("SET");
        cmd.arg(key).arg(value);
        if let Some(ttl) = ttl {
            cmd.arg("EX").arg(ttl);
        }
        let _: () = cmd.query_async(&mut *conn).await.expect("seed raw");
    }

    async fn persist_count(pool: &deadpool_redis::Pool, key: &str, count: i64) {
        let mut conn = pool.get().await.expect("redis conn");
        let _: () = redis::cmd("SET")
            .arg(key)
            .arg(count)
            .query_async(&mut *conn)
            .await
            .expect("persist count");
    }

    #[test]
    fn paired_admission_requires_a_shared_window() {
        assert!(require_shared_paired_window(60, 60).is_ok());
        let err = require_shared_paired_window(30, 60).expect_err("unequal windows");
        let text = err.to_string();
        assert!(
            text.contains("shared tenant/fleet window"),
            "unequal windows must fail closed, got {text}"
        );
        require_shared_paired_window(0, 0).expect_err("equal zero windows");
    }

    #[test]
    fn paired_corrupt_script_code_fails_closed_without_an_outcome() {
        let err =
            outcome_from_script_row(vec![4, 0, 10, 0, 0, 20, 0]).expect_err("code 4 is corrupt");
        assert!(
            err.to_string().contains("corrupt"),
            "corrupt counters must fail closed, got {err}"
        );
    }

    #[tokio::test]
    #[ignore = "requires Redis"]
    async fn paired_tenant_denial_charges_neither_counter() {
        let Some(pool) = redis_pool().await else {
            panic!("local Redis not reachable");
        };
        let limiter = RedisRateLimiter::new(pool.clone());
        let tenant = unique_tenant();
        let keys = Keys::generate();
        let ip = unique_ip();
        let tenant_key = rate_limit_key(&tenant, &keys.public_key(), &LimitType::IpConnections);
        let fleet_key = ip_rate_limit_key(&ip);
        seed_count(&pool, &tenant_key, 2, 30).await;
        seed_count(&pool, &fleet_key, 4, 30).await;
        let before_t = get_count(&pool, &tenant_key).await;
        let before_f = get_count(&pool, &fleet_key).await;
        let before_f_at = get_pexpiretime(&pool, &fleet_key).await;
        let outcome = limiter
            .check_paired_admission(request(&tenant, &keys.public_key(), &ip, 2, 20, 30))
            .await
            .expect("paired");
        assert!(
            matches!(outcome, PairedAdmissionOutcome::TenantDenied(ref result) if !result.allowed),
            "got {outcome:?}"
        );
        assert_eq!(get_count(&pool, &tenant_key).await, before_t);
        assert_eq!(get_count(&pool, &fleet_key).await, before_f);
        let after_f_at = get_pexpiretime(&pool, &fleet_key).await;
        assert_absolute_deadline_unmoved("fleet", before_f_at, after_f_at);
        assert_exact_shared_deadline(&pool, &tenant_key, &fleet_key).await;
        del(&pool, &tenant_key).await;
        del(&pool, &fleet_key).await;
    }

    #[tokio::test]
    #[ignore = "requires Redis"]
    async fn paired_fleet_denial_charges_neither_counter() {
        let Some(pool) = redis_pool().await else {
            panic!("local Redis not reachable");
        };
        let limiter = RedisRateLimiter::new(pool.clone());
        let tenant = unique_tenant();
        let keys = Keys::generate();
        let ip = unique_ip();
        let tenant_key = rate_limit_key(&tenant, &keys.public_key(), &LimitType::IpConnections);
        let fleet_key = ip_rate_limit_key(&ip);
        seed_count(&pool, &tenant_key, 1, 30).await;
        seed_count(&pool, &fleet_key, 5, 30).await;
        let before_t = get_count(&pool, &tenant_key).await;
        let before_f = get_count(&pool, &fleet_key).await;
        let before_f_at = get_pexpiretime(&pool, &fleet_key).await;
        let outcome = limiter
            .check_paired_admission(request(&tenant, &keys.public_key(), &ip, 10, 5, 30))
            .await
            .expect("paired");
        assert!(
            matches!(outcome, PairedAdmissionOutcome::FleetDenied(ref result) if !result.allowed),
            "got {outcome:?}"
        );
        assert_eq!(get_count(&pool, &tenant_key).await, before_t);
        assert_eq!(get_count(&pool, &fleet_key).await, before_f);
        let after_f_at = get_pexpiretime(&pool, &fleet_key).await;
        assert_absolute_deadline_unmoved("fleet", before_f_at, after_f_at);
        assert_exact_shared_deadline(&pool, &tenant_key, &fleet_key).await;
        del(&pool, &tenant_key).await;
        del(&pool, &fleet_key).await;
    }

    #[tokio::test]
    #[ignore = "requires Redis"]
    async fn paired_success_increments_both_and_sets_ttl() {
        let Some(pool) = redis_pool().await else {
            panic!("local Redis not reachable");
        };
        let limiter = RedisRateLimiter::new(pool.clone());
        let tenant = unique_tenant();
        let keys = Keys::generate();
        let ip = unique_ip();
        let tenant_key = rate_limit_key(&tenant, &keys.public_key(), &LimitType::IpConnections);
        let fleet_key = ip_rate_limit_key(&ip);
        del(&pool, &tenant_key).await;
        del(&pool, &fleet_key).await;
        let outcome = limiter
            .check_paired_admission(request(&tenant, &keys.public_key(), &ip, 10, 20, 30))
            .await
            .expect("paired");
        match outcome {
            PairedAdmissionOutcome::Allowed { tenant, fleet } => {
                assert_eq!(tenant.current, 1);
                assert_eq!(fleet.current, 1);
                assert!(tenant.allowed && fleet.allowed);
            }
            other => panic!("expected allow, got {other:?}"),
        }
        assert_eq!(get_count(&pool, &tenant_key).await, 1);
        assert_eq!(get_count(&pool, &fleet_key).await, 1);
        assert_admitted_bounded_pttl(&pool, &tenant_key, &fleet_key, 30).await;
        let tttl = get_ttl(&pool, &tenant_key).await;
        let fttl = get_ttl(&pool, &fleet_key).await;
        assert!(tttl > 0 && tttl <= 30, "tenant ttl {tttl}");
        assert!(fttl > 0 && fttl <= 30, "fleet ttl {fttl}");
        let outcome = limiter
            .check_paired_admission(request(&tenant, &keys.public_key(), &ip, 10, 20, 30))
            .await
            .expect("second");
        match outcome {
            PairedAdmissionOutcome::Allowed { tenant, fleet } => {
                assert_eq!(tenant.current, 2);
                assert_eq!(fleet.current, 2);
            }
            other => panic!("expected second allow, got {other:?}"),
        }
        let tttl2 = get_ttl(&pool, &tenant_key).await;
        assert!(
            tttl2 <= tttl,
            "second admit must not reset the fixed window, before={tttl} after={tttl2}"
        );
        del(&pool, &tenant_key).await;
        del(&pool, &fleet_key).await;
    }

    #[tokio::test]
    #[ignore = "requires Redis"]
    async fn paired_concurrent_calls_cannot_partially_charge() {
        let Some(pool) = redis_pool().await else {
            panic!("local Redis not reachable");
        };
        let limiter = Arc::new(RedisRateLimiter::new(pool.clone()));
        let tenant = unique_tenant();
        let keys = Keys::generate();
        let ip = unique_ip();
        let tenant_key = rate_limit_key(&tenant, &keys.public_key(), &LimitType::IpConnections);
        let fleet_key = ip_rate_limit_key(&ip);
        del(&pool, &tenant_key).await;
        del(&pool, &fleet_key).await;
        let pubkey = keys.public_key();
        let community = tenant.community();
        let host = tenant.host().to_owned();
        let mut joins = Vec::new();
        for _ in 0..40 {
            let limiter = Arc::clone(&limiter);
            let host = host.clone();
            joins.push(tokio::spawn(async move {
                let tenant = TenantContext::resolved(community, &host);
                limiter
                    .check_paired_admission(request(&tenant, &pubkey, &ip, 8, 20, 30))
                    .await
            }));
        }
        let mut allowed = 0u64;
        for join in joins {
            if matches!(
                join.await.expect("join").expect("paired"),
                PairedAdmissionOutcome::Allowed { .. }
            ) {
                allowed += 1;
            }
        }
        assert_eq!(allowed, 8);
        assert_eq!(get_count(&pool, &tenant_key).await, 8);
        assert_eq!(get_count(&pool, &fleet_key).await, 8);
        assert_admitted_bounded_pttl(&pool, &tenant_key, &fleet_key, 30).await;
        del(&pool, &tenant_key).await;
        del(&pool, &fleet_key).await;
    }

    #[tokio::test]
    #[ignore = "requires Redis"]
    async fn paired_new_fleet_window_does_not_carry_tenant_leftover() {
        let Some(pool) = redis_pool().await else {
            panic!("local Redis not reachable");
        };
        let limiter = RedisRateLimiter::new(pool.clone());
        let tenant = unique_tenant();
        let keys = Keys::generate();
        let ip = unique_ip();
        let tenant_key = rate_limit_key(&tenant, &keys.public_key(), &LimitType::IpConnections);
        let fleet_key = ip_rate_limit_key(&ip);
        seed_count(&pool, &tenant_key, 2, 30).await;
        del(&pool, &fleet_key).await;
        let first = limiter
            .check_paired_admission(request(&tenant, &keys.public_key(), &ip, 3, 6, 30))
            .await
            .expect("paired");
        match first {
            PairedAdmissionOutcome::Allowed { tenant, fleet } => {
                assert_eq!(tenant.current, 1, "leftover tenant count must not carry");
                assert_eq!(fleet.current, 1);
            }
            other => panic!("expected allow in a new fleet window, got {other:?}"),
        }
        assert_eq!(get_count(&pool, &tenant_key).await, 1);
        assert_eq!(get_count(&pool, &fleet_key).await, 1);
        assert_admitted_bounded_pttl(&pool, &tenant_key, &fleet_key, 30).await;
        for expected in 2..=3 {
            let outcome = limiter
                .check_paired_admission(request(&tenant, &keys.public_key(), &ip, 3, 6, 30))
                .await
                .expect("paired");
            match outcome {
                PairedAdmissionOutcome::Allowed { tenant, fleet } => {
                    assert_eq!(tenant.current, expected);
                    assert_eq!(fleet.current, expected);
                }
                other => panic!("expected allow {expected}, got {other:?}"),
            }
        }
        let denied = limiter
            .check_paired_admission(request(&tenant, &keys.public_key(), &ip, 3, 6, 30))
            .await
            .expect("paired");
        assert!(
            matches!(denied, PairedAdmissionOutcome::TenantDenied(ref result) if !result.allowed),
            "got {denied:?}"
        );
        assert_eq!(get_count(&pool, &tenant_key).await, 3);
        assert_eq!(
            get_count(&pool, &fleet_key).await,
            3,
            "one tenant must not consume a leftover-plus-fresh share of the fleet"
        );
        del(&pool, &tenant_key).await;
        del(&pool, &fleet_key).await;
    }

    #[tokio::test]
    #[ignore = "requires Redis"]
    async fn paired_misaligned_tenant_ttl_cannot_open_a_second_share() {
        let Some(pool) = redis_pool().await else {
            panic!("local Redis not reachable");
        };
        let limiter = RedisRateLimiter::new(pool.clone());
        let tenant = unique_tenant();
        let keys = Keys::generate();
        let ip = unique_ip();
        let tenant_key = rate_limit_key(&tenant, &keys.public_key(), &LimitType::IpConnections);
        let fleet_key = ip_rate_limit_key(&ip);
        seed_count(&pool, &tenant_key, 2, 3).await;
        seed_count(&pool, &fleet_key, 2, 30).await;
        let allowed = limiter
            .check_paired_admission(request(&tenant, &keys.public_key(), &ip, 3, 6, 30))
            .await
            .expect("paired");
        match allowed {
            PairedAdmissionOutcome::Allowed { tenant, fleet } => {
                assert_eq!(tenant.current, 3);
                assert_eq!(fleet.current, 3);
                assert!(
                    tenant.reset_in_secs >= 20,
                    "tenant TTL must be pinned to the fleet window, reset={}",
                    tenant.reset_in_secs
                );
            }
            other => panic!("expected allow that aligns TTL, got {other:?}"),
        }
        let tpttl = get_pttl(&pool, &tenant_key).await;
        assert!(
            tpttl > 3_000,
            "misaligned short tenant TTL must be extended, {tpttl}"
        );
        assert_exact_shared_deadline(&pool, &tenant_key, &fleet_key).await;
        tokio::time::sleep(std::time::Duration::from_secs(4)).await;
        let denied = limiter
            .check_paired_admission(request(&tenant, &keys.public_key(), &ip, 3, 6, 30))
            .await
            .expect("paired");
        assert!(
            matches!(denied, PairedAdmissionOutcome::TenantDenied(ref result) if !result.allowed),
            "tenant must not reset inside the fleet window, got {denied:?}"
        );
        assert_eq!(get_count(&pool, &tenant_key).await, 3);
        assert_eq!(get_count(&pool, &fleet_key).await, 3);
        del(&pool, &tenant_key).await;
        del(&pool, &fleet_key).await;
    }

    #[tokio::test]
    #[ignore = "requires Redis"]
    async fn paired_misaligned_denials_align_tenant_expiry_without_charging() {
        let Some(pool) = redis_pool().await else {
            panic!("local Redis not reachable");
        };
        let limiter = RedisRateLimiter::new(pool.clone());
        let tenant = unique_tenant();
        let keys = Keys::generate();
        let ip = unique_ip();
        let tenant_key = rate_limit_key(&tenant, &keys.public_key(), &LimitType::IpConnections);
        let fleet_key = ip_rate_limit_key(&ip);
        seed_count(&pool, &tenant_key, 3, 5).await;
        seed_count(&pool, &fleet_key, 4, 30).await;
        let before_t = get_count(&pool, &tenant_key).await;
        let before_f = get_count(&pool, &fleet_key).await;
        let before_t_at = get_pexpiretime(&pool, &tenant_key).await;
        let before_f_at = get_pexpiretime(&pool, &fleet_key).await;
        let tenant_denied = limiter
            .check_paired_admission(request(&tenant, &keys.public_key(), &ip, 3, 20, 30))
            .await
            .expect("paired");
        assert!(
            matches!(
                tenant_denied,
                PairedAdmissionOutcome::TenantDenied(ref result) if !result.allowed
            ),
            "got {tenant_denied:?}"
        );
        assert_eq!(get_count(&pool, &tenant_key).await, before_t);
        assert_eq!(get_count(&pool, &fleet_key).await, before_f);
        assert!(
            before_t_at > 0 && before_t_at < before_f_at,
            "fixture must start with a shorter tenant expiry: tenant={before_t_at} fleet={before_f_at}"
        );
        let after_f_at = get_pexpiretime(&pool, &fleet_key).await;
        assert_absolute_deadline_unmoved("fleet", before_f_at, after_f_at);
        assert_exact_shared_deadline(&pool, &tenant_key, &fleet_key).await;

        del(&pool, &tenant_key).await;
        del(&pool, &fleet_key).await;
        seed_count(&pool, &tenant_key, 1, 30).await;
        seed_count(&pool, &fleet_key, 5, 8).await;
        let before_t = get_count(&pool, &tenant_key).await;
        let before_f = get_count(&pool, &fleet_key).await;
        let before_t_at = get_pexpiretime(&pool, &tenant_key).await;
        let before_f_at = get_pexpiretime(&pool, &fleet_key).await;
        let fleet_denied = limiter
            .check_paired_admission(request(&tenant, &keys.public_key(), &ip, 10, 5, 30))
            .await
            .expect("paired");
        assert!(
            matches!(
                fleet_denied,
                PairedAdmissionOutcome::FleetDenied(ref result) if !result.allowed
            ),
            "got {fleet_denied:?}"
        );
        assert_eq!(get_count(&pool, &tenant_key).await, before_t);
        assert_eq!(get_count(&pool, &fleet_key).await, before_f);
        assert!(
            before_t_at >= before_f_at && before_f_at > 0,
            "fixture must start with tenant covering or outliving fleet: tenant={before_t_at} fleet={before_f_at}"
        );
        let after_f_at = get_pexpiretime(&pool, &fleet_key).await;
        assert_absolute_deadline_unmoved("fleet", before_f_at, after_f_at);
        assert_exact_shared_deadline(&pool, &tenant_key, &fleet_key).await;
        del(&pool, &tenant_key).await;
        del(&pool, &fleet_key).await;
    }

    #[tokio::test]
    #[ignore = "requires Redis"]
    async fn paired_aligned_windows_reset_together() {
        let Some(pool) = redis_pool().await else {
            panic!("local Redis not reachable");
        };
        let limiter = RedisRateLimiter::new(pool.clone());
        let tenant = unique_tenant();
        let keys = Keys::generate();
        let ip = unique_ip();
        let tenant_key = rate_limit_key(&tenant, &keys.public_key(), &LimitType::IpConnections);
        let fleet_key = ip_rate_limit_key(&ip);
        del(&pool, &tenant_key).await;
        del(&pool, &fleet_key).await;
        let first = limiter
            .check_paired_admission(request(&tenant, &keys.public_key(), &ip, 3, 6, 2))
            .await
            .expect("paired");
        match first {
            PairedAdmissionOutcome::Allowed { tenant, fleet } => {
                assert_eq!(tenant.current, 1);
                assert_eq!(fleet.current, 1);
                assert!(tenant.reset_in_secs > 0 && tenant.reset_in_secs <= 2);
                assert_eq!(tenant.reset_in_secs, fleet.reset_in_secs);
            }
            other => panic!("expected first allow, got {other:?}"),
        }
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
        let second = limiter
            .check_paired_admission(request(&tenant, &keys.public_key(), &ip, 3, 6, 2))
            .await
            .expect("reset");
        match second {
            PairedAdmissionOutcome::Allowed { tenant, fleet } => {
                assert_eq!(
                    tenant.current, 1,
                    "both counters must reset with the fleet window"
                );
                assert_eq!(fleet.current, 1);
            }
            other => panic!("expected allow after shared reset, got {other:?}"),
        }
        assert_eq!(get_count(&pool, &tenant_key).await, 1);
        assert_eq!(get_count(&pool, &fleet_key).await, 1);
        del(&pool, &tenant_key).await;
        del(&pool, &fleet_key).await;
    }

    #[tokio::test]
    #[ignore = "requires Redis"]
    async fn paired_concurrent_misaligned_ttls_cannot_partially_charge() {
        let Some(pool) = redis_pool().await else {
            panic!("local Redis not reachable");
        };
        let limiter = Arc::new(RedisRateLimiter::new(pool.clone()));
        let tenant = unique_tenant();
        let keys = Keys::generate();
        let ip = unique_ip();
        let tenant_key = rate_limit_key(&tenant, &keys.public_key(), &LimitType::IpConnections);
        let fleet_key = ip_rate_limit_key(&ip);
        seed_count(&pool, &tenant_key, 1, 4).await;
        seed_count(&pool, &fleet_key, 1, 30).await;
        let pubkey = keys.public_key();
        let community = tenant.community();
        let host = tenant.host().to_owned();
        let mut joins = Vec::new();
        for _ in 0..40 {
            let limiter = Arc::clone(&limiter);
            let host = host.clone();
            joins.push(tokio::spawn(async move {
                let tenant = TenantContext::resolved(community, &host);
                limiter
                    .check_paired_admission(request(&tenant, &pubkey, &ip, 8, 20, 30))
                    .await
            }));
        }
        let mut allowed = 0u64;
        for join in joins {
            if matches!(
                join.await.expect("join").expect("paired"),
                PairedAdmissionOutcome::Allowed { .. }
            ) {
                allowed += 1;
            }
        }
        assert_eq!(
            allowed, 7,
            "seeded 1 plus 7 admits must fill the tenant share"
        );
        assert_eq!(get_count(&pool, &tenant_key).await, 8);
        assert_eq!(get_count(&pool, &fleet_key).await, 8);
        assert_admitted_bounded_pttl(&pool, &tenant_key, &fleet_key, 30).await;
        del(&pool, &tenant_key).await;
        del(&pool, &fleet_key).await;
    }

    #[tokio::test]
    #[ignore = "requires Redis"]
    async fn paired_fractional_fleet_pttl_keeps_tenant_from_expiring_first() {
        let Some(pool) = redis_pool().await else {
            panic!("local Redis not reachable");
        };
        let limiter = RedisRateLimiter::new(pool.clone());
        let tenant = unique_tenant();
        let keys = Keys::generate();
        let ip = unique_ip();
        let tenant_key = rate_limit_key(&tenant, &keys.public_key(), &LimitType::IpConnections);
        let fleet_key = ip_rate_limit_key(&ip);

        seed_count_px(&pool, &tenant_key, 1, 500).await;
        seed_count_px(&pool, &fleet_key, 1, 1_400).await;
        let live = limiter
            .check_paired_admission(request(&tenant, &keys.public_key(), &ip, 10, 20, 30))
            .await
            .expect("live fleet");
        let live_fpttl = get_pttl(&pool, &fleet_key).await;
        match live {
            PairedAdmissionOutcome::Allowed { tenant, fleet } => {
                assert_eq!(tenant.current, 2);
                assert_eq!(fleet.current, 2);
                let min_reset = (live_fpttl.max(0) as u64).div_ceil(1000);
                assert!(
                    tenant.reset_in_secs >= min_reset,
                    "reset {} understated remaining {live_fpttl}ms (ceil {min_reset}s)",
                    tenant.reset_in_secs
                );
                assert_eq!(tenant.reset_in_secs, fleet.reset_in_secs);
            }
            other => panic!("expected allow against a live fractional fleet, got {other:?}"),
        }
        assert_admitted_bounded_pttl(&pool, &tenant_key, &fleet_key, 30).await;

        del(&pool, &tenant_key).await;
        del(&pool, &fleet_key).await;
        let created = limiter
            .check_paired_admission(request(&tenant, &keys.public_key(), &ip, 10, 20, 2))
            .await
            .expect("new fleet window");
        match created {
            PairedAdmissionOutcome::Allowed { tenant, fleet } => {
                assert_eq!(tenant.current, 1);
                assert_eq!(fleet.current, 1);
                assert!(tenant.reset_in_secs > 0 && tenant.reset_in_secs <= 2);
                assert_eq!(tenant.reset_in_secs, fleet.reset_in_secs);
            }
            other => panic!("expected allow creating a new fleet window, got {other:?}"),
        }
        assert_admitted_bounded_pttl(&pool, &tenant_key, &fleet_key, 2).await;
        del(&pool, &tenant_key).await;
        del(&pool, &fleet_key).await;
    }

    #[tokio::test]
    #[ignore = "requires Redis"]
    async fn paired_denied_short_tenant_cannot_reopen_before_fleet() {
        let Some(pool) = redis_pool().await else {
            panic!("local Redis not reachable");
        };
        let limiter = RedisRateLimiter::new(pool.clone());
        let tenant = unique_tenant();
        let keys = Keys::generate();
        let ip = unique_ip();
        let tenant_key = rate_limit_key(&tenant, &keys.public_key(), &LimitType::IpConnections);
        let fleet_key = ip_rate_limit_key(&ip);
        seed_count_px(&pool, &tenant_key, 3, 400).await;
        seed_count_px(&pool, &fleet_key, 4, 2_000).await;
        let before_t = get_count(&pool, &tenant_key).await;
        let before_f = get_count(&pool, &fleet_key).await;
        let before_t_at = get_pexpiretime(&pool, &tenant_key).await;
        let before_f_at = get_pexpiretime(&pool, &fleet_key).await;
        assert!(
            before_t_at > 0 && before_t_at < before_f_at,
            "fixture must start shorter than the live fleet: tenant={before_t_at} fleet={before_f_at}"
        );
        let denied = limiter
            .check_paired_admission(request(&tenant, &keys.public_key(), &ip, 3, 20, 30))
            .await
            .expect("paired");
        assert!(
            matches!(denied, PairedAdmissionOutcome::TenantDenied(ref result) if !result.allowed),
            "got {denied:?}"
        );
        assert_eq!(get_count(&pool, &tenant_key).await, before_t);
        assert_eq!(get_count(&pool, &fleet_key).await, before_f);
        let aligned_f_at = get_pexpiretime(&pool, &fleet_key).await;
        assert_absolute_deadline_unmoved("fleet", before_f_at, aligned_f_at);
        assert_exact_shared_deadline(&pool, &tenant_key, &fleet_key).await;
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        let still_denied = limiter
            .check_paired_admission(request(&tenant, &keys.public_key(), &ip, 3, 20, 30))
            .await
            .expect("reopen");
        assert!(
            matches!(
                still_denied,
                PairedAdmissionOutcome::TenantDenied(ref result) if !result.allowed
            ),
            "tenant must not expire/reopen before the fleet, got {still_denied:?}"
        );
        assert_eq!(get_count(&pool, &tenant_key).await, before_t);
        assert_eq!(get_count(&pool, &fleet_key).await, before_f);
        assert_exact_shared_deadline(&pool, &tenant_key, &fleet_key).await;
        del(&pool, &tenant_key).await;
        del(&pool, &fleet_key).await;
    }

    #[tokio::test]
    #[ignore = "requires Redis"]
    async fn paired_fleet_expiry_during_lua_establishes_fresh_bounded_window() {
        let Some(pool) = redis_pool().await else {
            panic!("local Redis not reachable");
        };
        let tenant = unique_tenant();
        let keys = Keys::generate();
        let ip = unique_ip();
        let tenant_key = rate_limit_key(&tenant, &keys.public_key(), &LimitType::IpConnections);
        let fleet_key = ip_rate_limit_key(&ip);
        seed_count(&pool, &tenant_key, 2, 30).await;
        seed_count(&pool, &fleet_key, 5, 30).await;
        let outcome =
            run_paired_admission_injecting_fleet_expiry(&pool, &tenant_key, &fleet_key, 30, 10, 20)
                .await;
        match outcome {
            PairedAdmissionOutcome::Allowed { tenant, fleet } => {
                assert_eq!(
                    tenant.current, 1,
                    "crossed fleet boundary must reset tenant"
                );
                assert_eq!(fleet.current, 1, "crossed fleet boundary must reset fleet");
                assert!(tenant.allowed && fleet.allowed);
            }
            other => {
                panic!("expected fresh-window allow after in-script fleet expiry, got {other:?}")
            }
        }
        assert_eq!(get_count(&pool, &tenant_key).await, 1);
        assert_eq!(get_count(&pool, &fleet_key).await, 1);
        assert_admitted_bounded_pttl(&pool, &tenant_key, &fleet_key, 30).await;
        del(&pool, &tenant_key).await;
        del(&pool, &fleet_key).await;
    }

    #[tokio::test]
    #[ignore = "requires Redis"]
    async fn paired_fleet_expiry_after_live_at_establishes_fresh_bounded_window() {
        let Some(pool) = redis_pool().await else {
            panic!("local Redis not reachable");
        };
        let tenant = unique_tenant();
        let keys = Keys::generate();
        let ip = unique_ip();
        let tenant_key = rate_limit_key(&tenant, &keys.public_key(), &LimitType::IpConnections);
        let fleet_key = ip_rate_limit_key(&ip);
        seed_count(&pool, &tenant_key, 2, 30).await;
        seed_count(&pool, &fleet_key, 5, 30).await;
        let outcome = run_paired_admission_injecting_fleet_expiry_after_live_at(
            &pool,
            &tenant_key,
            &fleet_key,
            30,
            10,
            20,
        )
        .await;
        match outcome {
            PairedAdmissionOutcome::Allowed { tenant, fleet } => {
                assert_eq!(
                    tenant.current, 1,
                    "post-live_at fleet expiry must not keep the incremented tenant count"
                );
                assert_eq!(
                    fleet.current, 1,
                    "post-live_at fleet expiry must not keep a recreated fleet count"
                );
                assert!(tenant.allowed && fleet.allowed);
            }
            other => {
                panic!("expected fresh-window allow after post-live_at fleet expiry, got {other:?}")
            }
        }
        assert_eq!(get_count(&pool, &tenant_key).await, 1);
        assert_eq!(get_count(&pool, &fleet_key).await, 1);
        assert_ne!(get_pttl(&pool, &fleet_key).await, -1);
        assert_ne!(get_pttl(&pool, &tenant_key).await, -1);
        assert_admitted_bounded_pttl(&pool, &tenant_key, &fleet_key, 30).await;
        del(&pool, &tenant_key).await;
        del(&pool, &fleet_key).await;
    }

    #[tokio::test]
    #[ignore = "requires Redis"]
    async fn paired_negative_counters_reject_before_any_mutation() {
        let Some(pool) = redis_pool().await else {
            panic!("local Redis not reachable");
        };
        let limiter = RedisRateLimiter::new(pool.clone());
        let tenant = unique_tenant();
        let keys = Keys::generate();
        let ip = unique_ip();
        let tenant_key = rate_limit_key(&tenant, &keys.public_key(), &LimitType::IpConnections);
        let fleet_key = ip_rate_limit_key(&ip);

        seed_count(&pool, &tenant_key, -3, 30).await;
        seed_count(&pool, &fleet_key, 1, 30).await;
        let before_t = get_raw(&pool, &tenant_key).await;
        let before_f = get_raw(&pool, &fleet_key).await;
        let err = limiter
            .check_paired_admission(request(&tenant, &keys.public_key(), &ip, 10, 20, 30))
            .await
            .expect_err("negative tenant must fail closed");
        assert!(
            err.to_string().contains("corrupt"),
            "negative counters must fail closed, got {err}"
        );
        assert_eq!(get_raw(&pool, &tenant_key).await, before_t);
        assert_eq!(get_raw(&pool, &fleet_key).await, before_f);

        del(&pool, &tenant_key).await;
        del(&pool, &fleet_key).await;
        seed_count(&pool, &tenant_key, 1, 30).await;
        seed_count(&pool, &fleet_key, -5, 30).await;
        let before_t = get_raw(&pool, &tenant_key).await;
        let before_f = get_raw(&pool, &fleet_key).await;
        limiter
            .check_paired_admission(request(&tenant, &keys.public_key(), &ip, 10, 20, 30))
            .await
            .expect_err("negative fleet must fail closed");
        assert_eq!(get_raw(&pool, &tenant_key).await, before_t);
        assert_eq!(get_raw(&pool, &fleet_key).await, before_f);
        del(&pool, &tenant_key).await;
        del(&pool, &fleet_key).await;
    }

    #[tokio::test]
    #[ignore = "requires Redis"]
    async fn paired_non_integer_counters_leave_both_keys_unchanged() {
        let Some(pool) = redis_pool().await else {
            panic!("local Redis not reachable");
        };
        let limiter = RedisRateLimiter::new(pool.clone());
        let tenant = unique_tenant();
        let keys = Keys::generate();
        let ip = unique_ip();
        let tenant_key = rate_limit_key(&tenant, &keys.public_key(), &LimitType::IpConnections);
        let fleet_key = ip_rate_limit_key(&ip);

        seed_raw(&pool, &tenant_key, "1.2", Some(30)).await;
        seed_count(&pool, &fleet_key, 4, 30).await;
        let before_t = get_raw(&pool, &tenant_key).await;
        let before_f = get_raw(&pool, &fleet_key).await;
        let err = limiter
            .check_paired_admission(request(&tenant, &keys.public_key(), &ip, 10, 20, 30))
            .await
            .expect_err("non-integer tenant must fail closed");
        assert!(
            err.to_string().contains("corrupt"),
            "non-integer counters must fail closed, got {err}"
        );
        assert_eq!(get_raw(&pool, &tenant_key).await, before_t);
        assert_eq!(get_raw(&pool, &fleet_key).await, before_f);
        assert_eq!(get_count(&pool, &fleet_key).await, 4);

        del(&pool, &tenant_key).await;
        del(&pool, &fleet_key).await;
        seed_count(&pool, &tenant_key, 1, 30).await;
        seed_raw(&pool, &fleet_key, "1.2", Some(30)).await;
        let before_t = get_raw(&pool, &tenant_key).await;
        let before_f = get_raw(&pool, &fleet_key).await;
        limiter
            .check_paired_admission(request(&tenant, &keys.public_key(), &ip, 10, 20, 30))
            .await
            .expect_err("non-integer fleet must fail closed");
        assert_eq!(get_raw(&pool, &tenant_key).await, before_t);
        assert_eq!(get_raw(&pool, &fleet_key).await, before_f);
        assert_eq!(get_count(&pool, &tenant_key).await, 1);
        del(&pool, &tenant_key).await;
        del(&pool, &fleet_key).await;
    }

    #[tokio::test]
    #[ignore = "requires Redis"]
    async fn paired_persistent_fleet_preserves_count_repairs_ttl_and_denies_at_limit() {
        let Some(pool) = redis_pool().await else {
            panic!("local Redis not reachable");
        };
        let limiter = RedisRateLimiter::new(pool.clone());
        let tenant = unique_tenant();
        let keys = Keys::generate();
        let ip = unique_ip();
        let tenant_key = rate_limit_key(&tenant, &keys.public_key(), &LimitType::IpConnections);
        let fleet_key = ip_rate_limit_key(&ip);

        seed_count(&pool, &tenant_key, 1, 30).await;
        persist_count(&pool, &fleet_key, 5).await;
        assert_eq!(get_pttl(&pool, &fleet_key).await, -1);
        let outcome = limiter
            .check_paired_admission(request(&tenant, &keys.public_key(), &ip, 10, 5, 30))
            .await
            .expect("persistent fleet at limit");
        assert!(
            matches!(outcome, PairedAdmissionOutcome::FleetDenied(ref result) if !result.allowed),
            "PTTL -1 at limit must be ordinary denial, not a reset, got {outcome:?}"
        );
        assert_eq!(get_count(&pool, &tenant_key).await, 1);
        assert_eq!(get_count(&pool, &fleet_key).await, 5);
        let repaired = get_pttl(&pool, &fleet_key).await;
        assert!(
            repaired > 0 && repaired <= 30_050,
            "persistent fleet must receive a bounded expiry, pttl={repaired}"
        );
        assert_ne!(repaired, -1);
        assert_exact_shared_deadline(&pool, &tenant_key, &fleet_key).await;

        del(&pool, &tenant_key).await;
        del(&pool, &fleet_key).await;
        persist_count(&pool, &tenant_key, 2).await;
        persist_count(&pool, &fleet_key, 3).await;
        assert_eq!(get_pttl(&pool, &fleet_key).await, -1);
        let allowed = limiter
            .check_paired_admission(request(&tenant, &keys.public_key(), &ip, 10, 20, 30))
            .await
            .expect("persistent under limit");
        match allowed {
            PairedAdmissionOutcome::Allowed { tenant, fleet } => {
                assert_eq!(tenant.current, 3, "persistent usage must not reset to 1");
                assert_eq!(fleet.current, 4, "persistent usage must not reset to 1");
            }
            other => panic!("expected allow that preserves persistent count, got {other:?}"),
        }
        assert_eq!(get_count(&pool, &tenant_key).await, 3);
        assert_eq!(get_count(&pool, &fleet_key).await, 4);
        assert_admitted_bounded_pttl(&pool, &tenant_key, &fleet_key, 30).await;
        del(&pool, &tenant_key).await;
        del(&pool, &fleet_key).await;
    }

    #[tokio::test]
    #[ignore = "requires Redis"]
    async fn paired_overflow_and_limit_deny_without_partial_charge() {
        let Some(pool) = redis_pool().await else {
            panic!("local Redis not reachable");
        };
        let limiter = RedisRateLimiter::new(pool.clone());
        let tenant = unique_tenant();
        let keys = Keys::generate();
        let ip = unique_ip();
        let tenant_key = rate_limit_key(&tenant, &keys.public_key(), &LimitType::IpConnections);
        let fleet_key = ip_rate_limit_key(&ip);

        seed_count(&pool, &tenant_key, 10, 30).await;
        seed_count(&pool, &fleet_key, 4, 30).await;
        let before_t = get_count(&pool, &tenant_key).await;
        let before_f = get_count(&pool, &fleet_key).await;
        let denied = limiter
            .check_paired_admission(request(&tenant, &keys.public_key(), &ip, 10, 20, 30))
            .await
            .expect("at-limit tenant");
        assert!(
            matches!(denied, PairedAdmissionOutcome::TenantDenied(ref result) if !result.allowed),
            "got {denied:?}"
        );
        assert_eq!(get_count(&pool, &tenant_key).await, before_t);
        assert_eq!(get_count(&pool, &fleet_key).await, before_f);

        del(&pool, &tenant_key).await;
        del(&pool, &fleet_key).await;
        seed_raw(&pool, &tenant_key, "9223372036854775807", Some(30)).await;
        seed_count(&pool, &fleet_key, 1, 30).await;
        let before_t = get_raw(&pool, &tenant_key).await;
        let before_f = get_raw(&pool, &fleet_key).await;
        let overflow = limiter
            .check_paired_admission(request(&tenant, &keys.public_key(), &ip, u64::MAX, 20, 30))
            .await;
        match overflow {
            Ok(PairedAdmissionOutcome::TenantDenied(result)) => {
                assert!(!result.allowed);
            }
            Err(error) => {
                assert!(
                    error.to_string().contains("corrupt"),
                    "overflow that cannot INCR must fail closed, got {error}"
                );
            }
            other => panic!("overflow must not charge, got {other:?}"),
        }
        assert_eq!(get_raw(&pool, &tenant_key).await, before_t);
        assert_eq!(get_raw(&pool, &fleet_key).await, before_f);
        del(&pool, &tenant_key).await;
        del(&pool, &fleet_key).await;
    }

    #[tokio::test]
    #[ignore = "requires Redis"]
    async fn paired_admitted_keys_share_one_absolute_deadline() {
        let Some(pool) = redis_pool().await else {
            panic!("local Redis not reachable");
        };
        let limiter = RedisRateLimiter::new(pool.clone());
        let tenant = unique_tenant();
        let keys = Keys::generate();
        let ip = unique_ip();
        let tenant_key = rate_limit_key(&tenant, &keys.public_key(), &LimitType::IpConnections);
        let fleet_key = ip_rate_limit_key(&ip);
        del(&pool, &tenant_key).await;
        del(&pool, &fleet_key).await;
        limiter
            .check_paired_admission(request(&tenant, &keys.public_key(), &ip, 10, 20, 30))
            .await
            .expect("paired");
        assert_exact_shared_deadline(&pool, &tenant_key, &fleet_key).await;
        del(&pool, &tenant_key).await;
        del(&pool, &fleet_key).await;
    }

    #[tokio::test]
    #[ignore = "requires Redis"]
    async fn paired_tenant_tail_cannot_extend_into_a_new_fleet_window() {
        let Some(pool) = redis_pool().await else {
            panic!("local Redis not reachable");
        };
        let limiter = RedisRateLimiter::new(pool.clone());
        let tenant_a = unique_tenant();
        let tenant_b = unique_tenant();
        let keys_a = Keys::generate();
        let keys_b = Keys::generate();
        let ip = unique_ip();
        let tenant_key_a =
            rate_limit_key(&tenant_a, &keys_a.public_key(), &LimitType::IpConnections);
        let tenant_key_b =
            rate_limit_key(&tenant_b, &keys_b.public_key(), &LimitType::IpConnections);
        let fleet_key = ip_rate_limit_key(&ip);
        del(&pool, &tenant_key_a).await;
        del(&pool, &tenant_key_b).await;
        del(&pool, &fleet_key).await;
        for expected in 1..=3 {
            let outcome = limiter
                .check_paired_admission(request(&tenant_a, &keys_a.public_key(), &ip, 3, 6, 2))
                .await
                .expect("A fills the window");
            match outcome {
                PairedAdmissionOutcome::Allowed { tenant, fleet } => {
                    assert_eq!(tenant.current, expected);
                    assert_eq!(fleet.current, expected);
                }
                other => panic!("expected A allow {expected}, got {other:?}"),
            }
        }
        assert_exact_shared_deadline(&pool, &tenant_key_a, &fleet_key).await;
        let denied = limiter
            .check_paired_admission(request(&tenant_a, &keys_a.public_key(), &ip, 3, 6, 2))
            .await
            .expect("A capped");
        assert!(
            matches!(denied, PairedAdmissionOutcome::TenantDenied(ref result) if !result.allowed),
            "got {denied:?}"
        );
        assert_exact_shared_deadline(&pool, &tenant_key_a, &fleet_key).await;
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
        assert!(
            get_pttl(&pool, &fleet_key).await <= 0,
            "shared deadline must expire the fleet key"
        );
        assert!(
            get_pttl(&pool, &tenant_key_a).await <= 0,
            "A must not keep a +1ms tail after fleet expiry"
        );
        let opened = limiter
            .check_paired_admission(request(&tenant_b, &keys_b.public_key(), &ip, 3, 6, 2))
            .await
            .expect("B opens");
        match opened {
            PairedAdmissionOutcome::Allowed { tenant, fleet } => {
                assert_eq!(tenant.current, 1);
                assert_eq!(fleet.current, 1);
            }
            other => panic!("B must open a fresh fleet window, got {other:?}"),
        }
        let retried = limiter
            .check_paired_admission(request(&tenant_a, &keys_a.public_key(), &ip, 3, 6, 2))
            .await
            .expect("A retries");
        match retried {
            PairedAdmissionOutcome::Allowed { tenant, fleet } => {
                assert_eq!(
                    tenant.current, 1,
                    "A must not carry a leftover tail into B's new window"
                );
                assert_eq!(fleet.current, 2);
            }
            other => panic!("A must start a fresh share after B opened the window, got {other:?}"),
        }
        assert_eq!(get_count(&pool, &tenant_key_a).await, 1);
        assert_eq!(get_count(&pool, &tenant_key_b).await, 1);
        assert_eq!(get_count(&pool, &fleet_key).await, 2);
        del(&pool, &tenant_key_a).await;
        del(&pool, &tenant_key_b).await;
        del(&pool, &fleet_key).await;
    }

    #[tokio::test]
    #[ignore = "requires Redis"]
    async fn paired_leading_zero_fleet_does_not_partially_mutate_missing_tenant() {
        let Some(pool) = redis_pool().await else {
            panic!("local Redis not reachable");
        };
        let limiter = RedisRateLimiter::new(pool.clone());
        let tenant = unique_tenant();
        let keys = Keys::generate();
        let ip = unique_ip();
        let tenant_key = rate_limit_key(&tenant, &keys.public_key(), &LimitType::IpConnections);
        let fleet_key = ip_rate_limit_key(&ip);
        del(&pool, &tenant_key).await;
        seed_raw(&pool, &fleet_key, "0001", Some(30)).await;
        let before_t_raw = get_raw(&pool, &tenant_key).await;
        let before_t_pttl = get_pttl(&pool, &tenant_key).await;
        let before_t_at = get_pexpiretime(&pool, &tenant_key).await;
        let before_f_raw = get_raw(&pool, &fleet_key).await;
        let before_f_at = get_pexpiretime(&pool, &fleet_key).await;
        assert_eq!(before_t_raw, None);
        assert_eq!(before_t_pttl, -2);
        assert_eq!(before_t_at, -2);
        assert_eq!(before_f_raw.as_deref(), Some("0001"));
        assert!(
            before_f_at > 0,
            "fleet fixture must be live, at={before_f_at}"
        );

        let err = limiter
            .check_paired_admission(request(&tenant, &keys.public_key(), &ip, 10, 20, 30))
            .await
            .expect_err("leading-zero fleet must fail closed before INCR");
        assert!(
            err.to_string().contains("corrupt"),
            "leading-zero counters must fail closed, got {err}"
        );

        assert_eq!(get_raw(&pool, &tenant_key).await, before_t_raw);
        assert_eq!(get_pttl(&pool, &tenant_key).await, before_t_pttl);
        assert_eq!(get_pexpiretime(&pool, &tenant_key).await, before_t_at);
        assert_eq!(get_raw(&pool, &fleet_key).await, before_f_raw);
        assert_eq!(
            get_pexpiretime(&pool, &fleet_key).await,
            before_f_at,
            "fleet expiry must be unchanged and bytes must not be canonicalized"
        );
        del(&pool, &tenant_key).await;
        del(&pool, &fleet_key).await;
    }

    #[tokio::test]
    #[ignore = "requires Redis"]
    async fn paired_upgrade_state_denial_clamps_tenant_to_exact_fleet_deadline() {
        let Some(pool) = redis_pool().await else {
            panic!("local Redis not reachable");
        };
        let limiter = RedisRateLimiter::new(pool.clone());
        let tenant_a = unique_tenant();
        let tenant_b = unique_tenant();
        let keys_a = Keys::generate();
        let keys_b = Keys::generate();
        let ip = unique_ip();
        let tenant_key_a =
            rate_limit_key(&tenant_a, &keys_a.public_key(), &LimitType::IpConnections);
        let tenant_key_b =
            rate_limit_key(&tenant_b, &keys_b.public_key(), &LimitType::IpConnections);
        let fleet_key = ip_rate_limit_key(&ip);
        del(&pool, &tenant_key_a).await;
        del(&pool, &tenant_key_b).await;
        del(&pool, &fleet_key).await;

        seed_count_px(&pool, &fleet_key, 4, 1_500).await;
        let fleet_at = get_pexpiretime(&pool, &fleet_key).await;
        assert!(fleet_at > 0, "live fleet must have an absolute expiry");
        seed_count_pxat(&pool, &tenant_key_a, 3, fleet_at + 1).await;
        assert_eq!(
            get_pexpiretime(&pool, &tenant_key_a).await,
            fleet_at + 1,
            "fixture must seed the pre-upgrade +1ms tenant tail"
        );
        let before_t = get_count(&pool, &tenant_key_a).await;
        let before_f = get_count(&pool, &fleet_key).await;

        let denied = limiter
            .check_paired_admission(request(&tenant_a, &keys_a.public_key(), &ip, 3, 20, 30))
            .await
            .expect("capped tenant");
        assert!(
            matches!(denied, PairedAdmissionOutcome::TenantDenied(ref result) if !result.allowed),
            "got {denied:?}"
        );
        assert_eq!(get_count(&pool, &tenant_key_a).await, before_t);
        assert_eq!(get_count(&pool, &fleet_key).await, before_f);
        let after_f_at = get_pexpiretime(&pool, &fleet_key).await;
        assert_absolute_deadline_unmoved("fleet", fleet_at, after_f_at);
        assert_exact_shared_deadline(&pool, &tenant_key_a, &fleet_key).await;

        let wait_ms = get_pttl(&pool, &fleet_key).await.max(0) as u64 + 100;
        tokio::time::sleep(std::time::Duration::from_millis(wait_ms)).await;
        assert!(
            get_pttl(&pool, &fleet_key).await <= 0,
            "shared fleet deadline must have passed"
        );
        assert!(
            get_pttl(&pool, &tenant_key_a).await <= 0,
            "clamped tenant A must expire with the fleet, not the +1ms tail"
        );

        let opened = limiter
            .check_paired_admission(request(&tenant_b, &keys_b.public_key(), &ip, 3, 20, 30))
            .await
            .expect("B opens");
        match opened {
            PairedAdmissionOutcome::Allowed { tenant, fleet } => {
                assert_eq!(tenant.current, 1);
                assert_eq!(fleet.current, 1);
            }
            other => panic!("B must open a fresh fleet window, got {other:?}"),
        }
        let retried = limiter
            .check_paired_admission(request(&tenant_a, &keys_a.public_key(), &ip, 3, 20, 30))
            .await
            .expect("A retries");
        match retried {
            PairedAdmissionOutcome::Allowed { tenant, fleet } => {
                assert_eq!(
                    tenant.current, 1,
                    "A must retry at count 1 rather than carrying stale capped state"
                );
                assert_eq!(fleet.current, 2);
            }
            other => panic!("A must start a fresh share after the fleet boundary, got {other:?}"),
        }
        assert_eq!(get_count(&pool, &tenant_key_a).await, 1);
        assert_eq!(get_count(&pool, &tenant_key_b).await, 1);
        assert_eq!(get_count(&pool, &fleet_key).await, 2);
        del(&pool, &tenant_key_a).await;
        del(&pool, &tenant_key_b).await;
        del(&pool, &fleet_key).await;
    }

    #[tokio::test]
    #[ignore = "requires Redis"]
    async fn paired_aligned_denial_preserves_exact_pexpiretime_and_counters() {
        let Some(pool) = redis_pool().await else {
            panic!("local Redis not reachable");
        };
        let limiter = RedisRateLimiter::new(pool.clone());
        let tenant = unique_tenant();
        let keys = Keys::generate();
        let ip = unique_ip();
        let tenant_key = rate_limit_key(&tenant, &keys.public_key(), &LimitType::IpConnections);
        let fleet_key = ip_rate_limit_key(&ip);
        del(&pool, &tenant_key).await;
        del(&pool, &fleet_key).await;
        seed_count(&pool, &fleet_key, 4, 30).await;
        let fleet_at = get_pexpiretime(&pool, &fleet_key).await;
        seed_count_pxat(&pool, &tenant_key, 2, fleet_at).await;
        assert_eq!(get_pexpiretime(&pool, &tenant_key).await, fleet_at);
        let before_t = get_count(&pool, &tenant_key).await;
        let before_f = get_count(&pool, &fleet_key).await;
        let marker_key = format!("paired-aligned-denial-monitor:{}", Uuid::new_v4());
        let start_marker = format!("start:{}", Uuid::new_v4());
        let end_marker = format!("end:{}", Uuid::new_v4());
        let quoted_tenant = format!("\"{tenant_key}\"");
        let quoted_marker = format!("\"{marker_key}\"");
        let quoted_start = format!("\"{start_marker}\"");
        let quoted_end = format!("\"{end_marker}\"");
        let url = std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".into());
        let client = match redis::Client::open(url) {
            Ok(client) => client,
            Err(_) => panic!("monitor client failed"),
        };
        let monitor = match tokio::time::timeout(
            std::time::Duration::from_secs(5),
            client.get_async_monitor(),
        )
        .await
        {
            Ok(Ok(monitor)) => monitor,
            Ok(Err(_)) => panic!("monitor unavailable"),
            Err(_) => panic!("monitor timed out"),
        };
        let messages = monitor.into_on_message::<String>();
        futures_util::pin_mut!(messages);
        {
            let mut conn = pool.get().await.expect("redis conn");
            let _: () = redis::cmd("SET")
                .arg(&marker_key)
                .arg(&start_marker)
                .arg("EX")
                .arg(30)
                .query_async(&mut *conn)
                .await
                .expect("start marker");
        }
        let denied = limiter
            .check_paired_admission(request(&tenant, &keys.public_key(), &ip, 2, 20, 30))
            .await
            .expect("aligned tenant cap");
        {
            let mut conn = pool.get().await.expect("redis conn");
            let _: () = redis::cmd("SET")
                .arg(&marker_key)
                .arg(&end_marker)
                .arg("EX")
                .arg(30)
                .query_async(&mut *conn)
                .await
                .expect("end marker");
        }
        let capture = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            let mut started = false;
            let mut ended = false;
            let mut lua_get_tenant: u32 = 0;
            let mut lua_pexpireat_tenant: u32 = 0;
            while let Some(line) = messages.next().await {
                if !started {
                    if line.contains("\"SET\"")
                        && line.contains(&quoted_marker)
                        && line.contains(&quoted_start)
                    {
                        started = true;
                    }
                    continue;
                }
                if line.contains("\"SET\"")
                    && line.contains(&quoted_marker)
                    && line.contains(&quoted_end)
                {
                    ended = true;
                    break;
                }
                let lua_source = line
                    .split_once('[')
                    .and_then(|(_, rest)| rest.split_once(']'))
                    .map(|(source, _)| {
                        let mut fields = source.split_whitespace();
                        let Some(_db) = fields.next() else {
                            return false;
                        };
                        matches!(fields.next(), Some("lua"))
                    })
                    .unwrap_or(false);
                if !lua_source {
                    continue;
                }
                if !line.contains(&quoted_tenant) {
                    continue;
                }
                if line.contains("\"GET\"") {
                    lua_get_tenant = lua_get_tenant.saturating_add(1);
                }
                if line.contains("\"PEXPIREAT\"") {
                    lua_pexpireat_tenant = lua_pexpireat_tenant.saturating_add(1);
                }
            }
            (started, ended, lua_get_tenant, lua_pexpireat_tenant)
        })
        .await;
        let (started, ended, lua_get_tenant, lua_pexpireat_tenant) = match capture {
            Ok(counts) => counts,
            Err(_) => panic!("aligned paired denial monitor capture timed out"),
        };
        assert!(
            started,
            "aligned paired denial monitor missed the start marker"
        );
        assert!(ended, "aligned paired denial monitor missed the end marker");
        assert!(
            lua_get_tenant >= 1,
            "aligned paired denial monitor captured no lua GET of the aligned tenant key"
        );
        assert_eq!(
            lua_pexpireat_tenant, 0,
            "aligned paired denial must not issue lua PEXPIREAT for an already-aligned tenant key"
        );
        assert!(
            matches!(
                denied,
                PairedAdmissionOutcome::TenantDenied(ref result) if !result.allowed
            ),
            "got {denied:?}"
        );
        assert_eq!(get_count(&pool, &tenant_key).await, before_t);
        assert_eq!(get_count(&pool, &fleet_key).await, before_f);
        assert_eq!(get_pexpiretime(&pool, &tenant_key).await, fleet_at);
        assert_eq!(get_pexpiretime(&pool, &fleet_key).await, fleet_at);

        seed_count_pxat(&pool, &tenant_key, 2, fleet_at + 1).await;
        assert_eq!(
            get_pexpiretime(&pool, &tenant_key).await,
            fleet_at + 1,
            "fixture must seed a misaligned tenant deadline"
        );
        let before_t = get_count(&pool, &tenant_key).await;
        let before_f = get_count(&pool, &fleet_key).await;
        let misaligned = limiter
            .check_paired_admission(request(&tenant, &keys.public_key(), &ip, 2, 20, 30))
            .await
            .expect("misaligned tenant cap");
        assert!(
            matches!(
                misaligned,
                PairedAdmissionOutcome::TenantDenied(ref result) if !result.allowed
            ),
            "got {misaligned:?}"
        );
        assert_eq!(get_count(&pool, &tenant_key).await, before_t);
        assert_eq!(get_count(&pool, &fleet_key).await, before_f);
        assert_absolute_deadline_unmoved(
            "fleet",
            fleet_at,
            get_pexpiretime(&pool, &fleet_key).await,
        );
        assert_eq!(get_pexpiretime(&pool, &tenant_key).await, fleet_at);
        del(&pool, &tenant_key).await;
        del(&pool, &fleet_key).await;
        del(&pool, &marker_key).await;
    }

    #[test]
    fn paired_request_constructor_rejects_zero_and_shares_one_window() {
        assert!(NonZeroU64::new(0).is_none());
        let tenant = unique_tenant();
        let keys = Keys::generate();
        let ip = unique_ip();
        let window = NonZeroU64::new(60).expect("live window");
        let pubkey = keys.public_key();
        let request = PairedAdmissionRequest::new(
            &tenant,
            &pubkey,
            LimitType::IpConnections,
            window,
            600,
            &ip,
            1_200,
        );
        assert_eq!(request.window_secs(), 60);
        assert_eq!(request.window_secs(), window.get());
    }

    fn hrequest<'a>(
        tenant: &'a TenantContext,
        identity: &'a nostr::PublicKey,
        community: &'a nostr::PublicKey,
        fleet_ip: &'a IpAddr,
        limits: HierarchicalAdmissionLimits,
        window: u64,
    ) -> HierarchicalAdmissionRequest<'a> {
        HierarchicalAdmissionRequest::new(
            tenant,
            identity,
            community,
            LimitType::KeyedHttpAttempts,
            NonZeroU64::new(window).expect("test window is nonzero"),
            limits,
            fleet_ip,
        )
    }

    fn peek_request<'a>(
        tenant: &'a TenantContext,
        identity: &'a nostr::PublicKey,
        fleet_ip: &'a IpAddr,
        identity_limit: u64,
    ) -> HierarchicalIdentityDenialPeekRequest<'a> {
        HierarchicalIdentityDenialPeekRequest::new(
            tenant,
            identity,
            LimitType::KeyedHttpAttempts,
            NonZeroU64::new(identity_limit).expect("test identity limit is nonzero"),
            fleet_ip,
        )
    }

    async fn get_type(pool: &deadpool_redis::Pool, key: &str) -> String {
        let mut conn = pool.get().await.expect("redis conn");
        redis::cmd("TYPE")
            .arg(key)
            .query_async(&mut *conn)
            .await
            .expect("type")
    }

    async fn exists(pool: &deadpool_redis::Pool, key: &str) -> bool {
        let mut conn = pool.get().await.expect("redis conn");
        let n: i64 = redis::cmd("EXISTS")
            .arg(key)
            .query_async(&mut *conn)
            .await
            .expect("exists");
        n > 0
    }

    async fn assert_exact_shared_deadline_3(
        pool: &deadpool_redis::Pool,
        identity_key: &str,
        community_key: &str,
        fleet_key: &str,
    ) {
        let identity_at = get_pexpiretime(pool, identity_key).await;
        let community_at = get_pexpiretime(pool, community_key).await;
        let fleet_at = get_pexpiretime(pool, fleet_key).await;
        assert!(
            identity_at > 0 && community_at > 0 && fleet_at > 0,
            "admitted keys must keep a positive absolute expiry: identity={identity_at} community={community_at} fleet={fleet_at}"
        );
        assert_eq!(
            identity_at, community_at,
            "identity and community must share one exact absolute deadline"
        );
        assert_eq!(
            community_at, fleet_at,
            "community and fleet must share one exact absolute deadline"
        );
    }

    async fn assert_identity_missing(pool: &deadpool_redis::Pool, identity_key: &str) {
        assert_eq!(get_raw(pool, identity_key).await, None);
        assert_eq!(get_pttl(pool, identity_key).await, -2);
        assert_eq!(get_pexpiretime(pool, identity_key).await, -2);
        assert!(!exists(pool, identity_key).await);
    }

    #[test]
    fn hierarchical_admission_requires_distinct_keys_and_a_shared_window() {
        assert!(require_hierarchical_contract("i", "c", "f", 60).is_ok());
        let err = require_hierarchical_contract("same", "same", "f", 60)
            .expect_err("aliased identity/community");
        assert_eq!(err.class().as_str(), "contract");
        let text = err.to_string();
        assert!(
            text.contains("shared identity/community/fleet window"),
            "aliased keys must fail closed, got {text}"
        );
        let err =
            require_hierarchical_contract("i", "c", "c", 60).expect_err("aliased community/fleet");
        assert_eq!(err.class().as_str(), "contract");
        let err = require_hierarchical_contract("i", "c", "f", 0).expect_err("zero window");
        assert_eq!(err.class().as_str(), "contract");
    }

    #[test]
    fn hierarchical_corrupt_script_code_fails_closed_without_an_outcome() {
        let err = hierarchical_outcome_from_script_row(vec![5, 0, 10, 0, 0, 20, 0, 0, 30, 0])
            .expect_err("code 5 is corrupt");
        assert_eq!(err.class().as_str(), "counter_corrupt");
        assert!(
            err.to_string().contains("corrupt"),
            "corrupt counters must fail closed, got {err}"
        );
        let err = hierarchical_outcome_from_script_row(vec![0, 1, 10, 1])
            .expect_err("short row is contract");
        assert_eq!(err.class().as_str(), "contract");
        assert!(
            err.to_string().contains("unexpected result"),
            "unexpected shape must fail closed, got {err}"
        );
        let err = hierarchical_outcome_from_script_row(vec![9, 0, 10, 0, 0, 20, 0, 0, 30, 0])
            .expect_err("unknown code");
        assert_eq!(err.class().as_str(), "contract");
        assert!(
            err.to_string().contains("unknown code"),
            "unknown code must fail closed, got {err}"
        );
        let err = hierarchical_outcome_from_script_row(vec![4, 0, 10, 0, 0, 20, 0, 0, 30, 0])
            .expect_err("code 4 is contract");
        assert_eq!(err.class().as_str(), "contract");
        assert!(
            err.to_string()
                .contains("shared identity/community/fleet window"),
            "window/alias contract must fail closed, got {err}"
        );
    }

    #[test]
    fn hierarchical_identity_peek_rejects_zero_or_aliased_contract_without_redis() {
        assert!(require_identity_denial_peek_contract("i", "f", 3).is_ok());
        let err =
            require_identity_denial_peek_contract("i", "f", 0).expect_err("zero identity limit");
        assert_eq!(err.class().as_str(), "contract");
        let text = err.to_string();
        assert!(
            text.contains("nonzero identity limit"),
            "zero identity limit must fail closed without Redis, got {text}"
        );
        let err = require_identity_denial_peek_contract("same", "same", 3)
            .expect_err("aliased identity/fleet");
        assert_eq!(err.class().as_str(), "contract");
        let err = require_identity_denial_peek_contract("i", "f", u64::MAX)
            .expect_err("identity limit that cannot be a Redis-INCR integer");
        assert_eq!(err.class().as_str(), "contract");
        assert!(NonZeroU64::new(0).is_none());
    }

    #[test]
    fn hierarchical_identity_peek_unknown_or_short_row_fails_closed() {
        assert_eq!(
            identity_denial_peek_from_script_row(vec![0, 0, 10, 0]).expect("fallthrough"),
            HierarchicalIdentityDenialPeekOutcome::NotDenied
        );
        match identity_denial_peek_from_script_row(vec![1, 5, 5, 12]).expect("denied") {
            HierarchicalIdentityDenialPeekOutcome::Denied(result) => {
                assert!(!result.allowed);
                assert_eq!(result.current, 5);
                assert_eq!(result.limit, 5);
                assert_eq!(result.reset_in_secs, 12);
            }
            other => panic!("code 1 must be a proven denial, got {other:?}"),
        }
        let err =
            identity_denial_peek_from_script_row(vec![1, 5, 5]).expect_err("short row is contract");
        assert_eq!(err.class().as_str(), "contract");
        assert!(
            err.to_string().contains("unexpected result"),
            "unexpected shape must fail closed, got {err}"
        );
        let err =
            identity_denial_peek_from_script_row(vec![9, 0, 10, 0]).expect_err("unknown code");
        assert_eq!(err.class().as_str(), "contract");
        assert!(
            err.to_string().contains("unknown code"),
            "unknown code must fail closed, got {err}"
        );
        let err =
            identity_denial_peek_from_script_row(vec![2, 0, 0, 0]).expect_err("code 2 is contract");
        assert_eq!(err.class().as_str(), "contract");
        assert!(
            err.to_string().contains("nonzero identity limit"),
            "peek contract code must fail closed, got {err}"
        );
    }

    #[test]
    fn hierarchical_local_contract_and_corrupt_branches_retain_typed_class() {
        let contract = require_hierarchical_contract("same", "same", "f", 60)
            .expect_err("aliased keys are contract");
        assert_eq!(contract.class().as_str(), "contract");
        let corrupt = hierarchical_outcome_from_script_row(vec![5, 0, 10, 0, 0, 20, 0, 0, 30, 0])
            .expect_err("code 5 is corrupt");
        assert_eq!(corrupt.class().as_str(), "counter_corrupt");
        let peek_contract = require_identity_denial_peek_contract("same", "same", 3)
            .expect_err("aliased peek keys are contract");
        assert_eq!(peek_contract.class().as_str(), "contract");
        let peek_unknown_code = identity_denial_peek_from_script_row(vec![9, 0, 10, 0])
            .expect_err("unknown peek code is contract");
        assert_eq!(peek_unknown_code.class().as_str(), "contract");
        assert_ne!(corrupt.class().as_str(), contract.class().as_str());
    }

    #[test]
    fn hierarchical_script_failures_are_terminal_and_not_an_internal_retry_signal() {
        let corrupt = hierarchical_outcome_from_script_row(vec![5, 0, 10, 0, 0, 20, 0, 0, 30, 0])
            .expect_err("corrupt is a known pre-mutation rejection");
        assert_eq!(corrupt.class(), KeyedAdmissionErrorClass::CounterCorrupt);
        let contract = hierarchical_outcome_from_script_row(vec![4, 0, 10, 0, 0, 20, 0, 0, 30, 0])
            .expect_err("contract failure is terminal");
        assert_eq!(contract.class(), KeyedAdmissionErrorClass::Contract);
        let unknown = hierarchical_outcome_from_script_row(vec![9, 0, 10, 0, 0, 20, 0, 0, 30, 0])
            .expect_err("unknown code is terminal");
        assert_eq!(unknown.class(), KeyedAdmissionErrorClass::Contract);
        let allowed = hierarchical_outcome_from_script_row(vec![0, 1, 10, 1, 1, 20, 1, 1, 30, 1])
            .expect("allow");
        match allowed {
            HierarchicalAdmissionOutcome::Allowed {
                identity,
                community,
                fleet,
            } => {
                assert_eq!(identity.current, 1);
                assert_eq!(community.current, 1);
                assert_eq!(fleet.current, 1);
            }
            other => panic!("expected all-three allow, got {other:?}"),
        }
        let identity = hierarchical_outcome_from_script_row(vec![1, 11, 10, 1, 0, 20, 0, 0, 30, 0])
            .expect("identity deny");
        assert!(matches!(
            identity,
            HierarchicalAdmissionOutcome::IdentityDenied(ref result) if !result.allowed
        ));
        let community =
            hierarchical_outcome_from_script_row(vec![2, 0, 10, 0, 21, 20, 1, 0, 30, 0])
                .expect("community deny");
        assert!(matches!(
            community,
            HierarchicalAdmissionOutcome::CommunityDenied(ref result) if !result.allowed
        ));
        let fleet = hierarchical_outcome_from_script_row(vec![3, 0, 10, 0, 0, 20, 0, 31, 30, 1])
            .expect("fleet deny");
        assert!(matches!(
            fleet,
            HierarchicalAdmissionOutcome::FleetDenied(ref result) if !result.allowed
        ));
    }

    #[tokio::test]
    #[ignore = "requires Redis"]
    async fn hierarchical_success_increments_all_three_and_shares_deadline() {
        let Some(pool) = redis_pool().await else {
            panic!("local Redis not reachable");
        };
        let limiter = RedisRateLimiter::new(pool.clone());
        let tenant = unique_tenant();
        let identity = Keys::generate();
        let community = Keys::generate();
        let ip = unique_ip();
        let identity_key = rate_limit_key(
            &tenant,
            &identity.public_key(),
            &LimitType::KeyedHttpAttempts,
        );
        let community_key = rate_limit_key(
            &tenant,
            &community.public_key(),
            &LimitType::KeyedHttpAttempts,
        );
        let fleet_key = ip_rate_limit_key(&ip);
        del(&pool, &identity_key).await;
        del(&pool, &community_key).await;
        del(&pool, &fleet_key).await;
        let outcome = limiter
            .check_hierarchical_admission(hrequest(
                &tenant,
                &identity.public_key(),
                &community.public_key(),
                &ip,
                HierarchicalAdmissionLimits::new(3, 6, 10),
                30,
            ))
            .await
            .expect("hierarchical");
        match outcome {
            HierarchicalAdmissionOutcome::Allowed {
                identity,
                community,
                fleet,
            } => {
                assert_eq!(identity.current, 1);
                assert_eq!(community.current, 1);
                assert_eq!(fleet.current, 1);
                assert!(identity.allowed && community.allowed && fleet.allowed);
                assert_eq!(identity.reset_in_secs, community.reset_in_secs);
                assert_eq!(community.reset_in_secs, fleet.reset_in_secs);
            }
            other => panic!("expected allow, got {other:?}"),
        }
        assert_eq!(get_count(&pool, &identity_key).await, 1);
        assert_eq!(get_count(&pool, &community_key).await, 1);
        assert_eq!(get_count(&pool, &fleet_key).await, 1);
        assert_exact_shared_deadline_3(&pool, &identity_key, &community_key, &fleet_key).await;
        let second = limiter
            .check_hierarchical_admission(hrequest(
                &tenant,
                &identity.public_key(),
                &community.public_key(),
                &ip,
                HierarchicalAdmissionLimits::new(3, 6, 10),
                30,
            ))
            .await
            .expect("second");
        match second {
            HierarchicalAdmissionOutcome::Allowed {
                identity,
                community,
                fleet,
            } => {
                assert_eq!(identity.current, 2);
                assert_eq!(community.current, 2);
                assert_eq!(fleet.current, 2);
            }
            other => panic!("expected second allow, got {other:?}"),
        }
        assert_exact_shared_deadline_3(&pool, &identity_key, &community_key, &fleet_key).await;
        del(&pool, &identity_key).await;
        del(&pool, &community_key).await;
        del(&pool, &fleet_key).await;
    }

    #[tokio::test]
    #[ignore = "requires Redis"]
    async fn hierarchical_identity_denial_mutates_no_counter_and_does_not_create_missing_key() {
        let Some(pool) = redis_pool().await else {
            panic!("local Redis not reachable");
        };
        let limiter = RedisRateLimiter::new(pool.clone());
        let tenant = unique_tenant();
        let identity = Keys::generate();
        let community = Keys::generate();
        let ip = unique_ip();
        let identity_key = rate_limit_key(
            &tenant,
            &identity.public_key(),
            &LimitType::KeyedHttpAttempts,
        );
        let community_key = rate_limit_key(
            &tenant,
            &community.public_key(),
            &LimitType::KeyedHttpAttempts,
        );
        let fleet_key = ip_rate_limit_key(&ip);
        del(&pool, &identity_key).await;
        seed_count(&pool, &community_key, 1, 30).await;
        seed_count(&pool, &fleet_key, 1, 30).await;
        let outcome = limiter
            .check_hierarchical_admission(hrequest(
                &tenant,
                &identity.public_key(),
                &community.public_key(),
                &ip,
                HierarchicalAdmissionLimits::new(0, 6, 10),
                30,
            ))
            .await
            .expect("hierarchical");
        assert!(
            matches!(
                outcome,
                HierarchicalAdmissionOutcome::IdentityDenied(ref result) if !result.allowed
            ),
            "got {outcome:?}"
        );
        assert_identity_missing(&pool, &identity_key).await;
        assert_eq!(get_count(&pool, &community_key).await, 1);
        assert_eq!(get_count(&pool, &fleet_key).await, 1);

        seed_count(&pool, &identity_key, 2, 30).await;
        let before_i = get_count(&pool, &identity_key).await;
        let before_c = get_count(&pool, &community_key).await;
        let before_f = get_count(&pool, &fleet_key).await;
        let before_f_at = get_pexpiretime(&pool, &fleet_key).await;
        let denied = limiter
            .check_hierarchical_admission(hrequest(
                &tenant,
                &identity.public_key(),
                &community.public_key(),
                &ip,
                HierarchicalAdmissionLimits::new(2, 6, 10),
                30,
            ))
            .await
            .expect("identity at limit");
        assert!(
            matches!(
                denied,
                HierarchicalAdmissionOutcome::IdentityDenied(ref result) if !result.allowed
            ),
            "got {denied:?}"
        );
        assert_eq!(get_count(&pool, &identity_key).await, before_i);
        assert_eq!(get_count(&pool, &community_key).await, before_c);
        assert_eq!(get_count(&pool, &fleet_key).await, before_f);
        assert_absolute_deadline_unmoved(
            "fleet",
            before_f_at,
            get_pexpiretime(&pool, &fleet_key).await,
        );
        assert_eq!(
            get_pexpiretime(&pool, &identity_key).await,
            get_pexpiretime(&pool, &fleet_key).await
        );
        assert_eq!(
            get_pexpiretime(&pool, &community_key).await,
            get_pexpiretime(&pool, &fleet_key).await
        );
        del(&pool, &identity_key).await;
        del(&pool, &community_key).await;
        del(&pool, &fleet_key).await;
    }

    #[tokio::test]
    #[ignore = "requires Redis"]
    async fn hierarchical_community_denial_does_not_burn_signer_fair_share() {
        let Some(pool) = redis_pool().await else {
            panic!("local Redis not reachable");
        };
        let limiter = RedisRateLimiter::new(pool.clone());
        let tenant = unique_tenant();
        let identity = Keys::generate();
        let community = Keys::generate();
        let ip = unique_ip();
        let identity_key = rate_limit_key(
            &tenant,
            &identity.public_key(),
            &LimitType::KeyedHttpAttempts,
        );
        let community_key = rate_limit_key(
            &tenant,
            &community.public_key(),
            &LimitType::KeyedHttpAttempts,
        );
        let fleet_key = ip_rate_limit_key(&ip);
        del(&pool, &identity_key).await;
        seed_count(&pool, &community_key, 3, 30).await;
        seed_count(&pool, &fleet_key, 4, 30).await;
        let before_c = get_count(&pool, &community_key).await;
        let before_f = get_count(&pool, &fleet_key).await;
        let before_f_at = get_pexpiretime(&pool, &fleet_key).await;
        let outcome = limiter
            .check_hierarchical_admission(hrequest(
                &tenant,
                &identity.public_key(),
                &community.public_key(),
                &ip,
                HierarchicalAdmissionLimits::new(3, 3, 10),
                30,
            ))
            .await
            .expect("hierarchical");
        assert!(
            matches!(
                outcome,
                HierarchicalAdmissionOutcome::CommunityDenied(ref result) if !result.allowed
            ),
            "got {outcome:?}"
        );
        assert_identity_missing(&pool, &identity_key).await;
        assert_eq!(get_count(&pool, &community_key).await, before_c);
        assert_eq!(get_count(&pool, &fleet_key).await, before_f);
        assert_absolute_deadline_unmoved(
            "fleet",
            before_f_at,
            get_pexpiretime(&pool, &fleet_key).await,
        );
        del(&pool, &community_key).await;
        del(&pool, &fleet_key).await;
    }

    #[tokio::test]
    #[ignore = "requires Redis"]
    async fn hierarchical_fleet_denial_does_not_create_identity_or_charge_community() {
        let Some(pool) = redis_pool().await else {
            panic!("local Redis not reachable");
        };
        let limiter = RedisRateLimiter::new(pool.clone());
        let tenant = unique_tenant();
        let identity = Keys::generate();
        let community = Keys::generate();
        let ip = unique_ip();
        let identity_key = rate_limit_key(
            &tenant,
            &identity.public_key(),
            &LimitType::KeyedHttpAttempts,
        );
        let community_key = rate_limit_key(
            &tenant,
            &community.public_key(),
            &LimitType::KeyedHttpAttempts,
        );
        let fleet_key = ip_rate_limit_key(&ip);
        del(&pool, &identity_key).await;
        seed_count(&pool, &community_key, 1, 30).await;
        seed_count(&pool, &fleet_key, 5, 30).await;
        let before_c = get_count(&pool, &community_key).await;
        let before_f = get_count(&pool, &fleet_key).await;
        let before_f_at = get_pexpiretime(&pool, &fleet_key).await;
        let outcome = limiter
            .check_hierarchical_admission(hrequest(
                &tenant,
                &identity.public_key(),
                &community.public_key(),
                &ip,
                HierarchicalAdmissionLimits::new(3, 6, 5),
                30,
            ))
            .await
            .expect("hierarchical");
        assert!(
            matches!(
                outcome,
                HierarchicalAdmissionOutcome::FleetDenied(ref result) if !result.allowed
            ),
            "got {outcome:?}"
        );
        assert_identity_missing(&pool, &identity_key).await;
        assert_eq!(get_count(&pool, &community_key).await, before_c);
        assert_eq!(get_count(&pool, &fleet_key).await, before_f);
        assert_absolute_deadline_unmoved(
            "fleet",
            before_f_at,
            get_pexpiretime(&pool, &fleet_key).await,
        );
        del(&pool, &community_key).await;
        del(&pool, &fleet_key).await;
    }

    #[tokio::test]
    #[ignore = "requires Redis"]
    async fn hierarchical_distinct_signers_use_distinct_keys_bounded_by_community() {
        let Some(pool) = redis_pool().await else {
            panic!("local Redis not reachable");
        };
        let limiter = RedisRateLimiter::new(pool.clone());
        let tenant = unique_tenant();
        let community = Keys::generate();
        let ip = unique_ip();
        let community_key = rate_limit_key(
            &tenant,
            &community.public_key(),
            &LimitType::KeyedHttpAttempts,
        );
        let fleet_key = ip_rate_limit_key(&ip);
        del(&pool, &community_key).await;
        del(&pool, &fleet_key).await;
        let community_limit = 3u64;
        let mut identity_keys = std::collections::BTreeSet::new();
        let mut signers = Vec::new();
        for expected in 1..=community_limit {
            let keys = Keys::generate();
            let identity_key =
                rate_limit_key(&tenant, &keys.public_key(), &LimitType::KeyedHttpAttempts);
            assert!(
                identity_keys.insert(identity_key.clone()),
                "authenticated signer keys must not collide"
            );
            let outcome = limiter
                .check_hierarchical_admission(hrequest(
                    &tenant,
                    &keys.public_key(),
                    &community.public_key(),
                    &ip,
                    HierarchicalAdmissionLimits::new(10, community_limit, 20),
                    30,
                ))
                .await
                .expect("hierarchical");
            match outcome {
                HierarchicalAdmissionOutcome::Allowed {
                    identity,
                    community,
                    fleet,
                } => {
                    assert_eq!(identity.current, 1);
                    assert_eq!(community.current, expected);
                    assert_eq!(fleet.current, expected);
                }
                other => panic!("expected allow {expected}, got {other:?}"),
            }
            assert_eq!(get_count(&pool, &identity_key).await, 1);
            signers.push(keys);
        }
        assert_eq!(identity_keys.len() as u64, community_limit);
        assert_eq!(
            get_count(&pool, &community_key).await,
            community_limit as i64
        );
        assert_eq!(get_count(&pool, &fleet_key).await, community_limit as i64);
        let overflow = Keys::generate();
        let overflow_key = rate_limit_key(
            &tenant,
            &overflow.public_key(),
            &LimitType::KeyedHttpAttempts,
        );
        del(&pool, &overflow_key).await;
        let denied = limiter
            .check_hierarchical_admission(hrequest(
                &tenant,
                &overflow.public_key(),
                &community.public_key(),
                &ip,
                HierarchicalAdmissionLimits::new(10, community_limit, 20),
                30,
            ))
            .await
            .expect("community full");
        assert!(
            matches!(
                denied,
                HierarchicalAdmissionOutcome::CommunityDenied(ref result) if !result.allowed
            ),
            "got {denied:?}"
        );
        assert_identity_missing(&pool, &overflow_key).await;
        assert_eq!(
            get_count(&pool, &community_key).await,
            community_limit as i64
        );
        assert_eq!(get_count(&pool, &fleet_key).await, community_limit as i64);
        for keys in &signers {
            del(
                &pool,
                &rate_limit_key(&tenant, &keys.public_key(), &LimitType::KeyedHttpAttempts),
            )
            .await;
        }
        del(&pool, &community_key).await;
        del(&pool, &fleet_key).await;
        del(&pool, &overflow_key).await;
    }

    #[tokio::test]
    #[ignore = "requires Redis"]
    async fn hierarchical_denial_cannot_extend_shared_deadline() {
        let Some(pool) = redis_pool().await else {
            panic!("local Redis not reachable");
        };
        let limiter = RedisRateLimiter::new(pool.clone());
        let tenant = unique_tenant();
        let identity = Keys::generate();
        let other = Keys::generate();
        let community = Keys::generate();
        let ip = unique_ip();
        let identity_key = rate_limit_key(
            &tenant,
            &identity.public_key(),
            &LimitType::KeyedHttpAttempts,
        );
        let other_key = rate_limit_key(&tenant, &other.public_key(), &LimitType::KeyedHttpAttempts);
        let community_key = rate_limit_key(
            &tenant,
            &community.public_key(),
            &LimitType::KeyedHttpAttempts,
        );
        let fleet_key = ip_rate_limit_key(&ip);
        del(&pool, &identity_key).await;
        del(&pool, &other_key).await;
        del(&pool, &community_key).await;
        del(&pool, &fleet_key).await;
        limiter
            .check_hierarchical_admission(hrequest(
                &tenant,
                &identity.public_key(),
                &community.public_key(),
                &ip,
                HierarchicalAdmissionLimits::new(1, 1, 1),
                30,
            ))
            .await
            .expect("first allow");
        assert_exact_shared_deadline_3(&pool, &identity_key, &community_key, &fleet_key).await;
        let before_f_at = get_pexpiretime(&pool, &fleet_key).await;
        let before_i_at = get_pexpiretime(&pool, &identity_key).await;
        let denied = limiter
            .check_hierarchical_admission(hrequest(
                &tenant,
                &other.public_key(),
                &community.public_key(),
                &ip,
                HierarchicalAdmissionLimits::new(1, 1, 1),
                30,
            ))
            .await
            .expect("shared full");
        assert!(
            matches!(
                denied,
                HierarchicalAdmissionOutcome::CommunityDenied(_)
                    | HierarchicalAdmissionOutcome::FleetDenied(_)
            ),
            "got {denied:?}"
        );
        assert_identity_missing(&pool, &other_key).await;
        assert_absolute_deadline_unmoved(
            "fleet",
            before_f_at,
            get_pexpiretime(&pool, &fleet_key).await,
        );
        assert_absolute_deadline_unmoved(
            "identity",
            before_i_at,
            get_pexpiretime(&pool, &identity_key).await,
        );
        assert_eq!(
            get_pexpiretime(&pool, &community_key).await,
            get_pexpiretime(&pool, &fleet_key).await
        );
        del(&pool, &identity_key).await;
        del(&pool, &other_key).await;
        del(&pool, &community_key).await;
        del(&pool, &fleet_key).await;
    }

    #[tokio::test]
    #[ignore = "requires Redis"]
    async fn hierarchical_leading_zero_and_non_integer_fail_closed_without_creating_identity() {
        let Some(pool) = redis_pool().await else {
            panic!("local Redis not reachable");
        };
        let limiter = RedisRateLimiter::new(pool.clone());
        let tenant = unique_tenant();
        let identity = Keys::generate();
        let community = Keys::generate();
        let ip = unique_ip();
        let identity_key = rate_limit_key(
            &tenant,
            &identity.public_key(),
            &LimitType::KeyedHttpAttempts,
        );
        let community_key = rate_limit_key(
            &tenant,
            &community.public_key(),
            &LimitType::KeyedHttpAttempts,
        );
        let fleet_key = ip_rate_limit_key(&ip);
        del(&pool, &identity_key).await;
        seed_raw(&pool, &community_key, "0001", Some(30)).await;
        seed_count(&pool, &fleet_key, 1, 30).await;
        let before_c = get_raw(&pool, &community_key).await;
        let before_f = get_raw(&pool, &fleet_key).await;
        let before_f_at = get_pexpiretime(&pool, &fleet_key).await;
        let err = limiter
            .check_hierarchical_admission(hrequest(
                &tenant,
                &identity.public_key(),
                &community.public_key(),
                &ip,
                HierarchicalAdmissionLimits::new(3, 6, 10),
                30,
            ))
            .await
            .expect_err("leading-zero community must fail closed");
        assert!(
            err.to_string().contains("corrupt"),
            "leading-zero counters must fail closed, got {err}"
        );
        assert_identity_missing(&pool, &identity_key).await;
        assert_eq!(get_raw(&pool, &community_key).await, before_c);
        assert_eq!(get_raw(&pool, &fleet_key).await, before_f);
        assert_absolute_deadline_unmoved(
            "fleet",
            before_f_at,
            get_pexpiretime(&pool, &fleet_key).await,
        );

        del(&pool, &community_key).await;
        seed_raw(&pool, &fleet_key, "1.2", Some(30)).await;
        let before_f = get_raw(&pool, &fleet_key).await;
        limiter
            .check_hierarchical_admission(hrequest(
                &tenant,
                &identity.public_key(),
                &community.public_key(),
                &ip,
                HierarchicalAdmissionLimits::new(3, 6, 10),
                30,
            ))
            .await
            .expect_err("non-integer fleet must fail closed");
        assert_identity_missing(&pool, &identity_key).await;
        assert_eq!(get_raw(&pool, &fleet_key).await, before_f);
        assert!(!exists(&pool, &community_key).await);
        del(&pool, &identity_key).await;
        del(&pool, &community_key).await;
        del(&pool, &fleet_key).await;
    }

    #[tokio::test]
    #[ignore = "requires Redis"]
    async fn hierarchical_overflow_negative_and_wrong_type_fail_closed_without_partial_charge() {
        let Some(pool) = redis_pool().await else {
            panic!("local Redis not reachable");
        };
        let limiter = RedisRateLimiter::new(pool.clone());
        let tenant = unique_tenant();
        let identity = Keys::generate();
        let community = Keys::generate();
        let ip = unique_ip();
        let identity_key = rate_limit_key(
            &tenant,
            &identity.public_key(),
            &LimitType::KeyedHttpAttempts,
        );
        let community_key = rate_limit_key(
            &tenant,
            &community.public_key(),
            &LimitType::KeyedHttpAttempts,
        );
        let fleet_key = ip_rate_limit_key(&ip);

        seed_raw(&pool, &identity_key, "9223372036854775807", Some(30)).await;
        seed_count(&pool, &community_key, 1, 30).await;
        seed_count(&pool, &fleet_key, 1, 30).await;
        let before_i = get_raw(&pool, &identity_key).await;
        let before_c = get_raw(&pool, &community_key).await;
        let before_f = get_raw(&pool, &fleet_key).await;
        let overflow = limiter
            .check_hierarchical_admission(hrequest(
                &tenant,
                &identity.public_key(),
                &community.public_key(),
                &ip,
                HierarchicalAdmissionLimits::new(u64::MAX, 20, 20),
                30,
            ))
            .await;
        match overflow {
            Ok(HierarchicalAdmissionOutcome::IdentityDenied(result)) => {
                assert!(!result.allowed);
            }
            Err(error) => {
                assert!(
                    error.to_string().contains("corrupt"),
                    "overflow that cannot INCR must fail closed, got {error}"
                );
            }
            other => panic!("overflow must not charge, got {other:?}"),
        }
        assert_eq!(get_raw(&pool, &identity_key).await, before_i);
        assert_eq!(get_raw(&pool, &community_key).await, before_c);
        assert_eq!(get_raw(&pool, &fleet_key).await, before_f);

        del(&pool, &identity_key).await;
        seed_count(&pool, &community_key, -3, 30).await;
        let before_c = get_raw(&pool, &community_key).await;
        limiter
            .check_hierarchical_admission(hrequest(
                &tenant,
                &identity.public_key(),
                &community.public_key(),
                &ip,
                HierarchicalAdmissionLimits::new(3, 6, 10),
                30,
            ))
            .await
            .expect_err("negative community must fail closed");
        assert_identity_missing(&pool, &identity_key).await;
        assert_eq!(get_raw(&pool, &community_key).await, before_c);

        del(&pool, &community_key).await;
        del(&pool, &fleet_key).await;
        del(&pool, &identity_key).await;
        seed_count(&pool, &community_key, 1, 30).await;
        seed_count(&pool, &fleet_key, 1, 30).await;
        let mut conn = pool.get().await.expect("redis conn");
        let _: () = redis::cmd("RPUSH")
            .arg(&identity_key)
            .arg("x")
            .query_async(&mut *conn)
            .await
            .expect("wrong type");
        drop(conn);
        let before_c = get_raw(&pool, &community_key).await;
        let before_f = get_raw(&pool, &fleet_key).await;
        limiter
            .check_hierarchical_admission(hrequest(
                &tenant,
                &identity.public_key(),
                &community.public_key(),
                &ip,
                HierarchicalAdmissionLimits::new(3, 6, 10),
                30,
            ))
            .await
            .expect_err("wrong-type identity must fail closed");
        assert_eq!(get_raw(&pool, &community_key).await, before_c);
        assert_eq!(get_raw(&pool, &fleet_key).await, before_f);
        assert_eq!(get_count(&pool, &community_key).await, 1);
        assert_eq!(get_count(&pool, &fleet_key).await, 1);
        let mut conn = pool.get().await.expect("redis conn");
        let kind: String = redis::cmd("TYPE")
            .arg(&identity_key)
            .query_async(&mut *conn)
            .await
            .expect("type");
        assert_eq!(kind, "list");
        del(&pool, &identity_key).await;
        del(&pool, &community_key).await;
        del(&pool, &fleet_key).await;
    }

    #[tokio::test]
    #[ignore = "requires Redis"]
    async fn hierarchical_persistent_and_misaligned_ttl_fail_closed_or_align_without_charge() {
        let Some(pool) = redis_pool().await else {
            panic!("local Redis not reachable");
        };
        let limiter = RedisRateLimiter::new(pool.clone());
        let tenant = unique_tenant();
        let identity = Keys::generate();
        let community = Keys::generate();
        let ip = unique_ip();
        let identity_key = rate_limit_key(
            &tenant,
            &identity.public_key(),
            &LimitType::KeyedHttpAttempts,
        );
        let community_key = rate_limit_key(
            &tenant,
            &community.public_key(),
            &LimitType::KeyedHttpAttempts,
        );
        let fleet_key = ip_rate_limit_key(&ip);
        del(&pool, &identity_key).await;
        persist_count(&pool, &community_key, 3).await;
        persist_count(&pool, &fleet_key, 5).await;
        assert_eq!(get_pttl(&pool, &fleet_key).await, -1);
        let outcome = limiter
            .check_hierarchical_admission(hrequest(
                &tenant,
                &identity.public_key(),
                &community.public_key(),
                &ip,
                HierarchicalAdmissionLimits::new(3, 3, 5),
                30,
            ))
            .await
            .expect("persistent at limit");
        assert!(
            matches!(
                outcome,
                HierarchicalAdmissionOutcome::CommunityDenied(_)
                    | HierarchicalAdmissionOutcome::FleetDenied(_)
            ),
            "PTTL -1 at limit must be ordinary denial, got {outcome:?}"
        );
        assert_identity_missing(&pool, &identity_key).await;
        assert_eq!(get_count(&pool, &community_key).await, 3);
        assert_eq!(get_count(&pool, &fleet_key).await, 5);
        assert_ne!(get_pttl(&pool, &fleet_key).await, -1);
        assert_eq!(
            get_pexpiretime(&pool, &community_key).await,
            get_pexpiretime(&pool, &fleet_key).await
        );
        assert!(
            get_pexpiretime(&pool, &community_key).await > 0,
            "persistent community denial must repair to a live fleet deadline"
        );

        del(&pool, &community_key).await;
        del(&pool, &fleet_key).await;
        seed_count(&pool, &community_key, 3, 5).await;
        seed_count(&pool, &fleet_key, 4, 30).await;
        let before_c = get_count(&pool, &community_key).await;
        let before_f = get_count(&pool, &fleet_key).await;
        let before_f_at = get_pexpiretime(&pool, &fleet_key).await;
        let denied = limiter
            .check_hierarchical_admission(hrequest(
                &tenant,
                &identity.public_key(),
                &community.public_key(),
                &ip,
                HierarchicalAdmissionLimits::new(3, 3, 20),
                30,
            ))
            .await
            .expect("community capped");
        assert!(
            matches!(
                denied,
                HierarchicalAdmissionOutcome::CommunityDenied(ref result) if !result.allowed
            ),
            "got {denied:?}"
        );
        assert_identity_missing(&pool, &identity_key).await;
        assert_eq!(get_count(&pool, &community_key).await, before_c);
        assert_eq!(get_count(&pool, &fleet_key).await, before_f);
        assert_absolute_deadline_unmoved(
            "fleet",
            before_f_at,
            get_pexpiretime(&pool, &fleet_key).await,
        );
        assert_eq!(
            get_pexpiretime(&pool, &community_key).await,
            get_pexpiretime(&pool, &fleet_key).await
        );
        del(&pool, &identity_key).await;
        del(&pool, &community_key).await;
        del(&pool, &fleet_key).await;
    }

    #[tokio::test]
    #[ignore = "requires Redis"]
    async fn hierarchical_aligned_denial_preserves_exact_pexpiretime_and_counters() {
        let Some(pool) = redis_pool().await else {
            panic!("local Redis not reachable");
        };
        let limiter = RedisRateLimiter::new(pool.clone());
        let tenant = unique_tenant();
        let identity = Keys::generate();
        let community = Keys::generate();
        let ip = unique_ip();
        let identity_key = rate_limit_key(
            &tenant,
            &identity.public_key(),
            &LimitType::KeyedHttpAttempts,
        );
        let community_key = rate_limit_key(
            &tenant,
            &community.public_key(),
            &LimitType::KeyedHttpAttempts,
        );
        let fleet_key = ip_rate_limit_key(&ip);
        del(&pool, &identity_key).await;
        del(&pool, &community_key).await;
        del(&pool, &fleet_key).await;
        seed_count(&pool, &fleet_key, 4, 30).await;
        let fleet_at = get_pexpiretime(&pool, &fleet_key).await;
        seed_count_pxat(&pool, &identity_key, 2, fleet_at).await;
        seed_count_pxat(&pool, &community_key, 1, fleet_at).await;
        assert_eq!(get_pexpiretime(&pool, &identity_key).await, fleet_at);
        assert_eq!(get_pexpiretime(&pool, &community_key).await, fleet_at);
        let before_i = get_count(&pool, &identity_key).await;
        let before_c = get_count(&pool, &community_key).await;
        let before_f = get_count(&pool, &fleet_key).await;
        let marker_key = format!("aligned-denial-monitor:{}", Uuid::new_v4());
        let start_marker = format!("start:{}", Uuid::new_v4());
        let end_marker = format!("end:{}", Uuid::new_v4());
        let quoted_identity = format!("\"{identity_key}\"");
        let quoted_community = format!("\"{community_key}\"");
        let quoted_marker = format!("\"{marker_key}\"");
        let quoted_start = format!("\"{start_marker}\"");
        let quoted_end = format!("\"{end_marker}\"");
        let url = std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".into());
        let client = match redis::Client::open(url) {
            Ok(client) => client,
            Err(_) => panic!("monitor client failed"),
        };
        let monitor = match tokio::time::timeout(
            std::time::Duration::from_secs(5),
            client.get_async_monitor(),
        )
        .await
        {
            Ok(Ok(monitor)) => monitor,
            Ok(Err(_)) => panic!("monitor unavailable"),
            Err(_) => panic!("monitor timed out"),
        };
        let messages = monitor.into_on_message::<String>();
        futures_util::pin_mut!(messages);
        {
            let mut conn = pool.get().await.expect("redis conn");
            let _: () = redis::cmd("SET")
                .arg(&marker_key)
                .arg(&start_marker)
                .arg("EX")
                .arg(30)
                .query_async(&mut *conn)
                .await
                .expect("start marker");
        }
        let denied = limiter
            .check_hierarchical_admission(hrequest(
                &tenant,
                &identity.public_key(),
                &community.public_key(),
                &ip,
                HierarchicalAdmissionLimits::new(2, 6, 10),
                30,
            ))
            .await
            .expect("aligned identity cap");
        {
            let mut conn = pool.get().await.expect("redis conn");
            let _: () = redis::cmd("SET")
                .arg(&marker_key)
                .arg(&end_marker)
                .arg("EX")
                .arg(30)
                .query_async(&mut *conn)
                .await
                .expect("end marker");
        }
        let capture = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            let mut started = false;
            let mut ended = false;
            let mut lua_get_targets: u32 = 0;
            let mut lua_pexpireat_aligned: u32 = 0;
            while let Some(line) = messages.next().await {
                if !started {
                    if line.contains("\"SET\"")
                        && line.contains(&quoted_marker)
                        && line.contains(&quoted_start)
                    {
                        started = true;
                    }
                    continue;
                }
                if line.contains("\"SET\"")
                    && line.contains(&quoted_marker)
                    && line.contains(&quoted_end)
                {
                    ended = true;
                    break;
                }
                let lua_source = line
                    .split_once('[')
                    .and_then(|(_, rest)| rest.split_once(']'))
                    .map(|(source, _)| {
                        let mut fields = source.split_whitespace();
                        let Some(_db) = fields.next() else {
                            return false;
                        };
                        matches!(fields.next(), Some("lua"))
                    })
                    .unwrap_or(false);
                if !lua_source {
                    continue;
                }
                let targets_key =
                    line.contains(&quoted_identity) || line.contains(&quoted_community);
                if !targets_key {
                    continue;
                }
                if line.contains("\"GET\"") {
                    lua_get_targets = lua_get_targets.saturating_add(1);
                }
                if line.contains("\"PEXPIREAT\"") {
                    lua_pexpireat_aligned = lua_pexpireat_aligned.saturating_add(1);
                }
            }
            (started, ended, lua_get_targets, lua_pexpireat_aligned)
        })
        .await;
        let (started, ended, lua_get_targets, lua_pexpireat_aligned) = match capture {
            Ok(counts) => counts,
            Err(_) => panic!("aligned denial monitor capture timed out"),
        };
        assert!(started, "aligned denial monitor missed the start marker");
        assert!(ended, "aligned denial monitor missed the end marker");
        assert!(
            lua_get_targets >= 1,
            "aligned denial monitor captured no lua GET of an aligned key"
        );
        assert_eq!(
            lua_pexpireat_aligned, 0,
            "aligned denial must not issue lua PEXPIREAT for an already-aligned key"
        );
        assert!(
            matches!(
                denied,
                HierarchicalAdmissionOutcome::IdentityDenied(ref result) if !result.allowed
            ),
            "got {denied:?}"
        );
        assert_eq!(get_count(&pool, &identity_key).await, before_i);
        assert_eq!(get_count(&pool, &community_key).await, before_c);
        assert_eq!(get_count(&pool, &fleet_key).await, before_f);
        assert_eq!(get_pexpiretime(&pool, &identity_key).await, fleet_at);
        assert_eq!(get_pexpiretime(&pool, &community_key).await, fleet_at);
        assert_eq!(get_pexpiretime(&pool, &fleet_key).await, fleet_at);

        seed_count_pxat(&pool, &identity_key, 1, fleet_at).await;
        seed_count_pxat(&pool, &community_key, 3, fleet_at).await;
        let before_i = get_count(&pool, &identity_key).await;
        let before_c = get_count(&pool, &community_key).await;
        let community_denied = limiter
            .check_hierarchical_admission(hrequest(
                &tenant,
                &identity.public_key(),
                &community.public_key(),
                &ip,
                HierarchicalAdmissionLimits::new(3, 3, 10),
                30,
            ))
            .await
            .expect("aligned community cap");
        assert!(
            matches!(
                community_denied,
                HierarchicalAdmissionOutcome::CommunityDenied(ref result) if !result.allowed
            ),
            "got {community_denied:?}"
        );
        assert_eq!(get_count(&pool, &identity_key).await, before_i);
        assert_eq!(get_count(&pool, &community_key).await, before_c);
        assert_eq!(get_count(&pool, &fleet_key).await, before_f);
        assert_eq!(get_pexpiretime(&pool, &identity_key).await, fleet_at);
        assert_eq!(get_pexpiretime(&pool, &community_key).await, fleet_at);
        assert_eq!(get_pexpiretime(&pool, &fleet_key).await, fleet_at);
        del(&pool, &identity_key).await;
        del(&pool, &community_key).await;
        del(&pool, &fleet_key).await;
        del(&pool, &marker_key).await;
    }

    #[tokio::test]
    #[ignore = "requires Redis"]
    async fn hierarchical_misaligned_denial_repairs_to_live_fleet_deadline_without_charge() {
        let Some(pool) = redis_pool().await else {
            panic!("local Redis not reachable");
        };
        let limiter = RedisRateLimiter::new(pool.clone());
        let tenant = unique_tenant();
        let identity = Keys::generate();
        let community = Keys::generate();
        let ip = unique_ip();
        let identity_key = rate_limit_key(
            &tenant,
            &identity.public_key(),
            &LimitType::KeyedHttpAttempts,
        );
        let community_key = rate_limit_key(
            &tenant,
            &community.public_key(),
            &LimitType::KeyedHttpAttempts,
        );
        let fleet_key = ip_rate_limit_key(&ip);
        del(&pool, &identity_key).await;
        del(&pool, &community_key).await;
        del(&pool, &fleet_key).await;
        seed_count(&pool, &identity_key, 2, 60).await;
        seed_count(&pool, &community_key, 1, 5).await;
        seed_count(&pool, &fleet_key, 4, 30).await;
        let before_i = get_count(&pool, &identity_key).await;
        let before_c = get_count(&pool, &community_key).await;
        let before_f = get_count(&pool, &fleet_key).await;
        let before_f_at = get_pexpiretime(&pool, &fleet_key).await;
        let before_i_at = get_pexpiretime(&pool, &identity_key).await;
        let before_c_at = get_pexpiretime(&pool, &community_key).await;
        assert_ne!(before_i_at, before_f_at);
        assert_ne!(before_c_at, before_f_at);
        assert!(
            before_i_at > before_f_at,
            "identity must start beyond the fleet deadline so repair clamps it"
        );
        let denied = limiter
            .check_hierarchical_admission(hrequest(
                &tenant,
                &identity.public_key(),
                &community.public_key(),
                &ip,
                HierarchicalAdmissionLimits::new(2, 6, 10),
                30,
            ))
            .await
            .expect("misaligned identity cap");
        assert!(
            matches!(
                denied,
                HierarchicalAdmissionOutcome::IdentityDenied(ref result) if !result.allowed
            ),
            "got {denied:?}"
        );
        assert_eq!(get_count(&pool, &identity_key).await, before_i);
        assert_eq!(get_count(&pool, &community_key).await, before_c);
        assert_eq!(get_count(&pool, &fleet_key).await, before_f);
        assert_absolute_deadline_unmoved(
            "fleet",
            before_f_at,
            get_pexpiretime(&pool, &fleet_key).await,
        );
        let after_f_at = get_pexpiretime(&pool, &fleet_key).await;
        assert_eq!(get_pexpiretime(&pool, &identity_key).await, after_f_at);
        assert_eq!(get_pexpiretime(&pool, &community_key).await, after_f_at);
        assert!(
            get_pexpiretime(&pool, &identity_key).await <= after_f_at,
            "repair must never extend identity beyond the live fleet deadline"
        );
        del(&pool, &identity_key).await;
        del(&pool, &community_key).await;
        del(&pool, &fleet_key).await;
    }

    #[tokio::test]
    #[ignore = "requires Redis"]
    async fn hierarchical_persistent_denial_repairs_present_keys_without_creating_missing_identity()
    {
        let Some(pool) = redis_pool().await else {
            panic!("local Redis not reachable");
        };
        let limiter = RedisRateLimiter::new(pool.clone());
        let tenant = unique_tenant();
        let identity = Keys::generate();
        let other = Keys::generate();
        let community = Keys::generate();
        let ip = unique_ip();
        let identity_key = rate_limit_key(
            &tenant,
            &identity.public_key(),
            &LimitType::KeyedHttpAttempts,
        );
        let other_key = rate_limit_key(&tenant, &other.public_key(), &LimitType::KeyedHttpAttempts);
        let community_key = rate_limit_key(
            &tenant,
            &community.public_key(),
            &LimitType::KeyedHttpAttempts,
        );
        let fleet_key = ip_rate_limit_key(&ip);
        del(&pool, &identity_key).await;
        del(&pool, &other_key).await;
        del(&pool, &community_key).await;
        del(&pool, &fleet_key).await;

        persist_count(&pool, &identity_key, 2).await;
        persist_count(&pool, &community_key, 1).await;
        seed_count(&pool, &fleet_key, 4, 30).await;
        assert_eq!(get_pttl(&pool, &identity_key).await, -1);
        assert_eq!(get_pttl(&pool, &community_key).await, -1);
        let before_i = get_count(&pool, &identity_key).await;
        let before_c = get_count(&pool, &community_key).await;
        let before_f = get_count(&pool, &fleet_key).await;
        let before_f_at = get_pexpiretime(&pool, &fleet_key).await;
        let denied = limiter
            .check_hierarchical_admission(hrequest(
                &tenant,
                &identity.public_key(),
                &community.public_key(),
                &ip,
                HierarchicalAdmissionLimits::new(2, 6, 10),
                30,
            ))
            .await
            .expect("persistent identity cap");
        assert!(
            matches!(
                denied,
                HierarchicalAdmissionOutcome::IdentityDenied(ref result) if !result.allowed
            ),
            "got {denied:?}"
        );
        assert_eq!(get_count(&pool, &identity_key).await, before_i);
        assert_eq!(get_count(&pool, &community_key).await, before_c);
        assert_eq!(get_count(&pool, &fleet_key).await, before_f);
        assert_absolute_deadline_unmoved(
            "fleet",
            before_f_at,
            get_pexpiretime(&pool, &fleet_key).await,
        );
        assert_eq!(
            get_pexpiretime(&pool, &identity_key).await,
            get_pexpiretime(&pool, &fleet_key).await
        );
        assert_eq!(
            get_pexpiretime(&pool, &community_key).await,
            get_pexpiretime(&pool, &fleet_key).await
        );
        assert_ne!(get_pttl(&pool, &identity_key).await, -1);
        assert_ne!(get_pttl(&pool, &community_key).await, -1);

        del(&pool, &identity_key).await;
        persist_count(&pool, &community_key, 3).await;
        persist_count(&pool, &fleet_key, 5).await;
        let missing_denied = limiter
            .check_hierarchical_admission(hrequest(
                &tenant,
                &other.public_key(),
                &community.public_key(),
                &ip,
                HierarchicalAdmissionLimits::new(3, 3, 5),
                30,
            ))
            .await
            .expect("missing identity community cap");
        assert!(
            matches!(
                missing_denied,
                HierarchicalAdmissionOutcome::CommunityDenied(_)
                    | HierarchicalAdmissionOutcome::FleetDenied(_)
            ),
            "got {missing_denied:?}"
        );
        assert_identity_missing(&pool, &other_key).await;
        assert_eq!(get_count(&pool, &community_key).await, 3);
        assert_eq!(get_count(&pool, &fleet_key).await, 5);
        assert_eq!(
            get_pexpiretime(&pool, &community_key).await,
            get_pexpiretime(&pool, &fleet_key).await
        );
        del(&pool, &identity_key).await;
        del(&pool, &other_key).await;
        del(&pool, &community_key).await;
        del(&pool, &fleet_key).await;
    }

    #[tokio::test]
    #[ignore = "requires Redis"]
    async fn hierarchical_fresh_suffix_does_not_alias_preauth_keys() {
        let Some(pool) = redis_pool().await else {
            panic!("local Redis not reachable");
        };
        let limiter = RedisRateLimiter::new(pool.clone());
        let tenant = unique_tenant();
        let identity = Keys::generate();
        let community = Keys::generate();
        let ip_preauth = unique_ip();
        let ip_fresh = unique_ip_distinct_from(ip_preauth);
        assert_ne!(ip_preauth, ip_fresh);
        let preauth_identity = rate_limit_key(
            &tenant,
            &identity.public_key(),
            &LimitType::KeyedHttpAttempts,
        );
        let preauth_community = rate_limit_key(
            &tenant,
            &community.public_key(),
            &LimitType::KeyedHttpAttempts,
        );
        let fresh_identity =
            rate_limit_key(&tenant, &identity.public_key(), &LimitType::KeyedHttpFresh);
        let fresh_community =
            rate_limit_key(&tenant, &community.public_key(), &LimitType::KeyedHttpFresh);
        let preauth_fleet = ip_rate_limit_key(&ip_preauth);
        let fresh_fleet = ip_rate_limit_key(&ip_fresh);
        assert_ne!(preauth_identity, fresh_identity);
        assert_ne!(preauth_community, fresh_community);
        assert_ne!(preauth_fleet, fresh_fleet);
        del(&pool, &preauth_identity).await;
        del(&pool, &preauth_community).await;
        del(&pool, &fresh_identity).await;
        del(&pool, &fresh_community).await;
        del(&pool, &preauth_fleet).await;
        del(&pool, &fresh_fleet).await;
        limiter
            .check_hierarchical_admission(hrequest(
                &tenant,
                &identity.public_key(),
                &community.public_key(),
                &ip_preauth,
                HierarchicalAdmissionLimits::new(3, 6, 10),
                30,
            ))
            .await
            .expect("preauth");
        let identity_pk = identity.public_key();
        let community_pk = community.public_key();
        let fresh_req = HierarchicalAdmissionRequest::new(
            &tenant,
            &identity_pk,
            &community_pk,
            LimitType::KeyedHttpFresh,
            NonZeroU64::new(30).expect("window"),
            HierarchicalAdmissionLimits::new(3, 6, 10),
            &ip_fresh,
        );
        limiter
            .check_hierarchical_admission(fresh_req)
            .await
            .expect("fresh");
        assert_eq!(get_count(&pool, &preauth_identity).await, 1);
        assert_eq!(get_count(&pool, &fresh_identity).await, 1);
        assert_eq!(get_count(&pool, &preauth_community).await, 1);
        assert_eq!(get_count(&pool, &fresh_community).await, 1);
        assert_eq!(get_count(&pool, &preauth_fleet).await, 1);
        assert_eq!(get_count(&pool, &fresh_fleet).await, 1);
        del(&pool, &preauth_identity).await;
        del(&pool, &preauth_community).await;
        del(&pool, &fresh_identity).await;
        del(&pool, &fresh_community).await;
        del(&pool, &preauth_fleet).await;
        del(&pool, &fresh_fleet).await;
    }

    fn monitor_line_is_lua(line: &str) -> bool {
        line.split_once('[')
            .and_then(|(_, rest)| rest.split_once(']'))
            .map(|(source, _)| {
                let mut fields = source.split_whitespace();
                let Some(_db) = fields.next() else {
                    return false;
                };
                matches!(fields.next(), Some("lua"))
            })
            .unwrap_or(false)
    }

    fn monitor_line_is_write(line: &str) -> bool {
        line.contains("\"SET\"")
            || line.contains("\"INCR\"")
            || line.contains("\"DEL\"")
            || line.contains("\"EXPIRE\"")
            || line.contains("\"PEXPIRE\"")
            || line.contains("\"PEXPIREAT\"")
            || line.contains("\"PERSIST\"")
            || line.contains("\"UNLINK\"")
    }

    #[tokio::test]
    #[ignore = "requires Redis"]
    async fn hierarchical_identity_peek_unproven_states_are_not_fast_denial() {
        let Some(pool) = redis_pool().await else {
            panic!("local Redis not reachable");
        };
        let limiter = RedisRateLimiter::new(pool.clone());
        let tenant = unique_tenant();
        let identity = Keys::generate();
        let ip = unique_ip();
        let identity_key = rate_limit_key(
            &tenant,
            &identity.public_key(),
            &LimitType::KeyedHttpAttempts,
        );
        let fleet_key = ip_rate_limit_key(&ip);

        async fn assert_not_denied(
            limiter: &RedisRateLimiter,
            tenant: &TenantContext,
            identity: &nostr::PublicKey,
            ip: &IpAddr,
        ) {
            let outcome = limiter
                .peek_hierarchical_identity_denial(peek_request(tenant, identity, ip, 3))
                .await
                .expect("peek");
            assert_eq!(
                outcome,
                HierarchicalIdentityDenialPeekOutcome::NotDenied,
                "unproven state must not fast-deny"
            );
        }

        del(&pool, &identity_key).await;
        del(&pool, &fleet_key).await;
        seed_count(&pool, &fleet_key, 1, 30).await;
        assert_not_denied(&limiter, &tenant, &identity.public_key(), &ip).await;
        assert_identity_missing(&pool, &identity_key).await;

        seed_count(&pool, &fleet_key, 1, 30).await;
        let fleet_at = get_pexpiretime(&pool, &fleet_key).await;
        seed_count_pxat(&pool, &identity_key, 1, fleet_at).await;
        let before_i = get_raw(&pool, &identity_key).await;
        let before_f = get_raw(&pool, &fleet_key).await;
        let before_i_at = get_pexpiretime(&pool, &identity_key).await;
        let before_f_at = get_pexpiretime(&pool, &fleet_key).await;
        assert_not_denied(&limiter, &tenant, &identity.public_key(), &ip).await;
        assert_eq!(get_raw(&pool, &identity_key).await, before_i);
        assert_eq!(get_raw(&pool, &fleet_key).await, before_f);
        assert_eq!(get_pexpiretime(&pool, &identity_key).await, before_i_at);
        assert_eq!(get_pexpiretime(&pool, &fleet_key).await, before_f_at);

        del(&pool, &fleet_key).await;
        seed_count_pxat(&pool, &identity_key, 3, fleet_at).await;
        let before_i = get_raw(&pool, &identity_key).await;
        let before_i_at = get_pexpiretime(&pool, &identity_key).await;
        assert_not_denied(&limiter, &tenant, &identity.public_key(), &ip).await;
        assert_eq!(get_raw(&pool, &identity_key).await, before_i);
        assert_eq!(get_pexpiretime(&pool, &identity_key).await, before_i_at);
        assert_identity_missing(&pool, &fleet_key).await;

        persist_count(&pool, &identity_key, 3).await;
        seed_count(&pool, &fleet_key, 1, 30).await;
        assert_eq!(get_pttl(&pool, &identity_key).await, -1);
        let before_i = get_raw(&pool, &identity_key).await;
        let before_f_at = get_pexpiretime(&pool, &fleet_key).await;
        assert_not_denied(&limiter, &tenant, &identity.public_key(), &ip).await;
        assert_eq!(get_raw(&pool, &identity_key).await, before_i);
        assert_eq!(get_pttl(&pool, &identity_key).await, -1);
        assert_eq!(get_pexpiretime(&pool, &fleet_key).await, before_f_at);

        seed_count(&pool, &identity_key, 3, 60).await;
        seed_count(&pool, &fleet_key, 1, 30).await;
        assert_ne!(
            get_pexpiretime(&pool, &identity_key).await,
            get_pexpiretime(&pool, &fleet_key).await
        );
        let before_i_at = get_pexpiretime(&pool, &identity_key).await;
        let before_f_at = get_pexpiretime(&pool, &fleet_key).await;
        assert_not_denied(&limiter, &tenant, &identity.public_key(), &ip).await;
        assert_eq!(get_pexpiretime(&pool, &identity_key).await, before_i_at);
        assert_eq!(get_pexpiretime(&pool, &fleet_key).await, before_f_at);

        seed_raw(&pool, &identity_key, "0001", Some(30)).await;
        seed_count(&pool, &fleet_key, 1, 30).await;
        let before_i = get_raw(&pool, &identity_key).await;
        assert_not_denied(&limiter, &tenant, &identity.public_key(), &ip).await;
        assert_eq!(get_raw(&pool, &identity_key).await, before_i);

        seed_count(&pool, &identity_key, 3, 30).await;
        seed_raw(&pool, &fleet_key, "nope", Some(30)).await;
        let before_f = get_raw(&pool, &fleet_key).await;
        assert_not_denied(&limiter, &tenant, &identity.public_key(), &ip).await;
        assert_eq!(get_raw(&pool, &fleet_key).await, before_f);

        seed_count(&pool, &identity_key, 3, 30).await;
        persist_count(&pool, &fleet_key, 1).await;
        assert_eq!(get_pttl(&pool, &fleet_key).await, -1);
        assert_not_denied(&limiter, &tenant, &identity.public_key(), &ip).await;
        assert_eq!(get_pttl(&pool, &fleet_key).await, -1);

        del(&pool, &identity_key).await;
        del(&pool, &fleet_key).await;
        let mut conn = pool.get().await.expect("redis conn");
        let _: () = redis::cmd("RPUSH")
            .arg(&identity_key)
            .arg("x")
            .query_async(&mut *conn)
            .await
            .expect("wrong type");
        drop(conn);
        seed_count(&pool, &fleet_key, 1, 30).await;
        assert_not_denied(&limiter, &tenant, &identity.public_key(), &ip).await;
        assert_eq!(get_type(&pool, &identity_key).await, "list");
        del(&pool, &identity_key).await;
        del(&pool, &fleet_key).await;
    }

    #[tokio::test]
    #[ignore = "requires Redis"]
    async fn hierarchical_identity_peek_aligned_over_limit_denies_without_community_or_writes() {
        let Some(pool) = redis_pool().await else {
            panic!("local Redis not reachable");
        };
        let limiter = RedisRateLimiter::new(pool.clone());
        let tenant = unique_tenant();
        let identity = Keys::generate();
        let community = Keys::generate();
        let ip = unique_ip();
        let identity_key = rate_limit_key(
            &tenant,
            &identity.public_key(),
            &LimitType::KeyedHttpAttempts,
        );
        let community_key = rate_limit_key(
            &tenant,
            &community.public_key(),
            &LimitType::KeyedHttpAttempts,
        );
        let fleet_key = ip_rate_limit_key(&ip);
        del(&pool, &identity_key).await;
        del(&pool, &community_key).await;
        del(&pool, &fleet_key).await;
        seed_count(&pool, &fleet_key, 1, 30).await;
        let fleet_at = get_pexpiretime(&pool, &fleet_key).await;
        seed_count_pxat(&pool, &identity_key, 2, fleet_at).await;
        seed_count_pxat(&pool, &community_key, 7, fleet_at).await;
        assert_eq!(get_pexpiretime(&pool, &identity_key).await, fleet_at);
        let before_i = get_count(&pool, &identity_key).await;
        let before_c = get_count(&pool, &community_key).await;
        let before_f = get_count(&pool, &fleet_key).await;
        let before_pttl = get_pttl(&pool, &identity_key).await;
        let marker_key = format!("identity-peek-deny-monitor:{}", Uuid::new_v4());
        let start_marker = format!("start:{}", Uuid::new_v4());
        let end_marker = format!("end:{}", Uuid::new_v4());
        let quoted_identity = format!("\"{identity_key}\"");
        let quoted_community = format!("\"{community_key}\"");
        let quoted_fleet = format!("\"{fleet_key}\"");
        let quoted_marker = format!("\"{marker_key}\"");
        let quoted_start = format!("\"{start_marker}\"");
        let quoted_end = format!("\"{end_marker}\"");
        let url = std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".into());
        let client = match redis::Client::open(url) {
            Ok(client) => client,
            Err(_) => panic!("monitor client failed"),
        };
        let monitor = match tokio::time::timeout(
            std::time::Duration::from_secs(5),
            client.get_async_monitor(),
        )
        .await
        {
            Ok(Ok(monitor)) => monitor,
            Ok(Err(_)) => panic!("monitor unavailable"),
            Err(_) => panic!("monitor timed out"),
        };
        let messages = monitor.into_on_message::<String>();
        futures_util::pin_mut!(messages);
        {
            let mut conn = pool.get().await.expect("redis conn");
            let _: () = redis::cmd("SET")
                .arg(&marker_key)
                .arg(&start_marker)
                .arg("EX")
                .arg(30)
                .query_async(&mut *conn)
                .await
                .expect("start marker");
        }
        let denied = limiter
            .check_hierarchical_admission(hrequest(
                &tenant,
                &identity.public_key(),
                &community.public_key(),
                &ip,
                HierarchicalAdmissionLimits::new(2, 6, 10),
                30,
            ))
            .await
            .expect("aligned identity cap");
        {
            let mut conn = pool.get().await.expect("redis conn");
            let _: () = redis::cmd("SET")
                .arg(&marker_key)
                .arg(&end_marker)
                .arg("EX")
                .arg(30)
                .query_async(&mut *conn)
                .await
                .expect("end marker");
        }
        let capture = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            let mut started = false;
            let mut ended = false;
            let mut community_access: u32 = 0;
            let mut writes: u32 = 0;
            let mut lua_get_identity: u32 = 0;
            while let Some(line) = messages.next().await {
                if !started {
                    if line.contains("\"SET\"")
                        && line.contains(&quoted_marker)
                        && line.contains(&quoted_start)
                    {
                        started = true;
                    }
                    continue;
                }
                if line.contains("\"SET\"")
                    && line.contains(&quoted_marker)
                    && line.contains(&quoted_end)
                {
                    ended = true;
                    break;
                }
                if line.contains(&quoted_community) {
                    community_access = community_access.saturating_add(1);
                }
                let targets_key = line.contains(&quoted_identity)
                    || line.contains(&quoted_community)
                    || line.contains(&quoted_fleet);
                if targets_key && monitor_line_is_write(&line) {
                    writes = writes.saturating_add(1);
                }
                if monitor_line_is_lua(&line)
                    && line.contains(&quoted_identity)
                    && line.contains("\"GET\"")
                {
                    lua_get_identity = lua_get_identity.saturating_add(1);
                }
            }
            (started, ended, community_access, writes, lua_get_identity)
        })
        .await;
        let (started, ended, community_access, writes, lua_get_identity) = match capture {
            Ok(counts) => counts,
            Err(_) => panic!("identity peek deny monitor capture timed out"),
        };
        assert!(
            started,
            "identity peek deny monitor missed the start marker"
        );
        assert!(ended, "identity peek deny monitor missed the end marker");
        assert_eq!(
            community_access, 0,
            "fast identity denial must not access the community key"
        );
        assert_eq!(
            writes, 0,
            "fast identity denial must not write or move any deadline"
        );
        assert!(
            lua_get_identity >= 1,
            "fast identity denial must read the identity key"
        );
        match denied {
            HierarchicalAdmissionOutcome::IdentityDenied(result) => {
                assert!(!result.allowed);
                assert_eq!(result.current, 2);
                assert_eq!(result.limit, 2);
                let after_pttl = get_pttl(&pool, &identity_key).await;
                let min_reset = (after_pttl.max(0) as u64).div_ceil(1000);
                let max_reset = (before_pttl.max(0) as u64).div_ceil(1000);
                assert!(
                    result.reset_in_secs >= min_reset && result.reset_in_secs <= max_reset,
                    "reset {} not in [{min_reset}, {max_reset}] for pttl before={before_pttl} after={after_pttl}",
                    result.reset_in_secs
                );
            }
            other => panic!("expected identity denial, got {other:?}"),
        }
        assert_eq!(get_count(&pool, &identity_key).await, before_i);
        assert_eq!(get_count(&pool, &community_key).await, before_c);
        assert_eq!(get_count(&pool, &fleet_key).await, before_f);
        assert_eq!(get_pexpiretime(&pool, &identity_key).await, fleet_at);
        assert_eq!(get_pexpiretime(&pool, &community_key).await, fleet_at);
        assert_eq!(get_pexpiretime(&pool, &fleet_key).await, fleet_at);
        del(&pool, &identity_key).await;
        del(&pool, &community_key).await;
        del(&pool, &fleet_key).await;
        del(&pool, &marker_key).await;
    }

    #[tokio::test]
    #[ignore = "requires Redis"]
    async fn hierarchical_concurrent_already_denied_identities_allow_zero_and_do_not_mutate() {
        let Some(pool) = redis_pool().await else {
            panic!("local Redis not reachable");
        };
        let limiter = Arc::new(RedisRateLimiter::new(pool.clone()));
        let tenant = unique_tenant();
        let identity = Keys::generate();
        let community = Keys::generate();
        let ip = unique_ip();
        let identity_key = rate_limit_key(
            &tenant,
            &identity.public_key(),
            &LimitType::KeyedHttpAttempts,
        );
        let community_key = rate_limit_key(
            &tenant,
            &community.public_key(),
            &LimitType::KeyedHttpAttempts,
        );
        let fleet_key = ip_rate_limit_key(&ip);
        del(&pool, &identity_key).await;
        del(&pool, &community_key).await;
        del(&pool, &fleet_key).await;
        seed_count(&pool, &fleet_key, 4, 30).await;
        let fleet_at = get_pexpiretime(&pool, &fleet_key).await;
        seed_count_pxat(&pool, &identity_key, 2, fleet_at).await;
        seed_count_pxat(&pool, &community_key, 4, fleet_at).await;
        let before_i = get_count(&pool, &identity_key).await;
        let before_c = get_count(&pool, &community_key).await;
        let before_f = get_count(&pool, &fleet_key).await;
        let identity_pk = identity.public_key();
        let community_pk = community.public_key();
        let community_id = tenant.community();
        let host = tenant.host().to_owned();
        let mut joins = Vec::new();
        for _ in 0..40 {
            let limiter = Arc::clone(&limiter);
            let host = host.clone();
            joins.push(tokio::spawn(async move {
                let tenant = TenantContext::resolved(community_id, &host);
                limiter
                    .check_hierarchical_admission(hrequest(
                        &tenant,
                        &identity_pk,
                        &community_pk,
                        &ip,
                        HierarchicalAdmissionLimits::new(2, 6, 10),
                        30,
                    ))
                    .await
            }));
        }
        let mut allowed = 0u64;
        for join in joins {
            match join.await.expect("join").expect("hierarchical") {
                HierarchicalAdmissionOutcome::Allowed { .. } => allowed += 1,
                HierarchicalAdmissionOutcome::IdentityDenied(result) => {
                    assert!(!result.allowed);
                    assert_eq!(result.current, 2);
                    assert_eq!(result.limit, 2);
                }
                other => panic!("already-denied identity must stay identity-denied, got {other:?}"),
            }
        }
        assert_eq!(allowed, 0);
        assert_eq!(get_count(&pool, &identity_key).await, before_i);
        assert_eq!(get_count(&pool, &community_key).await, before_c);
        assert_eq!(get_count(&pool, &fleet_key).await, before_f);
        assert_eq!(get_pexpiretime(&pool, &identity_key).await, fleet_at);
        assert_eq!(get_pexpiretime(&pool, &community_key).await, fleet_at);
        assert_eq!(get_pexpiretime(&pool, &fleet_key).await, fleet_at);
        del(&pool, &identity_key).await;
        del(&pool, &community_key).await;
        del(&pool, &fleet_key).await;
    }

    #[tokio::test]
    #[ignore = "requires Redis"]
    async fn hierarchical_identity_peek_fallthrough_allow_increments_each_key_once() {
        let Some(pool) = redis_pool().await else {
            panic!("local Redis not reachable");
        };
        let limiter = RedisRateLimiter::new(pool.clone());
        let tenant = unique_tenant();
        let identity = Keys::generate();
        let community = Keys::generate();
        let ip = unique_ip();
        let identity_key = rate_limit_key(
            &tenant,
            &identity.public_key(),
            &LimitType::KeyedHttpAttempts,
        );
        let community_key = rate_limit_key(
            &tenant,
            &community.public_key(),
            &LimitType::KeyedHttpAttempts,
        );
        let fleet_key = ip_rate_limit_key(&ip);
        del(&pool, &identity_key).await;
        del(&pool, &community_key).await;
        del(&pool, &fleet_key).await;
        seed_count(&pool, &fleet_key, 1, 30).await;
        let fleet_at = get_pexpiretime(&pool, &fleet_key).await;
        seed_count_pxat(&pool, &identity_key, 1, fleet_at).await;
        seed_count_pxat(&pool, &community_key, 1, fleet_at).await;
        let peek = limiter
            .peek_hierarchical_identity_denial(peek_request(
                &tenant,
                &identity.public_key(),
                &ip,
                3,
            ))
            .await
            .expect("peek");
        assert_eq!(peek, HierarchicalIdentityDenialPeekOutcome::NotDenied);
        let outcome = limiter
            .check_hierarchical_admission(hrequest(
                &tenant,
                &identity.public_key(),
                &community.public_key(),
                &ip,
                HierarchicalAdmissionLimits::new(3, 6, 10),
                30,
            ))
            .await
            .expect("hierarchical");
        match outcome {
            HierarchicalAdmissionOutcome::Allowed {
                identity,
                community,
                fleet,
            } => {
                assert_eq!(identity.current, 2);
                assert_eq!(community.current, 2);
                assert_eq!(fleet.current, 2);
            }
            other => panic!("under-limit fallthrough must allow once, got {other:?}"),
        }
        assert_eq!(get_count(&pool, &identity_key).await, 2);
        assert_eq!(get_count(&pool, &community_key).await, 2);
        assert_eq!(get_count(&pool, &fleet_key).await, 2);
        assert_eq!(get_pexpiretime(&pool, &fleet_key).await, fleet_at);
        assert_exact_shared_deadline_3(&pool, &identity_key, &community_key, &fleet_key).await;
        del(&pool, &identity_key).await;
        del(&pool, &community_key).await;
        del(&pool, &fleet_key).await;
    }

    #[tokio::test]
    #[ignore = "requires Redis"]
    async fn hierarchical_community_and_fleet_denial_remain_authoritative_after_identity_peek() {
        let Some(pool) = redis_pool().await else {
            panic!("local Redis not reachable");
        };
        let limiter = RedisRateLimiter::new(pool.clone());
        let tenant = unique_tenant();
        let identity = Keys::generate();
        let community = Keys::generate();
        let ip = unique_ip();
        let identity_key = rate_limit_key(
            &tenant,
            &identity.public_key(),
            &LimitType::KeyedHttpAttempts,
        );
        let community_key = rate_limit_key(
            &tenant,
            &community.public_key(),
            &LimitType::KeyedHttpAttempts,
        );
        let fleet_key = ip_rate_limit_key(&ip);
        del(&pool, &identity_key).await;
        del(&pool, &community_key).await;
        del(&pool, &fleet_key).await;
        seed_count(&pool, &fleet_key, 1, 30).await;
        let fleet_at = get_pexpiretime(&pool, &fleet_key).await;
        seed_count_pxat(&pool, &identity_key, 1, fleet_at).await;
        seed_count_pxat(&pool, &community_key, 3, fleet_at).await;
        let before_i = get_count(&pool, &identity_key).await;
        let before_c = get_count(&pool, &community_key).await;
        let before_f = get_count(&pool, &fleet_key).await;
        let community_denied = limiter
            .check_hierarchical_admission(hrequest(
                &tenant,
                &identity.public_key(),
                &community.public_key(),
                &ip,
                HierarchicalAdmissionLimits::new(3, 3, 10),
                30,
            ))
            .await
            .expect("community cap");
        assert!(
            matches!(
                community_denied,
                HierarchicalAdmissionOutcome::CommunityDenied(ref result) if !result.allowed
            ),
            "got {community_denied:?}"
        );
        assert_eq!(get_count(&pool, &identity_key).await, before_i);
        assert_eq!(get_count(&pool, &community_key).await, before_c);
        assert_eq!(get_count(&pool, &fleet_key).await, before_f);
        assert_eq!(get_pexpiretime(&pool, &identity_key).await, fleet_at);
        assert_eq!(get_pexpiretime(&pool, &community_key).await, fleet_at);
        assert_eq!(get_pexpiretime(&pool, &fleet_key).await, fleet_at);

        del(&pool, &identity_key).await;
        seed_count_pxat(&pool, &community_key, 1, fleet_at).await;
        seed_count_pxat(&pool, &fleet_key, 5, fleet_at).await;
        let before_c = get_count(&pool, &community_key).await;
        let before_f = get_count(&pool, &fleet_key).await;
        let fleet_denied = limiter
            .check_hierarchical_admission(hrequest(
                &tenant,
                &identity.public_key(),
                &community.public_key(),
                &ip,
                HierarchicalAdmissionLimits::new(3, 6, 5),
                30,
            ))
            .await
            .expect("fleet cap");
        assert!(
            matches!(
                fleet_denied,
                HierarchicalAdmissionOutcome::FleetDenied(ref result) if !result.allowed
            ),
            "got {fleet_denied:?}"
        );
        assert_identity_missing(&pool, &identity_key).await;
        assert_eq!(get_count(&pool, &community_key).await, before_c);
        assert_eq!(get_count(&pool, &fleet_key).await, before_f);
        assert_eq!(get_pexpiretime(&pool, &community_key).await, fleet_at);
        assert_eq!(get_pexpiretime(&pool, &fleet_key).await, fleet_at);
        del(&pool, &identity_key).await;
        del(&pool, &community_key).await;
        del(&pool, &fleet_key).await;
    }

    #[tokio::test]
    #[ignore = "requires Redis"]
    async fn hierarchical_persistent_corrupt_fleet_is_quarantined_once_without_touching_counters() {
        let Some(pool) = redis_pool().await else {
            panic!("local Redis not reachable");
        };
        let limiter = RedisRateLimiter::new(pool.clone());
        let cases: &[(&str, &str, &str)] = &[
            ("garbage", "nope", "string"),
            ("negative", "-5", "string"),
            ("overflow", "9223372036854775808", "string"),
            ("leading-zero", "0001", "string"),
            ("fractional", "1.2", "string"),
        ];
        for (label, value, expected_type) in cases {
            let tenant = unique_tenant();
            let identity = Keys::generate();
            let community = Keys::generate();
            let ip = unique_ip();
            let identity_key = rate_limit_key(
                &tenant,
                &identity.public_key(),
                &LimitType::KeyedHttpAttempts,
            );
            let community_key = rate_limit_key(
                &tenant,
                &community.public_key(),
                &LimitType::KeyedHttpAttempts,
            );
            let fleet_key = ip_rate_limit_key(&ip);
            del(&pool, &identity_key).await;
            del(&pool, &community_key).await;
            del(&pool, &fleet_key).await;
            seed_count(&pool, &identity_key, 1, 30).await;
            seed_count(&pool, &community_key, 1, 30).await;
            seed_raw(&pool, &fleet_key, value, None).await;
            assert_eq!(get_pttl(&pool, &fleet_key).await, -1, "{label}");
            let before_i = get_raw(&pool, &identity_key).await;
            let before_c = get_raw(&pool, &community_key).await;
            let before_f = get_raw(&pool, &fleet_key).await;
            let before_i_at = get_pexpiretime(&pool, &identity_key).await;
            let before_c_at = get_pexpiretime(&pool, &community_key).await;
            let err = limiter
                .check_hierarchical_admission(hrequest(
                    &tenant,
                    &identity.public_key(),
                    &community.public_key(),
                    &ip,
                    HierarchicalAdmissionLimits::new(3, 6, 10),
                    30,
                ))
                .await
                .expect_err(label);
            assert!(
                err.to_string().contains("corrupt"),
                "{label} must fail closed as corrupt, got {err}"
            );
            assert_eq!(get_raw(&pool, &identity_key).await, before_i, "{label}");
            assert_eq!(get_raw(&pool, &community_key).await, before_c, "{label}");
            assert_eq!(get_raw(&pool, &fleet_key).await, before_f, "{label}");
            assert_eq!(get_type(&pool, &fleet_key).await, *expected_type, "{label}");
            assert_eq!(
                get_pexpiretime(&pool, &identity_key).await,
                before_i_at,
                "{label}"
            );
            assert_eq!(
                get_pexpiretime(&pool, &community_key).await,
                before_c_at,
                "{label}"
            );
            let quarantined = get_pttl(&pool, &fleet_key).await;
            assert!(
                quarantined > 0 && quarantined <= 30_050,
                "{label} persistent corrupt fleet must gain one finite quarantine TTL, pttl={quarantined}"
            );
            let first_at = get_pexpiretime(&pool, &fleet_key).await;
            limiter
                .check_hierarchical_admission(hrequest(
                    &tenant,
                    &identity.public_key(),
                    &community.public_key(),
                    &ip,
                    HierarchicalAdmissionLimits::new(3, 6, 10),
                    30,
                ))
                .await
                .expect_err("second corrupt request");
            assert_eq!(get_raw(&pool, &fleet_key).await, before_f, "{label}");
            assert_eq!(
                get_pexpiretime(&pool, &fleet_key).await,
                first_at,
                "{label} second request must not extend quarantine"
            );
            del(&pool, &identity_key).await;
            del(&pool, &community_key).await;
            del(&pool, &fleet_key).await;
        }

        let tenant = unique_tenant();
        let identity = Keys::generate();
        let community = Keys::generate();
        let ip = unique_ip();
        let identity_key = rate_limit_key(
            &tenant,
            &identity.public_key(),
            &LimitType::KeyedHttpAttempts,
        );
        let community_key = rate_limit_key(
            &tenant,
            &community.public_key(),
            &LimitType::KeyedHttpAttempts,
        );
        let fleet_key = ip_rate_limit_key(&ip);
        del(&pool, &identity_key).await;
        del(&pool, &community_key).await;
        del(&pool, &fleet_key).await;
        seed_count(&pool, &identity_key, 1, 30).await;
        seed_count(&pool, &community_key, 1, 30).await;
        let mut conn = pool.get().await.expect("redis conn");
        let _: () = redis::cmd("RPUSH")
            .arg(&fleet_key)
            .arg("x")
            .query_async(&mut *conn)
            .await
            .expect("wrong type");
        drop(conn);
        assert_eq!(get_pttl(&pool, &fleet_key).await, -1);
        let before_i = get_raw(&pool, &identity_key).await;
        let before_c = get_raw(&pool, &community_key).await;
        let before_i_at = get_pexpiretime(&pool, &identity_key).await;
        let before_c_at = get_pexpiretime(&pool, &community_key).await;
        let err = limiter
            .check_hierarchical_admission(hrequest(
                &tenant,
                &identity.public_key(),
                &community.public_key(),
                &ip,
                HierarchicalAdmissionLimits::new(3, 6, 10),
                30,
            ))
            .await
            .expect_err("wrongtype fleet");
        assert!(
            err.to_string().contains("corrupt"),
            "WRONGTYPE fleet must fail closed as corrupt, got {err}"
        );
        assert_eq!(get_raw(&pool, &identity_key).await, before_i);
        assert_eq!(get_raw(&pool, &community_key).await, before_c);
        assert_eq!(get_type(&pool, &fleet_key).await, "list");
        let mut conn = pool.get().await.expect("redis conn");
        let members: Vec<String> = redis::cmd("LRANGE")
            .arg(&fleet_key)
            .arg(0)
            .arg(-1)
            .query_async(&mut *conn)
            .await
            .expect("lrange");
        drop(conn);
        assert_eq!(members, vec!["x".to_string()]);
        assert_eq!(get_pexpiretime(&pool, &identity_key).await, before_i_at);
        assert_eq!(get_pexpiretime(&pool, &community_key).await, before_c_at);
        let quarantined = get_pttl(&pool, &fleet_key).await;
        assert!(
            quarantined > 0 && quarantined <= 30_050,
            "WRONGTYPE persistent fleet must gain one finite quarantine TTL, pttl={quarantined}"
        );
        let first_at = get_pexpiretime(&pool, &fleet_key).await;
        limiter
            .check_hierarchical_admission(hrequest(
                &tenant,
                &identity.public_key(),
                &community.public_key(),
                &ip,
                HierarchicalAdmissionLimits::new(3, 6, 10),
                30,
            ))
            .await
            .expect_err("second wrongtype");
        assert_eq!(get_type(&pool, &fleet_key).await, "list");
        assert_eq!(
            get_pexpiretime(&pool, &fleet_key).await,
            first_at,
            "second WRONGTYPE request must not extend quarantine"
        );
        del(&pool, &identity_key).await;
        del(&pool, &community_key).await;
        del(&pool, &fleet_key).await;
    }

    #[tokio::test]
    #[ignore = "requires Redis"]
    async fn hierarchical_corrupt_fleet_finite_ttl_and_expiry_restore_ordinary_window() {
        let Some(pool) = redis_pool().await else {
            panic!("local Redis not reachable");
        };
        let limiter = RedisRateLimiter::new(pool.clone());
        let tenant = unique_tenant();
        let identity = Keys::generate();
        let community = Keys::generate();
        let ip = unique_ip();
        let identity_key = rate_limit_key(
            &tenant,
            &identity.public_key(),
            &LimitType::KeyedHttpAttempts,
        );
        let community_key = rate_limit_key(
            &tenant,
            &community.public_key(),
            &LimitType::KeyedHttpAttempts,
        );
        let fleet_key = ip_rate_limit_key(&ip);
        del(&pool, &identity_key).await;
        del(&pool, &community_key).await;
        del(&pool, &fleet_key).await;
        seed_count(&pool, &identity_key, 1, 30).await;
        seed_count(&pool, &community_key, 1, 30).await;
        seed_raw(&pool, &fleet_key, "nope", Some(30)).await;
        let finite_at = get_pexpiretime(&pool, &fleet_key).await;
        assert!(finite_at > 0);
        let before_f = get_raw(&pool, &fleet_key).await;
        limiter
            .check_hierarchical_admission(hrequest(
                &tenant,
                &identity.public_key(),
                &community.public_key(),
                &ip,
                HierarchicalAdmissionLimits::new(3, 6, 10),
                30,
            ))
            .await
            .expect_err("finite-ttl corrupt fleet");
        assert_eq!(get_raw(&pool, &fleet_key).await, before_f);
        assert_eq!(
            get_pexpiretime(&pool, &fleet_key).await,
            finite_at,
            "finite-TTL corruption must keep its exact deadline"
        );

        persist_count(&pool, &identity_key, 1).await;
        persist_count(&pool, &community_key, 1).await;
        seed_raw(&pool, &fleet_key, "nope", None).await;
        limiter
            .check_hierarchical_admission(hrequest(
                &tenant,
                &identity.public_key(),
                &community.public_key(),
                &ip,
                HierarchicalAdmissionLimits::new(3, 6, 10),
                30,
            ))
            .await
            .expect_err("quarantine");
        assert!(get_pttl(&pool, &fleet_key).await > 0);
        del(&pool, &fleet_key).await;
        assert_eq!(get_pttl(&pool, &fleet_key).await, -2);
        let allowed = limiter
            .check_hierarchical_admission(hrequest(
                &tenant,
                &identity.public_key(),
                &community.public_key(),
                &ip,
                HierarchicalAdmissionLimits::new(3, 6, 10),
                30,
            ))
            .await
            .expect("fresh window after expiry");
        match allowed {
            HierarchicalAdmissionOutcome::Allowed {
                identity,
                community,
                fleet,
            } => {
                assert_eq!(identity.current, 1);
                assert_eq!(community.current, 1);
                assert_eq!(fleet.current, 1);
            }
            other => panic!("expired corrupt fleet must open 1/1/1, got {other:?}"),
        }
        assert_eq!(get_count(&pool, &identity_key).await, 1);
        assert_eq!(get_count(&pool, &community_key).await, 1);
        assert_eq!(get_count(&pool, &fleet_key).await, 1);
        assert_exact_shared_deadline_3(&pool, &identity_key, &community_key, &fleet_key).await;
        let window_ms = 30_050;
        assert!(
            get_pttl(&pool, &fleet_key).await > 0 && get_pttl(&pool, &fleet_key).await <= window_ms
        );
        del(&pool, &identity_key).await;
        del(&pool, &community_key).await;
        del(&pool, &fleet_key).await;
    }

    #[tokio::test]
    #[ignore = "requires Redis"]
    async fn hierarchical_healthy_identity_community_corruption_does_not_quarantine_healthy_fleet()
    {
        let Some(pool) = redis_pool().await else {
            panic!("local Redis not reachable");
        };
        let limiter = RedisRateLimiter::new(pool.clone());
        let tenant = unique_tenant();
        let identity = Keys::generate();
        let community = Keys::generate();
        let ip = unique_ip();
        let identity_key = rate_limit_key(
            &tenant,
            &identity.public_key(),
            &LimitType::KeyedHttpAttempts,
        );
        let community_key = rate_limit_key(
            &tenant,
            &community.public_key(),
            &LimitType::KeyedHttpAttempts,
        );
        let fleet_key = ip_rate_limit_key(&ip);
        del(&pool, &identity_key).await;
        del(&pool, &community_key).await;
        del(&pool, &fleet_key).await;
        seed_raw(&pool, &identity_key, "nope", Some(30)).await;
        seed_count(&pool, &community_key, 1, 30).await;
        persist_count(&pool, &fleet_key, 3).await;
        assert_eq!(get_pttl(&pool, &fleet_key).await, -1);
        let before_f = get_raw(&pool, &fleet_key).await;
        let before_i = get_raw(&pool, &identity_key).await;
        limiter
            .check_hierarchical_admission(hrequest(
                &tenant,
                &identity.public_key(),
                &community.public_key(),
                &ip,
                HierarchicalAdmissionLimits::new(3, 6, 10),
                30,
            ))
            .await
            .expect_err("corrupt identity");
        assert_eq!(get_raw(&pool, &identity_key).await, before_i);
        assert_eq!(get_raw(&pool, &fleet_key).await, before_f);
        assert_eq!(
            get_pttl(&pool, &fleet_key).await,
            -1,
            "healthy persistent fleet must not be quarantined for identity corruption"
        );

        del(&pool, &identity_key).await;
        seed_count(&pool, &identity_key, 1, 30).await;
        seed_raw(&pool, &community_key, "1.2", Some(30)).await;
        seed_count(&pool, &fleet_key, 4, 30).await;
        let before_f = get_raw(&pool, &fleet_key).await;
        let before_f_at = get_pexpiretime(&pool, &fleet_key).await;
        let before_c = get_raw(&pool, &community_key).await;
        limiter
            .check_hierarchical_admission(hrequest(
                &tenant,
                &identity.public_key(),
                &community.public_key(),
                &ip,
                HierarchicalAdmissionLimits::new(3, 6, 10),
                30,
            ))
            .await
            .expect_err("corrupt community");
        assert_eq!(get_raw(&pool, &community_key).await, before_c);
        assert_eq!(get_raw(&pool, &fleet_key).await, before_f);
        assert_absolute_deadline_unmoved(
            "healthy fleet",
            before_f_at,
            get_pexpiretime(&pool, &fleet_key).await,
        );
        del(&pool, &identity_key).await;
        del(&pool, &community_key).await;
        del(&pool, &fleet_key).await;
    }
}
