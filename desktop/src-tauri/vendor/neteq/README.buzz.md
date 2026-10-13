# Buzz's NetEq source copy

This is the published `neteq` 0.8.3 crate, verified against the crates.io SHA-256
recorded in `UPSTREAM.json`. Its `.cargo_vcs_info.json` identifies upstream commit
`fcf644253bf3113b79dda9111052e8463a8c68b0` in
<https://github.com/security-union/videocall-rs>. The MIT and Apache licenses were
copied from that same revision because the published archive omits them.

All Rust source files are byte-identical to the published package. The sole
manifest patch removes the unused `ringbuf = "0.3"` dependency. No source file
references that crate. The dependency brings in
[RUSTSEC-2026-0293](https://rustsec.org/advisories/RUSTSEC-2026-0293.html), whose
fixed version is incompatible with NetEq's published requirement. Even NetEq
0.9.1 still requests `ringbuf ^0.3`; changing audio algorithms or blindly
overriding a semver-incompatible dependency is unnecessary here.

`Cargo.toml.upstream` preserves the original normalized manifest;
`remove-unused-ringbuf.patch` records the complete patch. The original generated
`Cargo.lock` is omitted: Buzz's desktop workspace lockfile resolves this path
dependency. Standalone upstream tests may generate their own ignored lockfile.

Run `node scripts/verify-vendored-neteq.mjs` from the repository root to verify
every upstream file and the exact manifest change without network access.
Validate updates with the upstream tests (`cargo test --manifest-path
desktop/src-tauri/vendor/neteq/Cargo.toml --no-default-features`) and Buzz's
native huddle jitter tests. Keep default features disabled, matching Buzz's
existing Opus decoder adapter. Remove this source copy when a compatible
upstream release drops or fixes the dependency and the same audio tests pass.
