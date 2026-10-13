# Maintained YAML dependencies

The root Rust workspace uses serde-saphyr 1.3 for workflow definitions, persona frontmatter and agent skill discovery. Kube 4.2 uses its maintained parser internally. The root minimum supported Rust version is 1.89; the pinned 1.95 toolchain satisfies it. The separate desktop workspace still uses its own YAML dependency and is not covered by this change.

Application parsers explicitly retain YAML 1.2-style boolean handling, ordinary `<<` keys (no implicit merge expansion), and literal strings for `!!binary`. Anchors still resolve normally. Source snippets are disabled in parser errors so neighboring configuration values are not copied into diagnostics. Typed parsing is preserved; values are not converted through strings or a JSON intermediate. Skill discovery and advisory validation ignore unknown YAML extension fields, including sequence-key mappings, while requiring string names. The maintained parser rejects duplicate keys and has bounded parser/alias resources. Inputs exceeding those limits and non-finite values in untyped or ignored skill fields are rejected rather than silently coerced. Tests exercise the real consumer entry points and existing errors remain failures.

## Kubernetes compatibility

Kube 4.2 requires k8s-openapi 0.28, whose earliest schema feature is `v1_32`. This changes the generated model selection from 1.31 to 1.32. The provider continues using core v1 Pod, Secret and Namespace APIs; the selected schema is not evidence of a live cluster's version or compatibility. Validate against the intended cluster before deployment. Synthetic API tests preserve requests, ownership fences and exact reason-based error decisions. Jiff timestamps are converted by epoch nanoseconds for the existing Chrono-based server-clock garbage-collection decision, including subsecond and pre-epoch boundaries.

## Mesh manifest backport

`third_party/mesh-llm` contains the exact host-runtime source from Mesh v0.75.1, revision `3295c902d4c4f859aaadf9240042ffdaf06dd07e`, with its original license and referenced test documentation. Only Cargo metadata changes: inherited package/lint fields are expanded, sibling dependencies resolve to the original Git tag, and an unused `serde_yaml` declaration is removed. There are no Rust source changes. The root Git-source patch selects this crate for both direct and SDK transitive use.

Run `python3 scripts/verify-mesh-host-runtime-upstream.py` to verify every upstream file and the complete allowed manifest transformation. CI runs this before dependency policy. `UPSTREAM.json` records source hashes; `Cargo.toml.upstream` retains the original manifest. Updating the vendor requires a fresh provenance review and consumer compilation. No advisory is ignored.

Stable Mesh 0.76+ cannot currently replace this backport without additional integration work: its rusqlite 0.40 requires libsqlite3-sys 0.38, while SQLx 0.9's supported native link range ends below 0.38. Retain the narrow backport until compatible maintained upstream versions can replace it. Full native inference and live cluster deployment remain separate operational validation.
