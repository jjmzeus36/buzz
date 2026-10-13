import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";

const root = new URL("../desktop/src-tauri/vendor/neteq/", import.meta.url);
const provenance = JSON.parse(readFileSync(new URL("UPSTREAM.json", root), "utf8"));
const hash = (bytes) => createHash("sha256").update(bytes).digest("hex");

for (const [name, expected] of Object.entries(provenance.upstream_files_sha256)) {
  const localName = name === "Cargo.toml" ? "Cargo.toml.upstream" : name;
  assert.equal(hash(readFileSync(new URL(localName, root))), expected, localName);
}

const upstream = readFileSync(new URL("Cargo.toml.upstream", root), "utf8");
const unusedDependency = '[dependencies.ringbuf]\nversion = "0.3"\n\n';
assert.equal(upstream.split(unusedDependency).length, 2);
const manifest = readFileSync(new URL("Cargo.toml", root), "utf8");
assert.equal(manifest, upstream.replace(unusedDependency, ""));
assert.equal(hash(Buffer.from(manifest)), provenance.patched_manifest_sha256);
console.log("NetEq 0.8.3 upstream source and sole unused-dependency patch verified");
