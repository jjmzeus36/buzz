#!/usr/bin/env bash
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/bin"
cat > "$tmp/bin/rustc" <<'SH'
#!/usr/bin/env bash
echo 'host: aarch64-apple-darwin'
SH
chmod +x "$tmp/bin/rustc"
export PATH="$tmp/bin:$PATH"
cd "$tmp"
bins=(buzz-acp buzz-agent buzz-dev-mcp git-credential-nostr buzz buzz-backend-kubernetes)
mkdir -p target/release desktop/src-tauri/binaries
for bin in "${bins[@]}"; do
    printf '#!/usr/bin/env bash\necho fixture-%s\n' "$bin" > "target/release/$bin"
done
# A compile-check placeholder must not be accepted as a packaged sidecar.
: > target/release/buzz
printf 'preserve' > desktop/src-tauri/binaries/buzz-acp-aarch64-apple-darwin
if bash "$root/scripts/bundle-sidecars.sh" > error.log 2>&1; then
    echo 'bundler accepted an empty sidecar' >&2; exit 1
fi
grep -q 'missing or empty release binaries' error.log
[[ $(cat desktop/src-tauri/binaries/buzz-acp-aarch64-apple-darwin) == preserve ]]
printf '#!/usr/bin/env bash\necho fixture-buzz\n' > target/release/buzz
bash "$root/scripts/bundle-sidecars.sh"
for bin in "${bins[@]}"; do
    destination="desktop/src-tauri/binaries/$bin-aarch64-apple-darwin"
    cmp "target/release/$bin" "$destination"
    [[ -x "$destination" ]]
done
# Explicit targets use their qualified source directory and Windows omits
# the Kubernetes backend while preserving the .exe extension.
target=x86_64-pc-windows-msvc
mkdir -p "target/$target/release"
for bin in "${bins[@]:0:5}"; do
    printf 'windows-%s' "$bin" > "target/$target/release/$bin.exe"
done
bash "$root/scripts/bundle-sidecars.sh" "$target"
for bin in "${bins[@]:0:5}"; do
    cmp "target/$target/release/$bin.exe" "desktop/src-tauri/binaries/$bin-$target.exe"
done
[[ ! -e "desktop/src-tauri/binaries/buzz-backend-kubernetes-$target.exe" ]]
# Keep compile-only Rust stubs separate from the workflow that packages apps.
! grep -q 'Create sidecar placeholders' "$root/.github/workflows/_ci-desktop-macos.yml"
grep -q './scripts/bundle-sidecars.sh' "$root/.github/workflows/_ci-desktop-macos.yml"
echo 'sidecar bundling contract passed'
