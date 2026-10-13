#!/usr/bin/env python3
"""Execute production helper recipes with isolated command/container fixtures."""

import argparse
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


SOURCE_ROOT = Path(__file__).resolve().parent.parent
JUST = os.environ.get("BUZZ_HELPER_TEST_JUST", "just")
BASH = os.environ.get("BUZZ_HELPER_TEST_BASH", "bash")
SIDECARS = ["buzz-acp", "buzz-agent", "buzz-dev-mcp", "git-credential-nostr", "buzz"]

DOCKER = r"""#!/usr/bin/env bash
set -euo pipefail
case "$1" in
  compose)
    echo "compose:$*" >> "$TEST_LOG"
    if [[ "$*" == *--force-recreate* && "$*" == *minio-init* ]]; then
      [[ "$*" == *--no-deps* ]] || exit 99
      echo init-start >> "$TEST_LOG"
      : > "$TEST_STATE/init-started"
      rm -f "$TEST_STATE/init-polled"
    elif [[ "${!#}" == minio ]]; then
      [[ "$TEST_CASE" != compose-failed ]] || exit 1
      echo s3-up >> "$TEST_LOG"
      : > "$TEST_STATE/s3-started"
    else
      : > "$TEST_STATE/core-started"
    fi
    ;;
  inspect)
    case "${!#}" in
      buzz-postgres|buzz-redis)
        if [[ "$TEST_CASE" == core-cold && ! -f "$TEST_STATE/core-started" ]]; then
          exit 1
        fi
        echo healthy
        ;;
      buzz-minio)
        echo s3-health >> "$TEST_LOG"
        if [[ "$TEST_CASE" == minio-unhealthy || ! -f "$TEST_STATE/s3-started" ]]; then
          echo starting
        else
          echo healthy
        fi
        ;;
      buzz-minio-init)
        [[ -f "$TEST_STATE/init-started" ]] || exit 1
        if [[ "$TEST_CASE" == init-running || ! -f "$TEST_STATE/init-polled" ]]; then
          : > "$TEST_STATE/init-polled"
          echo init-running >> "$TEST_LOG"
          echo 'running 0'
        elif [[ "$TEST_CASE" == init-failed ]]; then
          echo init-failed >> "$TEST_LOG"
          echo 'exited 1'
        else
          echo init-success >> "$TEST_LOG"
          echo 'exited 0'
        fi
        ;;
      *) exit 99 ;;
    esac
    ;;
  logs) echo diagnostics >> "$TEST_LOG" ;;
  *) exit 99 ;;
esac
"""

CARGO = r"""#!/usr/bin/env bash
set -euo pipefail
echo "cargo:$*" >> "$TEST_LOG"
[[ "$TEST_CASE" != cargo-failed ]] || exit 9
packages=()
target=""
while (( $# )); do
  case "$1" in
    --target) target="$2"; shift 2 ;;
    -p) packages+=("$2"); shift 2 ;;
    *) shift ;;
  esac
done
[[ -n "$target" && ${#packages[@]} -gt 0 ]] || exit 99
mkdir -p "target/$target/release"
for package in "${packages[@]}"; do
  binary="$package"
  [[ "$binary" != buzz-cli ]] || binary=buzz
  extension=""
  [[ "$target" != *windows* ]] || extension=.exe
  output="target/$target/release/$binary$extension"
  printf 'built-%s' "$binary" > "$output"
  if [[ "$TEST_CASE" == empty-buzz && "$binary" == buzz ]]; then : > "$output"; fi
done
"""


class HelperContracts(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="buzz-helper-contract-")
        self.addCleanup(self.temporary.cleanup)
        self.fixture = Path(self.temporary.name)
        for directory in ["bin", "scripts", "desktop", "state"]:
            (self.fixture / directory).mkdir()
        for name in [
            "bundle-sidecars.sh",
            "ensure-s3-fixture.sh",
            "start-relay-for-tests.sh",
        ]:
            source = SOURCE_ROOT / "scripts" / name
            if source.exists():
                shutil.copyfile(source, self.fixture / "scripts" / name)
        self.write("bin/docker", DOCKER)
        self.write("bin/cargo", CARGO)
        self.write("bin/rustc", "#!/usr/bin/env bash\necho 'host: aarch64-apple-darwin'\n")
        self.write("bin/pnpm", '#!/usr/bin/env bash\necho "pnpm:$*" >> "$TEST_LOG"\n')
        self.write("bin/sleep", '#!/usr/bin/env bash\necho sleep >> "$TEST_LOG"\n')
        self.write("bin/pgschema", '#!/usr/bin/env bash\necho schema >> "$TEST_LOG"\nexit 70\n')
        # Shell functions keep polling deterministic without spawning hundreds
        # of fake executables; PATH stubs also prevent a real-command fallback.
        functions = []
        for command in ["docker", "cargo", "pnpm", "sleep", "rustc"]:
            body = (self.fixture / "bin" / command).read_text().split("\n", 1)[1]
            body = body.replace("exit ", "return ")
            functions.append(f"{command}() {{\n{body}\n}}\n")
        shell_environment = self.write("shell-environment.sh", "".join(functions))
        self.log_path = self.fixture / "events"
        self.environment = {
            **os.environ,
            "PATH": str(self.fixture / "bin") + os.pathsep + os.environ["PATH"],
            "TEST_LOG": self.log_path.as_posix(),
            "TEST_STATE": (self.fixture / "state").as_posix(),
            "TEST_CASE": "success",
            "BASH_ENV": shell_environment.as_posix(),
        }

    def write(self, name, text):
        path = self.fixture / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8", newline="\n")
        path.chmod(0o755)
        return path

    def events(self):
        return self.log_path.read_text(encoding="utf-8").splitlines() if self.log_path.exists() else []

    def run_script(self, script, case="success"):
        return subprocess.run(
            [BASH, script.as_posix()],
            cwd=self.fixture,
            env={**self.environment, "TEST_CASE": case},
            capture_output=True,
            text=True,
            timeout=20,
        )

    def run_recipe(self, recipe, case="success", target=None):
        command = [
            JUST, "--no-dotenv", "--justfile", str(SOURCE_ROOT / "Justfile"),
            "--working-directory", str(self.fixture), "--dry-run", recipe,
        ]
        if target:
            command.append(target)
        rendered = subprocess.run(command, capture_output=True, text=True, timeout=20)
        self.assertEqual(rendered.returncode, 0, rendered.stderr)
        script = rendered.stderr or rendered.stdout
        self.assertTrue(script.startswith("#!"), script)
        return self.run_script(self.write("recipe.sh", script), case)

    def assert_initialized(self):
        events = self.events()
        self.assertIn("s3-up", events)
        self.assertIn("init-start", events)
        self.assertIn("init-running", events)
        self.assertIn("init-success", events)
        self.assertLess(events.index("s3-up"), events.index("s3-health"))
        self.assertLess(events.index("s3-health"), events.index("init-start"))
        self.assertLess(events.index("init-start"), events.index("init-success"))

    def test_healthy_core_still_starts_s3_and_reinitializes_each_time(self):
        for _ in range(2):
            result = self.run_recipe("_ensure-services")
            self.assertEqual(result.returncode, 0, result.stderr)
        self.assert_initialized()
        self.assertEqual(self.events().count("init-start"), 2)
        self.assertEqual(self.events().count("init-success"), 2)

    def test_cold_core_also_requires_initializer(self):
        result = self.run_recipe("_ensure-services", "core-cold")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assert_initialized()

    def test_failed_initializer_fails_setup(self):
        result = self.run_recipe("_ensure-services", "init-failed")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("init-failed", self.events())

    def test_running_initializer_times_out(self):
        result = self.run_recipe("_ensure-services", "init-running")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("did not finish", result.stderr)
        self.assertEqual(self.events().count("init-running"), 60)

    def test_unhealthy_s3_times_out_before_initializer(self):
        result = self.run_recipe("_ensure-services", "minio-unhealthy")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.events().count("s3-health"), 60)
        self.assertNotIn("init-start", self.events())

    def test_s3_reconciliation_failure_propagates(self):
        result = self.run_recipe("_ensure-services", "compose-failed")
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("init-start", self.events())

    def test_relay_start_stops_before_schema_on_initializer_failure(self):
        result = self.run_script(self.fixture / "scripts/start-relay-for-tests.sh", "init-failed")
        self.assertNotEqual(result.returncode, 0)
        self.assertNotEqual(result.returncode, 70)
        self.assertIn("init-failed", self.events())
        self.assertNotIn("schema", self.events())

    def test_relay_start_reaches_schema_only_after_initializer_success(self):
        result = self.run_script(self.fixture / "scripts/start-relay-for-tests.sh")
        self.assertEqual(result.returncode, 70, result.stderr)
        self.assert_initialized()
        self.assertLess(self.events().index("init-success"), self.events().index("schema"))

    def test_unix_release_builds_and_bundles_requested_target(self):
        target = "x86_64-apple-darwin"
        result = self.run_recipe("desktop-release-build", target=target)
        self.assertEqual(result.returncode, 0, result.stderr)
        for binary in [*SIDECARS, "buzz-backend-kubernetes"]:
            destination = self.fixture / f"desktop/src-tauri/binaries/{binary}-{target}"
            self.assertEqual(destination.read_text(), f"built-{binary}")
        self.assertTrue(self.events()[0].startswith("cargo:build --locked --release --target "))
        self.assertIn(f"pnpm:tauri build --features mesh-llm --target {target}", self.events())

    def test_empty_release_binary_stops_before_packaging_and_preserves_destinations(self):
        target = "aarch64-apple-darwin"
        destination = self.write(f"desktop/src-tauri/binaries/buzz-acp-{target}", "preserve")
        result = self.run_recipe("desktop-release-build", "empty-buzz", target)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("missing or empty release binaries", result.stderr)
        self.assertEqual(destination.read_text(), "preserve")
        self.assertFalse(any(event.startswith("pnpm:") for event in self.events()))

    def test_sidecar_build_failure_stops_before_packaging(self):
        result = self.run_recipe("desktop-release-build", "cargo-failed", "aarch64-apple-darwin")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(any(event.startswith("pnpm:") for event in self.events()))

    def test_windows_release_omits_kubernetes_and_bundles_exe(self):
        target = "x86_64-pc-windows-msvc"
        result = self.run_recipe("desktop-release-build", target=target)
        self.assertEqual(result.returncode, 0, result.stderr)
        for binary in SIDECARS:
            destination = self.fixture / f"desktop/src-tauri/binaries/{binary}-{target}.exe"
            self.assertEqual(destination.read_text(), f"built-{binary}")
        self.assertNotIn("buzz-backend-kubernetes", self.events()[0])
        self.assertEqual(len(list((self.fixture / "desktop/src-tauri/binaries").iterdir())), 5)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-root", type=Path, default=SOURCE_ROOT)
    arguments, remaining = parser.parse_known_args()
    SOURCE_ROOT = arguments.source_root.resolve()
    unittest.main(argv=[__file__, *remaining])
