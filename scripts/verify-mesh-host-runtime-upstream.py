#!/usr/bin/env python3
"""Verify the manifest-only backport against pinned Mesh source hashes."""

import hashlib
import json
from pathlib import Path
import re
import sys


def normalized_manifest(original: str) -> str:
    result = original.replace('version.workspace = true', 'version = "0.75.1"')
    result = result.replace('license.workspace = true', 'license = "MIT OR Apache-2.0"')
    result = result.replace(
        '[lints]\nworkspace = true',
        '[lints.clippy]\ncognitive_complexity = "warn"\ntoo_many_lines = "warn"',
    )
    result = result.replace(
        'mesh-llm-build-info.workspace = true',
        'mesh-llm-build-info = { git = "https://github.com/Mesh-LLM/mesh-llm.git", tag = "v0.75.1", version = "0.75.1" }',
    )
    result = re.sub(
        r'path = "\.\./[^\"]+",',
        'git = "https://github.com/Mesh-LLM/mesh-llm.git", tag = "v0.75.1",',
        result,
    )
    if result.count('serde_yaml = "0.9"\n') != 1:
        raise ValueError("Expected exactly one unused YAML dependency")
    return result.replace('serde_yaml = "0.9"\n', '')


def verify(root: Path) -> None:
    for path in root.rglob('*'):
        if path.is_symlink():
            raise ValueError(f'Vendor symlink is not allowed: {path.relative_to(root)}')
    provenance = (root / 'UPSTREAM.json').read_bytes()
    if hashlib.sha256(provenance).hexdigest() != 'a24c712b8f09a1e4613cfc757a734f25698848a3736d2bb713f4659bbe65f0e0':
        raise ValueError('Upstream provenance manifest changed; independent revision review required')
    metadata = json.loads(provenance)
    if metadata['revision'] != '3295c902d4c4f859aaadf9240042ffdaf06dd07e':
        raise ValueError('Unexpected Mesh revision')
    manifest = 'crates/mesh-llm-host-runtime/Cargo.toml'
    expected = set(metadata['files_sha256']) | {manifest + '.upstream', 'UPSTREAM.json'}
    actual = {str(p.relative_to(root)) for p in root.rglob('*') if p.is_file()}
    if expected != actual:
        raise ValueError(f'Unexpected vendor file set: {expected ^ actual}')
    for relative, digest in metadata['files_sha256'].items():
        path = root / (relative + '.upstream' if relative == manifest else relative)
        if path.is_symlink() or hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            raise ValueError(f'Upstream source differs: {relative}')
        if relative.endswith('.rs') and re.search(r'\bserde_yaml\b', path.read_text()):
            raise ValueError(f'YAML dependency is used: {relative}')
    original = (root / (manifest + '.upstream')).read_text()
    if (root / manifest).read_text() != normalized_manifest(original):
        raise ValueError('Manifest differs from the documented normalization/removal')
    print(f"PASS: {len(metadata['files_sha256'])} upstream files; manifest-only backport")


if __name__ == '__main__':
    vendor = Path(__file__).resolve().parents[1] / 'third_party/mesh-llm'
    try:
        verify(vendor)
    except (ValueError, OSError, KeyError) as error:
        print(f'FAIL: {error}', file=sys.stderr)
        sys.exit(1)
