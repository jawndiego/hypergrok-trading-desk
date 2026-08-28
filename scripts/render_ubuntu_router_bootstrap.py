#!/usr/bin/env python3
"""Render and replay-check the attended, air-gapped Lima bootstrap bundle.

The renderer is deliberately inert: it performs no privilege, VM, network,
credential, package, or venue operation.  It only composes reviewed local
source bytes into a new mode-0700 directory.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import sys
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "deploy" / "ubuntu-router" / "lima-bootstrap"
LOCK_PATH = SOURCE / "bootstrap-lock.json"
SHA256_RE = re.compile(r"[0-9a-f]{64}")
PLACEHOLDER_RE = re.compile(r"__[A-Z0-9_]+__")

SOURCE_FILES: dict[str, int] = {
    "README.md": 0o600,
    "bootstrap-apply-launcher.sh": 0o700,
    "bootstrap-apply.py": 0o700,
    "bootstrap-lock.json": 0o600,
    "cloud-config-first-boot.yaml.example": 0o600,
    "finalize-first-boot.sh": 0o700,
    "first-boot-hardening.sh": 0o700,
    "lima-first-boot.yaml.example": 0o600,
    "networks-first-boot.yaml": 0o600,
    "predecessor-cloud-config.template": 0o600,
    "predecessor-lima-create-local.yaml": 0o600,
    "verify-first-boot.py": 0o700,
}


def _sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _canonical_json(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _read(path: Path, label: str, maximum: int = 1024 * 1024) -> bytes:
    if not path.is_absolute() or not path.is_file() or path.is_symlink():
        raise ValueError(f"{label} must be a real absolute file")
    metadata = path.stat()
    if metadata.st_nlink != 1 or not 0 < metadata.st_size <= maximum:
        raise ValueError(f"{label} metadata is unsafe")
    return path.read_bytes()


def _load_lock(content: bytes) -> dict[str, Any]:
    try:
        value = json.loads(content, object_pairs_hook=_unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("bootstrap lock is invalid") from error
    if not isinstance(value, dict):
        raise ValueError("bootstrap lock must be an object")
    if (
        value.get("schema_version") != 1
        or value.get("review_status")
        != "attended_airgap_hardened_recreate_enabled_start_disabled"
        or value.get("host", {}).get("router_operator_uid") != 454
        or value.get("host", {}).get("router_operator_gid") != 454
        or value.get("guest", {}).get("instance_name") != "trading-desk-router"
        or value.get("pins", {}).get("predecessor_vm_receipt_sha256")
        != "1b80f2931f496ef7ad9e7fa4aac48cdc2b2dcd8f47c8e08207988c4386af1601"
        or value.get("phases")
        != {
            "airgapped_start_apply_enabled": False,
            "guest_package_apply_enabled": False,
            "hardened_recreate_apply_enabled": True,
            "router_activation_apply_enabled": False,
        }
        or value.get("storage")
        != {
            "minimum_free_after_bytes": 5 * 1024**3,
            "minimum_free_before_create_bytes": 25 * 1024**3,
        }
        or value.get("stop_line")
        != {
            "executor_started": False,
            "mainnet_authorized": False,
            "network_reconnect_authorized": False,
            "router_key_generation_authorized": False,
            "venue_credentials_authorized": False,
            "venue_writes_authorized": False,
            "vm_start_authorized": False,
        }
    ):
        raise ValueError("bootstrap lock authorization boundary differs")
    return value


def _yaml_block(content: bytes, indentation: int) -> str:
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError("guest bootstrap source is not UTF-8") from error
    if "\x00" in text or not text.endswith("\n"):
        raise ValueError("guest bootstrap source is noncanonical")
    lines = text.splitlines()
    prefix = " " * indentation
    return lines[0] + "\n" + "\n".join(
        prefix + line if line else prefix for line in lines[1:]
    )


def _render_template(path: Path, replacements: dict[str, str]) -> bytes:
    text = _read(path, f"template {path.name}").decode("utf-8")
    for marker, replacement in replacements.items():
        if text.count(marker) != 1:
            raise ValueError(f"template marker count differs: {marker}")
        text = text.replace(marker, replacement)
    remaining = PLACEHOLDER_RE.findall(text)
    if remaining:
        raise ValueError(f"unresolved template markers: {remaining}")
    return text.encode("utf-8")


def _rendered_files() -> tuple[dict[str, tuple[bytes, int]], dict[str, Any]]:
    source_bytes = {
        name: _read(SOURCE / name, name)
        for name in SOURCE_FILES
    }
    lock = _load_lock(source_bytes["bootstrap-lock.json"])
    verifier_sha256 = _sha256(source_bytes["verify-first-boot.py"])
    finalizer_marker = b"__VERIFY_FIRST_BOOT_SHA256__"
    if source_bytes["finalize-first-boot.sh"].count(finalizer_marker) != 1:
        raise ValueError("finalizer verifier marker count differs")
    rendered_finalizer = source_bytes["finalize-first-boot.sh"].replace(
        finalizer_marker, verifier_sha256.encode("ascii")
    )
    plan = _render_template(
        SOURCE / "lima-first-boot.yaml.example",
        {
            "__PINNED_HARDENED_IMAGE_LOCATION_YAML__": json.dumps(
                f"file://{lock['paths']['local_image']}"
            ),
            "__PINNED_HARDENED_IMAGE_DIGEST_YAML__": json.dumps(
                f"sha256:{lock['pins']['local_image_sha256']}"
            ),
            "__EARLY_BOOT_HARDENING_SCRIPT_YAML__": _yaml_block(
                source_bytes["first-boot-hardening.sh"], 6
            ),
            "__VERIFY_FIRST_BOOT_SCRIPT_YAML__": _yaml_block(
                source_bytes["verify-first-boot.py"], 6
            ),
            "__FINALIZE_FIRST_BOOT_SCRIPT_YAML__": _yaml_block(
                rendered_finalizer, 6
            ),
        },
    )
    network = source_bytes["networks-first-boot.yaml"]
    plan_pin = lock["pins"]["hardened_plan_sha256"]
    network_pin = lock["pins"]["networks_first_boot_sha256"]
    if plan_pin != "REVIEW_REQUIRED" and _sha256(plan) != plan_pin:
        raise ValueError("hardened plan digest differs from lock")
    if network_pin != "REVIEW_REQUIRED" and _sha256(network) != network_pin:
        raise ValueError("first-boot networks digest differs from lock")
    files: dict[str, tuple[bytes, int]] = {
        name: (content, SOURCE_FILES[name]) for name, content in source_bytes.items()
    }
    files["lima-first-boot.yaml"] = (plan, 0o600)
    return files, lock


def _write(path: Path, content: bytes, mode: int) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        view = memoryview(content)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("zero-length bundle write")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    path.chmod(mode)


def render(output: Path) -> dict[str, Any]:
    if not output.is_absolute() or output.exists() or output.is_symlink():
        raise ValueError("output must be a new absolute path")
    if not output.parent.is_dir() or output.parent.is_symlink():
        raise ValueError("output parent must be a real directory")
    files, lock = _rendered_files()
    output.mkdir(mode=0o700)
    try:
        hashes: dict[str, str] = {}
        for name, (content, mode) in sorted(files.items()):
            _write(output / name, content, mode)
            hashes[name] = _sha256(content)
        manifest = {
            "apply_enabled": False,
            "bundle_kind": "trading-desk.ubuntu-router-airgap-bootstrap",
            "files": hashes,
            "hardened_plan_sha256": hashes["lima-first-boot.yaml"],
            "mainnet_authorized": False,
            "network_changes_performed": False,
            "predecessor_vm_receipt_sha256": lock["pins"][
                "predecessor_vm_receipt_sha256"
            ],
            "schema_version": 1,
            "venue_writes_authorized": False,
            "vm_started": False,
        }
        _write(output / "bundle-manifest.json", _canonical_json(manifest), 0o600)
    except BaseException:
        shutil.rmtree(output, ignore_errors=True)
        raise
    return manifest


def verify(bundle: Path, expected_manifest_sha256: str, owner_uid: int | None) -> dict[str, Any]:
    if SHA256_RE.fullmatch(expected_manifest_sha256) is None:
        raise ValueError("expected manifest digest is invalid")
    if not bundle.is_absolute() or not bundle.is_dir() or bundle.is_symlink():
        raise ValueError("bundle must be a real absolute directory")
    metadata = bundle.stat()
    if stat.S_IMODE(metadata.st_mode) != 0o700:
        raise ValueError("bundle directory mode differs")
    if owner_uid is not None and metadata.st_uid != owner_uid:
        raise ValueError("bundle directory owner differs")
    manifest_raw = _read(bundle / "bundle-manifest.json", "bundle manifest")
    if _sha256(manifest_raw) != expected_manifest_sha256:
        raise ValueError("bundle manifest digest differs")
    try:
        manifest = json.loads(manifest_raw, object_pairs_hook=_unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("bundle manifest is invalid") from error
    expected_files, lock = _rendered_files()
    expected_names = set(expected_files) | {"bundle-manifest.json"}
    if {path.name for path in bundle.iterdir()} != expected_names:
        raise ValueError("bundle file inventory differs")
    if (
        not isinstance(manifest, dict)
        or manifest.get("bundle_kind")
        != "trading-desk.ubuntu-router-airgap-bootstrap"
        or manifest.get("apply_enabled") is not False
        or manifest.get("network_changes_performed") is not False
        or manifest.get("vm_started") is not False
        or manifest.get("venue_writes_authorized") is not False
        or manifest.get("mainnet_authorized") is not False
        or manifest.get("predecessor_vm_receipt_sha256")
        != lock["pins"]["predecessor_vm_receipt_sha256"]
    ):
        raise ValueError("bundle manifest boundary differs")
    expected_hashes = {name: _sha256(content) for name, (content, _mode) in expected_files.items()}
    if manifest.get("files") != expected_hashes:
        raise ValueError("bundle manifest hashes differ")
    for name, (content, mode) in expected_files.items():
        path = bundle / name
        current = _read(path, f"bundle file {name}")
        info = path.stat()
        if current != content or stat.S_IMODE(info.st_mode) != mode:
            raise ValueError(f"bundle file differs: {name}")
        if owner_uid is not None and info.st_uid != owner_uid:
            raise ValueError(f"bundle file owner differs: {name}")
    if manifest.get("hardened_plan_sha256") != expected_hashes["lima-first-boot.yaml"]:
        raise ValueError("manifest hardened plan digest differs")
    return manifest


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--check-bundle", type=Path)
    parser.add_argument("--expected-manifest-sha256")
    parser.add_argument("--require-owner-uid", type=int)
    return parser


def main() -> int:
    args = _parser().parse_args()
    try:
        if args.output_dir is not None and args.check_bundle is None:
            manifest = render(args.output_dir)
            print(json.dumps(manifest, indent=2, sort_keys=True))
            return 0
        if (
            args.check_bundle is not None
            and args.output_dir is None
            and args.expected_manifest_sha256 is not None
        ):
            manifest = verify(
                args.check_bundle,
                args.expected_manifest_sha256,
                args.require_owner_uid,
            )
            print(json.dumps(manifest, indent=2, sort_keys=True))
            return 0
        raise ValueError("choose render or check mode")
    except (OSError, ValueError, KeyError, TypeError) as error:
        print(f"router_bootstrap_render_failed: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
