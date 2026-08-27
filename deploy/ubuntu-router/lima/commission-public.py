#!/usr/bin/env python3
"""Verify immutable public router inputs without applying them.

This artifact never downloads, installs, creates/starts a VM, changes a route,
generates a key, or invokes the trading harness.  Its successful verify mode
only proves the public bytes locked by ``commission-lock.json``.
"""

from __future__ import annotations

import argparse
from collections import deque
import hashlib
import io
import json
import lzma
import os
from pathlib import Path, PurePosixPath
import posixpath
import re
import stat
import subprocess
import sys
import tarfile
from typing import Any


SCRIPT_DIR = Path(__file__).resolve().parent
LOCK_PATH = SCRIPT_DIR / "commission-lock.json"
CLOUD_KEY_PATH = SCRIPT_DIR / "ubuntu-cloud-image-signing-key.gpg"
TRUSTED_ROOT_PATH = SCRIPT_DIR / "sigstore-trusted-root.jsonl"
LIMA_ATTESTATION_PATH = SCRIPT_DIR / "lima-2.2.0-attestation.jsonl"
SOCKET_VMNET_ATTESTATION_PATH = (
    SCRIPT_DIR / "socket-vmnet-1.2.2-attestation.jsonl"
)

SHA256_RE = re.compile(r"[0-9a-f]{64}")
PACKAGE_RE = re.compile(r"[a-z0-9][a-z0-9+.-]{0,127}")
VERSION_RE = re.compile(r"[0-9A-Za-z][0-9A-Za-z.+:~_-]{0,255}")
DEPENDENCY_RE = re.compile(
    r"([a-z0-9][a-z0-9+.-]*)"
    r"(?::(?:any|native|arm64))?"
    r"(?:\s*\((<<|<=|=|>=|>>)\s*([^()\s]+)\))?"
)
AUTHORIZATION = {
    "apply_enabled": False,
    "guest_package_install_enabled": False,
    "host_install_enabled": False,
    "network_changes_enabled": False,
    "router_key_generation_enabled": False,
    "vm_create_enabled": False,
}


class VerificationError(ValueError):
    """A fail-closed public-input verification failure."""


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise VerificationError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_bytes(), object_pairs_hook=_unique_object)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise VerificationError(f"invalid JSON: {path.name}") from error
    if not isinstance(value, dict):
        raise VerificationError(f"JSON root is not an object: {path.name}")
    return value


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _require_sha_size(path: Path, digest: object, size: object, label: str) -> None:
    if not isinstance(digest, str) or not SHA256_RE.fullmatch(digest):
        raise VerificationError(f"invalid locked SHA-256 for {label}")
    if type(size) is not int or size <= 0:
        raise VerificationError(f"invalid locked size for {label}")
    metadata = path.stat()
    if metadata.st_size != size:
        raise VerificationError(f"size differs for {label}")
    if _sha256(path) != digest:
        raise VerificationError(f"SHA-256 differs for {label}")


def _safe_regular(path: Path, owner_uid: int, label: str) -> None:
    if (
        not path.is_absolute()
        or path.is_symlink()
        or not path.is_file()
        or path.resolve(strict=True) != path
    ):
        raise VerificationError(f"{label} must be an absolute real regular file")
    metadata = path.stat()
    if metadata.st_nlink != 1:
        raise VerificationError(f"{label} has an unsafe link count")
    if metadata.st_uid != owner_uid:
        raise VerificationError(f"{label} owner differs from the operator")
    if stat.S_IMODE(metadata.st_mode) & 0o022:
        raise VerificationError(f"{label} is group/world writable")


def _safe_tool(path: Path, owner_uid: int, label: str) -> Path:
    _safe_regular(path, owner_uid, label)
    if not os.access(path, os.X_OK):
        raise VerificationError(f"{label} is not executable")
    return path


def _support_files(lock: dict[str, Any], *, enforce_bundle_permissions: bool = False) -> None:
    support = {
        CLOUD_KEY_PATH: lock["cloud_image"]["signing_key_sha256"],
        TRUSTED_ROOT_PATH: lock["host_attestation"][
            "sigstore_trusted_root_sha256"
        ],
        LIMA_ATTESTATION_PATH: lock["host_attestation"]["lima"][
            "attestation_bundle_sha256"
        ],
        SOCKET_VMNET_ATTESTATION_PATH: lock["host_attestation"][
            "socket_vmnet"
        ]["attestation_bundle_sha256"],
    }
    for path, expected in support.items():
        if not path.is_file() or path.is_symlink() or path.stat().st_nlink != 1:
            raise VerificationError(f"embedded support file is unsafe: {path.name}")
        if _sha256(path) != expected:
            raise VerificationError(f"embedded support file digest differs: {path.name}")
    if enforce_bundle_permissions:
        directory_metadata = SCRIPT_DIR.stat()
        if (
            SCRIPT_DIR.is_symlink()
            or directory_metadata.st_uid != os.getuid()
            or stat.S_IMODE(directory_metadata.st_mode) != 0o700
        ):
            raise VerificationError("rendered commission bundle owner/mode is unsafe")
        for path in (LOCK_PATH, *support):
            _safe_regular(path, os.getuid(), f"rendered bundle file {path.name}")
            if stat.S_IMODE(path.stat().st_mode) != 0o600:
                raise VerificationError(f"rendered bundle file mode differs: {path.name}")
        _safe_regular(Path(__file__).resolve(), os.getuid(), "commission verifier")
        if stat.S_IMODE(Path(__file__).resolve().stat().st_mode) != 0o700:
            raise VerificationError("commission verifier mode is not 0700")


def _expected_evidence_names(lock: dict[str, Any]) -> set[str]:
    names = {
        "ubuntu-archive-keyring.gpg",
        "SHA256SUMS",
        "SHA256SUMS.gpg",
        lock["cloud_image"]["manifest_filename"],
        lock["cloud_image"]["image_filename"],
    }
    names.update(
        tool["archive_filename"]
        for tool in (
            lock["host_attestation"]["lima"],
            lock["host_attestation"]["socket_vmnet"],
        )
    )
    for suite in lock["snapshot"]["suites"]:
        names.add(suite["inrelease_filename"])
        names.add(suite["packages_filename"])
    for archive in lock["install_transaction"]["download_archives"]:
        names.add(archive["filename"])
    return names


def _validate_evidence_dir(path: Path, lock: dict[str, Any]) -> dict[str, Path]:
    if (
        not path.is_absolute()
        or path.is_symlink()
        or not path.is_dir()
        or path.resolve(strict=True) != path
    ):
        raise VerificationError("evidence directory must be an absolute real directory")
    metadata = path.stat()
    if metadata.st_uid != os.getuid() or stat.S_IMODE(metadata.st_mode) != 0o700:
        raise VerificationError("evidence directory owner/mode must be operator/0700")
    entries = {entry.name: entry for entry in path.iterdir()}
    expected = _expected_evidence_names(lock)
    if set(entries) != expected:
        raise VerificationError(
            "evidence file set differs; "
            f"missing={sorted(expected - entries.keys())}, "
            f"extra={sorted(entries.keys() - expected)}"
        )
    for name, entry in entries.items():
        _safe_regular(entry, os.getuid(), f"evidence file {name}")
    return entries


def _sanitized_environment() -> dict[str, str]:
    environment = {
        "HOME": "/var/empty",
        "GH_CONFIG_DIR": "/var/empty",
        "GH_NO_UPDATE_NOTIFIER": "1",
        "GH_PROMPT_DISABLED": "1",
        "GIT_TERMINAL_PROMPT": "0",
        "XDG_CONFIG_HOME": "/var/empty",
        "XDG_CACHE_HOME": "/var/empty",
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
    }
    return environment


def _run_bounded(command: list[str], label: str) -> subprocess.CompletedProcess[str]:
    try:
        result = subprocess.run(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="strict",
            env=_sanitized_environment(),
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired, UnicodeError) as error:
        raise VerificationError(f"{label} could not run safely") from error
    if result.returncode != 0:
        raise VerificationError(f"{label} failed")
    if len(result.stdout) > 4 * 1024 * 1024 or len(result.stderr) > 1024 * 1024:
        raise VerificationError(f"{label} output exceeds the bound")
    return result


def _verify_gpg(
    gpgv: Path,
    keyring: Path,
    signed: Path,
    expected_fingerprint: str,
    detached_data: Path | None = None,
) -> None:
    command = [str(gpgv), "--status-fd", "1", "--keyring", str(keyring), str(signed)]
    if detached_data is not None:
        command.append(str(detached_data))
    result = _run_bounded(command, f"GPG verification for {signed.name}")
    fingerprints = []
    for line in result.stdout.splitlines():
        if line.startswith("[GNUPG:] VALIDSIG "):
            fields = line.split()
            if len(fields) >= 3:
                fingerprints.append(fields[2])
    if fingerprints != [expected_fingerprint]:
        raise VerificationError(f"unexpected signing fingerprint for {signed.name}")


def _verify_attestation(
    gh: Path,
    archive: Path,
    bundle: Path,
    trusted_root: Path,
    contract: dict[str, Any],
) -> None:
    result = _run_bounded(
        [
            str(gh),
            "attestation",
            "verify",
            str(archive),
            "--repo",
            contract["repository"],
            "--bundle",
            str(bundle),
            "--custom-trusted-root",
            str(trusted_root),
            "--cert-identity",
            contract["cert_identity"],
            "--deny-self-hosted-runners",
            "--format",
            "json",
        ],
        f"offline artifact attestation for {archive.name}",
    )
    try:
        values = json.loads(result.stdout, object_pairs_hook=_unique_object)
    except (json.JSONDecodeError, VerificationError) as error:
        raise VerificationError("attestation verifier returned invalid JSON") from error
    if not isinstance(values, list) or len(values) != 1 or not isinstance(values[0], dict):
        raise VerificationError("attestation verifier returned an ambiguous result set")
    verification = values[0].get("verificationResult")
    if not isinstance(verification, dict):
        raise VerificationError("attestation verification result is absent")
    signature = verification.get("signature")
    statement = verification.get("statement")
    if not isinstance(signature, dict) or not isinstance(statement, dict):
        raise VerificationError("attestation signature or statement is absent")
    certificate = signature.get("certificate")
    if not isinstance(certificate, dict):
        raise VerificationError("attestation certificate evidence is absent")
    expected_certificate = {
        "subjectAlternativeName": contract["cert_identity"],
        "githubWorkflowRepository": contract["repository"],
        "githubWorkflowRef": contract["source_ref"],
        "githubWorkflowSHA": contract["source_commit"],
        "runnerEnvironment": contract["runner_environment"],
        "sourceRepositoryRef": contract["source_ref"],
        "sourceRepositoryDigest": contract["source_commit"],
    }
    for key, expected in expected_certificate.items():
        if certificate.get(key) != expected:
            raise VerificationError(f"attestation certificate field differs: {key}")
    if statement.get("predicateType") != "https://slsa.dev/provenance/v1":
        raise VerificationError("attestation predicate type differs")
    subjects = statement.get("subject")
    if not isinstance(subjects, list):
        raise VerificationError("attestation subject set is absent")
    matching = [
        subject
        for subject in subjects
        if isinstance(subject, dict)
        and subject.get("name") == archive.name
        and subject.get("digest") == {"sha256": contract["archive_sha256"]}
    ]
    if len(matching) != 1:
        raise VerificationError("attestation does not bind the exact archive")


def _verify_tar_archive(path: Path, contract: dict[str, Any]) -> None:
    _require_sha_size(
        path, contract["archive_sha256"], contract["archive_size_bytes"], path.name
    )
    with tarfile.open(path, mode="r:gz") as archive:
        members = archive.getmembers()
        if not 1 <= len(members) <= 4096:
            raise VerificationError(f"unsafe member count in {path.name}")
        by_name: dict[str, tarfile.TarInfo] = {}
        for member in members:
            name = PurePosixPath(member.name)
            if name.is_absolute() or ".." in name.parts or member.name in by_name:
                raise VerificationError(f"unsafe or duplicate tar member in {path.name}")
            if not (member.isfile() or member.isdir() or member.issym()):
                raise VerificationError(f"unsupported tar member type in {path.name}")
            if member.issym():
                target = PurePosixPath(member.linkname)
                combined = posixpath.normpath(
                    posixpath.join(posixpath.dirname(member.name), member.linkname)
                )
                if (
                    target.is_absolute()
                    or combined == ".."
                    or combined.startswith("../")
                ):
                    raise VerificationError(f"unsafe tar symlink in {path.name}")
            by_name[member.name] = member
        expected_members = (
            {contract["binary_member"]: contract["binary_sha256"]}
            if "binary_member" in contract
            else contract["binary_members"]
        )
        for name, expected_digest in expected_members.items():
            member = by_name.get(name)
            if member is None or not member.isfile() or member.size > 256 * 1024 * 1024:
                raise VerificationError(f"locked binary member is absent: {name}")
            stream = archive.extractfile(member)
            if stream is None:
                raise VerificationError(f"locked binary member is unreadable: {name}")
            digest = hashlib.sha256(stream.read()).hexdigest()
            if digest != expected_digest:
                raise VerificationError(f"locked binary member digest differs: {name}")


def _parse_control(text: str, label: str) -> list[dict[str, str]]:
    records: list[dict[str, str]] = []
    for paragraph in text.split("\n\n"):
        if not paragraph.strip():
            continue
        record: dict[str, str] = {}
        current: str | None = None
        for line in paragraph.splitlines():
            if line.startswith((" ", "\t")):
                if current is None:
                    raise VerificationError(f"invalid continuation in {label}")
                record[current] += " " + line.strip()
                continue
            if ": " not in line:
                raise VerificationError(f"invalid field in {label}")
            key, value = line.split(": ", 1)
            if key in record:
                raise VerificationError(f"duplicate field in {label}: {key}")
            record[key] = value
            current = key
        records.append(record)
    return records


def _cleartext_inrelease(path: Path) -> str:
    text = path.read_text(encoding="utf-8")
    prefix = "-----BEGIN PGP SIGNED MESSAGE-----\n"
    signature = "\n-----BEGIN PGP SIGNATURE-----\n"
    if not text.startswith(prefix) or signature not in text:
        raise VerificationError(f"invalid clearsigned InRelease: {path.name}")
    body = text.split("\n\n", 1)[1].split(signature, 1)[0]
    return body.replace("\n- -", "\n-")


def _verify_snapshot(
    entries: dict[str, Path], lock: dict[str, Any], gpgv: Path
) -> dict[tuple[str, str], list[dict[str, str]]]:
    snapshot = lock["snapshot"]
    keyring = entries["ubuntu-archive-keyring.gpg"]
    if _sha256(keyring) != snapshot["archive_keyring_sha256"]:
        raise VerificationError("Ubuntu archive keyring digest differs")
    all_records: dict[tuple[str, str], list[dict[str, str]]] = {}
    for suite in snapshot["suites"]:
        inrelease = entries[suite["inrelease_filename"]]
        packages = entries[suite["packages_filename"]]
        _require_sha_size(
            inrelease,
            suite["inrelease_sha256"],
            suite["inrelease_size_bytes"],
            inrelease.name,
        )
        _verify_gpg(
            gpgv,
            keyring,
            inrelease,
            snapshot["archive_signing_fingerprint"],
        )
        body = _cleartext_inrelease(inrelease)
        metadata = _parse_control(body.split("\nMD5Sum:\n", 1)[0] + "\n", inrelease.name)
        if len(metadata) != 1:
            raise VerificationError(f"ambiguous InRelease metadata: {inrelease.name}")
        fields = metadata[0]
        if (
            fields.get("Origin") != "Ubuntu"
            or fields.get("Suite") != suite["name"]
            or fields.get("Codename") != "noble"
            or "arm64" not in fields.get("Architectures", "").split()
            or fields.get("Components", "").split()
            != ["main", "restricted", "universe", "multiverse"]
        ):
            raise VerificationError(f"InRelease identity differs: {inrelease.name}")
        sha_section = body.split("\nSHA256:\n", 1)
        if len(sha_section) != 2:
            raise VerificationError(f"InRelease SHA256 section is absent: {inrelease.name}")
        matches = []
        for line in sha_section[1].splitlines():
            fields_line = line.split()
            if len(fields_line) == 3 and fields_line[2] == suite["packages_path"]:
                matches.append(fields_line)
        expected_line = [
            suite["packages_sha256"],
            str(suite["packages_size_bytes"]),
            suite["packages_path"],
        ]
        if matches != [expected_line]:
            raise VerificationError(f"signed package index binding differs: {suite['name']}")
        _require_sha_size(
            packages,
            suite["packages_sha256"],
            suite["packages_size_bytes"],
            packages.name,
        )
        try:
            package_text = lzma.decompress(packages.read_bytes()).decode("utf-8")
        except (lzma.LZMAError, UnicodeDecodeError) as error:
            raise VerificationError(f"invalid package index: {packages.name}") from error
        for record in _parse_control(package_text, packages.name):
            name = record.get("Package")
            version = record.get("Version")
            if name is None or version is None:
                raise VerificationError(f"package identity is absent: {packages.name}")
            all_records.setdefault((name, version), []).append(record)
    return all_records


def _verify_cloud_image(
    entries: dict[str, Path], lock: dict[str, Any], gpgv: Path
) -> dict[str, str]:
    cloud = lock["cloud_image"]
    sums = entries["SHA256SUMS"]
    signature = entries["SHA256SUMS.gpg"]
    _require_sha_size(
        sums, cloud["sha256sums_sha256"], cloud["sha256sums_size_bytes"], sums.name
    )
    _require_sha_size(
        signature,
        cloud["sha256sums_signature_sha256"],
        cloud["sha256sums_signature_size_bytes"],
        signature.name,
    )
    _verify_gpg(
        gpgv,
        CLOUD_KEY_PATH,
        signature,
        cloud["signing_key_fingerprint"],
        sums,
    )
    parsed_sums: dict[str, str] = {}
    for line in sums.read_text(encoding="utf-8").splitlines():
        match = re.fullmatch(r"([0-9a-f]{64}) \*([^/\s]+)", line)
        if match is None or match.group(2) in parsed_sums:
            raise VerificationError("cloud SHA256SUMS is noncanonical")
        parsed_sums[match.group(2)] = match.group(1)
    for filename, expected in (
        (cloud["image_filename"], cloud["image_sha256"]),
        (cloud["manifest_filename"], cloud["manifest_sha256"]),
    ):
        if parsed_sums.get(filename) != expected:
            raise VerificationError(f"signed cloud checksum differs: {filename}")
    image = entries[cloud["image_filename"]]
    manifest = entries[cloud["manifest_filename"]]
    _require_sha_size(
        image, cloud["image_sha256"], cloud["image_size_bytes"], image.name
    )
    _require_sha_size(
        manifest,
        cloud["manifest_sha256"],
        cloud["manifest_size_bytes"],
        manifest.name,
    )
    installed: dict[str, str] = {}
    for line in manifest.read_text(encoding="utf-8").splitlines():
        fields = line.split("\t")
        if len(fields) != 2:
            raise VerificationError("cloud package manifest is noncanonical")
        name = fields[0].split(":", 1)[0]
        version = fields[1]
        if (
            not PACKAGE_RE.fullmatch(name)
            or not VERSION_RE.fullmatch(version)
            or name in installed
        ):
            raise VerificationError("cloud package manifest has an invalid entry")
        installed[name] = version
    return installed


def _version_parts(value: str) -> tuple[int, str, str]:
    if ":" in value:
        epoch_text, remainder = value.split(":", 1)
        if not epoch_text.isdigit():
            raise VerificationError("invalid Debian version epoch")
        epoch = int(epoch_text)
    else:
        epoch, remainder = 0, value
    if "-" in remainder:
        upstream, revision = remainder.rsplit("-", 1)
    else:
        upstream, revision = remainder, "0"
    return epoch, upstream, revision


def _char_order(value: str) -> int:
    if value == "~":
        return -1
    if value == "":
        return 0
    if value.isalpha() and value.isascii():
        return ord(value)
    return ord(value) + 256


def _revision_compare(left: str, right: str) -> int:
    while left or right:
        while (left and not left[0].isdigit()) or (right and not right[0].isdigit()):
            left_char = left[0] if left and not left[0].isdigit() else ""
            right_char = right[0] if right and not right[0].isdigit() else ""
            if _char_order(left_char) != _char_order(right_char):
                return -1 if _char_order(left_char) < _char_order(right_char) else 1
            if left_char:
                left = left[1:]
            if right_char:
                right = right[1:]
        left = left.lstrip("0")
        right = right.lstrip("0")
        left_digits = re.match(r"\d*", left).group(0)
        right_digits = re.match(r"\d*", right).group(0)
        if len(left_digits) != len(right_digits):
            return -1 if len(left_digits) < len(right_digits) else 1
        if left_digits != right_digits:
            return -1 if left_digits < right_digits else 1
        left = left[len(left_digits) :]
        right = right[len(right_digits) :]
    return 0


def _version_compare(left: str, right: str) -> int:
    left_epoch, left_upstream, left_revision = _version_parts(left)
    right_epoch, right_upstream, right_revision = _version_parts(right)
    if left_epoch != right_epoch:
        return -1 if left_epoch < right_epoch else 1
    upstream = _revision_compare(left_upstream, right_upstream)
    return upstream or _revision_compare(left_revision, right_revision)


def _version_satisfies(actual: str, operator: str | None, expected: str | None) -> bool:
    if operator is None:
        return True
    if expected is None:
        return False
    comparison = _version_compare(actual, expected)
    return {
        "<<": comparison < 0,
        "<=": comparison <= 0,
        "=": comparison == 0,
        ">=": comparison >= 0,
        ">>": comparison > 0,
    }[operator]


def _dependency_alternatives(value: str) -> list[tuple[str, str | None, str | None]]:
    alternatives: list[tuple[str, str | None, str | None]] = []
    for raw in value.split("|"):
        # This lock is for one native arm64 runtime transaction. Architecture
        # lists and build profiles do not occur in its reachable package
        # records. Reject them rather than deleting syntax and accidentally
        # accepting an alternative that is inapplicable on arm64.
        if "[" in raw or "]" in raw or re.search(r"\s<[^>]+>", raw):
            raise VerificationError(
                f"architecture/profile-qualified dependency is unsupported: {raw}"
            )
        candidate = raw.strip()
        match = DEPENDENCY_RE.fullmatch(candidate)
        if match is None:
            raise VerificationError(f"unsupported dependency expression: {raw}")
        alternatives.append(match.groups())
    return alternatives


def _record_for(
    records: dict[tuple[str, str], list[dict[str, str]]], name: str, version: str
) -> dict[str, str]:
    options = records.get((name, version))
    if not options:
        raise VerificationError(f"locked package record is absent: {name}={version}")
    relevant = (
        "Architecture",
        "Pre-Depends",
        "Depends",
        "Provides",
        "Filename",
        "Size",
        "SHA256",
    )
    identities = {tuple(option.get(key, "") for key in relevant) for option in options}
    if len(identities) != 1:
        raise VerificationError(f"ambiguous package records: {name}={version}")
    return options[0]


def _verify_deb_container(path: Path) -> None:
    content = path.read_bytes()
    if not content.startswith(b"!<arch>\n"):
        raise VerificationError(f"invalid Debian archive: {path.name}")
    offset = 8
    members: dict[str, bytes] = {}
    while offset < len(content):
        if offset + 60 > len(content):
            raise VerificationError(f"truncated Debian archive: {path.name}")
        header = content[offset : offset + 60]
        if header[58:60] != b"`\n":
            raise VerificationError(f"invalid Debian archive header: {path.name}")
        try:
            name = header[:16].decode("ascii").strip().removesuffix("/")
            size = int(header[48:58].decode("ascii").strip())
        except (UnicodeDecodeError, ValueError) as error:
            raise VerificationError(f"invalid Debian archive member: {path.name}") from error
        offset += 60
        end = offset + size
        if end > len(content) or name in members:
            raise VerificationError(f"unsafe Debian archive member: {path.name}")
        members[name] = content[offset:end]
        offset = end + (size % 2)
    if offset != len(content) or members.get("debian-binary") != b"2.0\n":
        raise VerificationError(f"invalid Debian archive framing: {path.name}")
    if not any(name.startswith("control.tar.") for name in members) or not any(
        name.startswith("data.tar.") for name in members
    ):
        raise VerificationError(f"Debian archive payload is incomplete: {path.name}")


def _verify_dependency_closure(
    entries: dict[str, Path],
    lock: dict[str, Any],
    installed: dict[str, str],
    records: dict[tuple[str, str], list[dict[str, str]]],
) -> None:
    transaction = lock["install_transaction"]
    closure = transaction["closure_packages"]
    direct = transaction["direct_packages"]
    if (
        transaction["apt_no_install_recommends"] is not True
        or transaction["base_manifest_package_count"] != len(installed)
        or transaction["closure_package_count"] != len(closure)
        or not isinstance(closure, dict)
        or not isinstance(direct, dict)
    ):
        raise VerificationError("dependency closure cardinality/policy differs")
    if not set(direct).issubset(closure) or any(
        closure.get(name) != version for name, version in direct.items()
    ):
        raise VerificationError("direct package set differs from the closure")
    added = transaction["packages_added"]
    if (
        added != ["wireguard-tools"]
        or transaction["packages_removed"] != []
        or transaction["packages_upgraded"] != []
    ):
        raise VerificationError("locked package transaction widens installation")
    for name, version in closure.items():
        if not PACKAGE_RE.fullmatch(name) or not VERSION_RE.fullmatch(version):
            raise VerificationError("closure package identity is invalid")
        _record_for(records, name, version)
        if name not in added and installed.get(name) != version:
            raise VerificationError(f"base package differs from signed manifest: {name}")
        if name in added and name in installed:
            raise VerificationError(f"added package is already in the base manifest: {name}")

    closure_records = {
        name: _record_for(records, name, version) for name, version in closure.items()
    }
    providers: dict[str, list[tuple[str, str | None]]] = {}
    for name, record in closure_records.items():
        for value in record.get("Provides", "").split(","):
            value = value.strip()
            if not value:
                continue
            match = re.fullmatch(
                r"([a-z0-9][a-z0-9+.-]*)(?:\s*\(=\s*([^()\s]+)\))?", value
            )
            if match is None:
                raise VerificationError(f"unsupported Provides expression: {value}")
            providers.setdefault(match.group(1), []).append((name, match.group(2)))

    reached: set[str] = set()
    queue: deque[str] = deque(sorted(direct))
    while queue:
        name = queue.popleft()
        if name in reached:
            continue
        reached.add(name)
        record = closure_records[name]
        for field in ("Pre-Depends", "Depends"):
            for dependency in [
                value.strip()
                for value in record.get(field, "").split(",")
                if value.strip()
            ]:
                selected: str | None = None
                for dep_name, operator, expected in _dependency_alternatives(dependency):
                    actual = closure.get(dep_name)
                    if actual is not None and _version_satisfies(
                        actual, operator, expected
                    ):
                        selected = dep_name
                        break
                    for provider_name, provided_version in sorted(
                        providers.get(dep_name, [])
                    ):
                        if operator is None or (
                            provided_version is not None
                            and _version_satisfies(
                                provided_version, operator, expected
                            )
                        ):
                            selected = provider_name
                            break
                    if selected is not None:
                        break
                if selected is None:
                    raise VerificationError(
                        f"unsatisfied locked dependency: {name}: {dependency}"
                    )
                queue.append(selected)
    if reached != set(closure):
        raise VerificationError("closure contains unreachable or missing packages")

    downloads = transaction["download_archives"]
    if not isinstance(downloads, list) or len(downloads) != 1:
        raise VerificationError("download archive set differs")
    for archive in downloads:
        name = archive["package"]
        version = archive["version"]
        record = _record_for(records, name, version)
        expected_record = {
            "Architecture": archive["architecture"],
            "Filename": archive["repository_path"],
            "Size": str(archive["size_bytes"]),
            "SHA256": archive["sha256"],
        }
        for key, expected in expected_record.items():
            if record.get(key) != expected:
                raise VerificationError(f"download package index field differs: {key}")
        path = entries[archive["filename"]]
        _require_sha_size(path, archive["sha256"], archive["size_bytes"], path.name)
        _verify_deb_container(path)


def _validate_lock(lock: dict[str, Any]) -> None:
    expected_keys = {
        "architecture",
        "authorization",
        "cloud_image",
        "host_attestation",
        "install_transaction",
        "review_status",
        "schema_version",
        "snapshot",
    }
    if set(lock) != expected_keys or lock.get("schema_version") != 1:
        raise VerificationError("commission lock schema differs")
    if (
        lock.get("review_status")
        != "signed_snapshot_and_dependency_closure_locked_apply_disabled"
        or lock.get("architecture") != "arm64"
        or lock.get("authorization") != AUTHORIZATION
    ):
        raise VerificationError("commission lock status/authorization differs")
    if lock["snapshot"].get("base_url") != (
        "https://snapshot.ubuntu.com/ubuntu/20260814T203500Z/"
    ):
        raise VerificationError("snapshot URL differs")
    if lock["snapshot"].get("components") != ["main"]:
        raise VerificationError("snapshot components differ")
    suites = lock["snapshot"].get("suites")
    if not isinstance(suites, list) or [value.get("name") for value in suites] != [
        "noble",
        "noble-updates",
        "noble-security",
        "noble-backports",
    ]:
        raise VerificationError("snapshot suite order differs")


def _plan(lock: dict[str, Any]) -> int:
    print("apply_enabled=false")
    print("host_install_enabled=false")
    print("vm_create_enabled=false")
    print("guest_package_install_enabled=false")
    print("network_changes_enabled=false")
    print("router_key_generation_enabled=false")
    print(f"snapshot_url={lock['snapshot']['base_url']}")
    print("snapshot_components=main")
    print(
        "dependency_closure_package_count="
        f"{lock['install_transaction']['closure_package_count']}"
    )
    print("packages_added=wireguard-tools")
    print("packages_upgraded=none")
    print("packages_removed=none")
    print("host_attestation_mode=offline_bundles_with_pinned_sigstore_root")
    print("immutable_input_verification_available=true")
    print("verification_tools_must_be_operator_trusted=true")
    expected_files = sorted(_expected_evidence_names(lock))
    print(f"evidence_file_count={len(expected_files)}")
    for name in expected_files:
        print(f"evidence_file={name}")
    print("evidence_status=awaiting_immutable_public_input_replay")
    return 0


def verify(evidence_dir: Path, gh: Path, gpgv: Path) -> int:
    lock = _read_json(LOCK_PATH)
    _validate_lock(lock)
    _support_files(lock, enforce_bundle_permissions=True)
    owner_uid = os.getuid()
    gh = _safe_tool(gh, owner_uid, "GitHub attestation verifier")
    gpgv = _safe_tool(gpgv, owner_uid, "GPG verifier")
    entries = _validate_evidence_dir(evidence_dir, lock)

    for name, contract, bundle in (
        (
            "lima",
            lock["host_attestation"]["lima"],
            LIMA_ATTESTATION_PATH,
        ),
        (
            "socket_vmnet",
            lock["host_attestation"]["socket_vmnet"],
            SOCKET_VMNET_ATTESTATION_PATH,
        ),
    ):
        archive = entries[contract["archive_filename"]]
        _verify_tar_archive(archive, contract)
        _verify_attestation(gh, archive, bundle, TRUSTED_ROOT_PATH, contract)

    records = _verify_snapshot(entries, lock, gpgv)
    installed = _verify_cloud_image(entries, lock, gpgv)
    _verify_dependency_closure(entries, lock, installed, records)

    print("immutable_inputs_verified=true")
    print("host_artifact_attestations_verified=true")
    print("signed_cloud_image_and_manifest_verified=true")
    print("signed_snapshot_indexes_verified=true")
    print("dependency_closure_verified=true")
    print("verification_tool_provenance_external=true")
    print(f"gh_verifier_sha256={_sha256(gh)}")
    print(f"gpgv_verifier_sha256={_sha256(gpgv)}")
    print("apply_enabled=false")
    print("host_install_enabled=false")
    print("vm_create_enabled=false")
    print("guest_package_install_enabled=false")
    print("network_changes_enabled=false")
    print("router_key_generation_enabled=false")
    print("evidence_status=immutable_public_inputs_verified_apply_still_disabled")
    return 0


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Plan or verify immutable public Ubuntu router inputs."
    )
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--plan", action="store_true")
    mode.add_argument("--verify-inputs", action="store_true")
    parser.add_argument("--evidence-dir", type=Path)
    parser.add_argument("--gh", type=Path)
    parser.add_argument("--gpgv", type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        lock = _read_json(LOCK_PATH)
        _validate_lock(lock)
        _support_files(lock)
        if arguments.plan:
            if any(
                value is not None
                for value in (arguments.evidence_dir, arguments.gh, arguments.gpgv)
            ):
                raise VerificationError("plan mode does not accept verification paths")
            return _plan(lock)
        if None in (arguments.evidence_dir, arguments.gh, arguments.gpgv):
            raise VerificationError(
                "verify mode requires --evidence-dir, --gh and --gpgv"
            )
        return verify(arguments.evidence_dir, arguments.gh, arguments.gpgv)
    except VerificationError as error:
        print(f"commission_public_failed: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
