#!/usr/bin/false
"""Quarantine one exact interrupted first boot and recreate its stopped VM."""
from __future__ import annotations
import argparse, importlib.util, os, re, stat, subprocess
from pathlib import Path
from typing import Any
HERE = Path(__file__).resolve().parent; SPEC = importlib.util.spec_from_file_location("router_bootstrap_apply", HERE / "bootstrap-apply.py")
if SPEC is None or SPEC.loader is None: raise SystemExit("router_interrupted_recovery_failed: controller import")
C = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(C)
SOURCE = "91c455c4f6a2ebb670d9ea01b394158c0b48edbb92da55317b3c3e9ec7ffeda9"; FRESH = "e33dbb26c0b91014f0748dd121d78d66627dd11c1fe8db4af0931d2254865999"
FAILED_MANIFEST = "b8e7fd49e23fa4b988834764f97ffbb1c1e179c26f491b2f098ba04e887d0f4d"; OLD_RECEIPT = "8ea55aa7a05534b91e40d42e70034162575f2dae3d568be06f6c8433ee1d39b6"
PREDECESSOR_RECOVERY_MANIFEST = "51b0ac392c5588a41512cde239f096de8293d532f7c13bcccf45c38bea171e00"
TRANSACTION_SHA256 = "e76da7a511d625dc4114cb0696a1ddc2e48029d351a3f8809c266fc7788eb2ef"
STOPPED_PROOF_SHA256 = "62676d50371deab1de5ef8fbb58f4e87676a8ec9c550d2a3be1da9d4dc822f36"
FILES = {
    "base": (54537718, 7578, "fa5d70ec9e4b79c177f06a1da4178e9d626212cc230119b12ad9e0999dec8860", 0o400),
    "hardware_lock": (54537798, 7050, "fc295a66b57489906715b2b697df406bf4650e8cbe39c73d0fea0b52a62aad32", 0o400),
    "preparing": (54537719, 487, "c26942b6a89fae9895765e4e220c426ea41ff2fafe5bd1ad9fb047f572f7236c", 0o400),
    "starting": (54537840, 577, "1e4df90482210461a2c1c51265bca81938e4167d200845e99cb4695940a508c1", 0o400),
    "start_stdout": (54537841, 0, C._sha256_bytes(b""), 0o600),
    "start_stderr": (54537842, 831, "001b372563e4490a906311309ea6fbc8a1bbbb9f50dc3be288a7a8094ebfc2e7", 0o600),
    "socket_stdout": (54537722, 0, C._sha256_bytes(b""), 0o600),
    "socket_stderr": (54537723, 591, "c37dd0a380ff30dbebf623c4e9a65b33e823b7273b909876310c6ea3b26bfac0", 0o600),
    "sudoers": (54537720, 714, "fb36f1a319cc6bff643c11582ff08afe7564e7c47c309a4a702cf6f4e5b50e35", 0o440),
}
CORE = {
    "cloud-config.yaml": (54537882, 11734, "758a1143d5e27b2cb2afa82875cd86b8764075d9dff30b16a981e1e212a3da87", 0o400),
    "disk": (50928241, 20 * 1024**3, "ce00dc50bc7e299d831dc8bd05afabd5b291fa7ecca234c7c1f7713d06134d46", 0o600),
    "lima-version": (50928237, 6, "c3f991ed0f7bc00c631591ef0ad097ef1df20e91a43276d49a33cd9f451d7634", 0o400),
    "lima.yaml": (50928236, 41067, "aea50ab9aeaf1022f1cf1fbd7055cb9d249e6c94cb5bbae96ff04944a67a9874", 0o600),
    "vz-identifier": (50928239, 70, "ec9a156391042bd2b99e65a8152b8b0727b82829178ff53bf0b4278a479feb07", 0o600),
}
ORDER = ("library", "instance", "runtime", "sudoers", "base", "hardware_lock", "preparing", "starting", "receipt08"); ACL = ["0: user:trading-router-operator allow read,readattr"]
def _acl(path: Path) -> list[str]:
    result = subprocess.run(
        ["/bin/ls", "-led", str(path)], stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        encoding="utf-8", errors="strict",
        env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C", "LC_ALL": "C"},
        timeout=10, check=False,
    )
    if result.returncode or result.stderr:
        raise C.BootstrapError("interrupted ACL inspection failed")
    return [line.strip() for line in result.stdout.splitlines()[1:] if re.match(r"^\s*[0-9]+:", line)]
def _paths(lock: dict[str, Any], state: dict[str, Path]) -> dict[str, tuple[Path, Path]]:
    root = state["state"]; live = {
        "library": Path(lock["paths"]["lima_home"]) / "Library",
        "instance": Path(lock["paths"]["lima_home"]) / lock["guest"]["instance_name"],
        "runtime": Path(lock["paths"]["vmnet_runtime"]),
        "sudoers": Path(lock["paths"]["vmnet_sudoers"]),
        "base": root / f"airgap-hardware-base-capture-{SOURCE}.json",
        "hardware_lock": root / "airgap-hardware-lock.json",
        "preparing": root / ".airgap-first-boot.PREPARING.json",
        "starting": root / ".airgap-first-boot.STARTING.json",
        "receipt08": Path(lock["paths"]["hardened_vm_receipt"]),
    }
    return {key: (path, state["quarantine"] / f"interrupted-first-boot-{key}-{SOURCE}") for key, path in live.items()}
def _fixed(path: Path, key: str, *, cleared: bool | None = False) -> bytes:
    inode, size, digest, mode = FILES[key]
    observed = path.lstat()
    actual_mode = stat.S_IMODE(observed.st_mode)
    if (
        path.is_symlink() or not stat.S_ISREG(observed.st_mode)
        or (observed.st_ino, observed.st_uid, observed.st_gid, observed.st_nlink, observed.st_size)
        != (inode, 0, 0, 1, size)
        or actual_mode not in ({0o400} if key == "sudoers" and cleared is True else ({0o440, 0o400} if key == "sudoers" and cleared is None else {mode}))
    ):
        raise C.BootstrapError(f"interrupted {key} metadata differs")
    content = C._read_bound(path, uid=0, gid=0, mode=actual_mode, maximum=max(size, 1), allow_empty=size == 0)
    if C._sha256_bytes(content) != digest or (key != "sudoers" and _acl(path)):
        raise C.BootstrapError(f"interrupted {key} evidence differs")
    return content
def _old_receipt(lock: dict[str, Any], path: Path) -> tuple[dict[str, Any], list[Any]]:
    content = C._read_bound(path, uid=0, gid=0, mode=0o400, maximum=256 * 1024)
    value = C._load_json_bytes(content, "old receipt08")
    metadata = path.stat()
    if (
        C._sha256_bytes(content) != OLD_RECEIPT or _acl(path)
        or value.get("kind") != "trading-desk.router-bootstrap.hardened-vm"
        or value.get("disk_sha256") != lock["pins"]["predecessor_disk_sha256"]
        or value.get("vm_status") != "Stopped" or value.get("vm_started") is not False
        or value.get("instance_path") != str(_paths(lock, {"state": Path(lock["paths"]["state_root"]), "quarantine": Path(lock["paths"]["quarantine_parent"])})["instance"][0])
    ):
        raise C.BootstrapError("old receipt08 differs")
    return value, [metadata.st_ino, metadata.st_size, OLD_RECEIPT]
def _opaque_instance(path: Path, receipt: dict[str, Any]) -> dict[str, Any]:
    root = C._assert_real(path, kind="directory", uid=454, gid=454, mode=0o700)
    if (root.st_dev, root.st_ino) != (receipt.get("instance_device"), receipt.get("instance_inode")):
        raise C.BootstrapError("tainted instance identity differs")
    observed: dict[str, list[Any]] = {}
    for name, (inode, size, digest, mode) in CORE.items():
        item = path / name
        metadata = C._assert_real(item, kind="file", uid=454, gid=454, mode=mode, links=1)
        actual = C._hash_bound_file(item, uid=454, gid=454, mode=mode, expected_size=size)
        if metadata.st_ino != inode or actual != digest:
            raise C.BootstrapError("tainted instance core differs")
        observed[name] = [metadata.st_ino, metadata.st_size, actual]
    return {"device": root.st_dev, "inode": root.st_ino, "core": observed}
def _library(path: Path) -> dict[str, int]:
    root = C._assert_real(path, kind="directory", uid=454, gid=454, mode=0o755)
    if (root.st_dev, root.st_ino, root.st_nlink, root.st_size) != (16777234, 54538220, 4, 128):
        raise C.BootstrapError("tainted Library root differs")
    return {"device": root.st_dev, "inode": root.st_ino}
def _runtime(path: Path, *, cleared: bool | None) -> dict[str, Any]:
    root = C._assert_real(path, kind="directory", uid=0, gid=0, mode=0o755)
    C._verify_recovery_xattrs(path, "runtime")
    socket_path = path / "socket_vmnet.td-router-ingress"
    pid_path = path / "td-router-ingress_socket_vmnet.pid"
    socket = socket_path.lstat()
    pid = C._read_bound(pid_path, uid=0, gid=0, mode=0o600, maximum=32)
    C._verify_recovery_xattrs(pid_path, "pidfile")
    if (
        root.st_ino != 54537721 or {item.name for item in path.iterdir()} != {socket_path.name, pid_path.name}
        or socket_path.is_symlink() or not stat.S_ISSOCK(socket.st_mode) or _acl(socket_path)
        or (socket.st_uid, socket.st_gid, stat.S_IMODE(socket.st_mode), socket.st_nlink, socket.st_size) != (0, 454, 0o770, 1, 0)
        or pid != b"35850" or _acl(pid_path) not in ([[]] if cleared is True else ([ACL, []] if cleared is None else [ACL]))
    ):
        raise C.BootstrapError("tainted VMNet runtime differs")
    try:
        os.kill(35850, 0)
    except ProcessLookupError:
        pass
    else:
        raise C.BootstrapError("stale VMNet PID is live or reused")
    return {"device": root.st_dev, "inode": root.st_ino, "pid_inode": pid_path.stat().st_ino, "socket_inode": socket.st_ino}
def _sudoers(path: Path, *, cleared: bool | None) -> dict[str, Any]:
    content = _fixed(path, "sudoers", cleared=cleared)
    entries = _acl(path)
    if entries not in ([[]] if cleared is True else ([ACL, []] if cleared is None else [ACL])) or (cleared is None and stat.S_IMODE(path.stat().st_mode) == 0o400 and entries):
        raise C.BootstrapError("tainted sudoers ACL differs")
    return {"inode": path.stat().st_ino, "sha256": C._sha256_bytes(content)}
def _stationary(state: dict[str, Path]) -> dict[str, str]:
    root = state["state"]; values = {}
    for key in ("start_stdout", "start_stderr", "socket_stdout", "socket_stderr"):
        prefix = "limactl-start" if key.startswith("start") else "socket-vmnet"
        suffix = key.rsplit("_", 1)[1]
        values[key] = C._sha256_bytes(_fixed(root / f"{prefix}-{SOURCE}.{suffix}", key))
    expected = {f"{prefix}-{SOURCE}.{suffix}" for prefix in ("limactl-start", "socket-vmnet") for suffix in ("stdout", "stderr")}
    if {path.name for path in root.iterdir() if SOURCE in path.name and path.suffix in {".stdout", ".stderr"}} != expected:
        raise C.BootstrapError("interrupted log frontier differs")
    if not _fixed(root / f"limactl-start-{SOURCE}.stderr", "start_stderr").endswith(b"[VZ] - vm state change: running\"\n"):
        raise C.BootstrapError("VM running evidence differs")
    if b"for process 35850\n" not in _fixed(root / f"socket-vmnet-{SOURCE}.stderr", "socket_stderr"):
        raise C.BootstrapError("socket PID evidence differs")
    return values
def _reject_final_pending(path: Path) -> None:
    pending = path.parent / f".{path.name}.pending"
    if (path.exists() or path.is_symlink()) and (pending.exists() or pending.is_symlink()):
        raise C.BootstrapError("interrupted final/pending state is ambiguous")
def _quiescent(lock: dict[str, Any], state: dict[str, Path]) -> None:
    C._assert_no_airgap_watchdog_process()
    if C._router_uid_processes():
        raise C.BootstrapError("UID454 process remains")
    C._assert_no_vm_process()
    receipt09 = Path(lock["paths"]["airgap_first_boot_receipt"])
    absent = [
        receipt09, receipt09.parent / f".{receipt09.name}.pending",
        state["receipts"] / f"09-airgap-first-boot-incident-{SOURCE}.json",
        state["receipts"] / f".09-airgap-first-boot-incident-{SOURCE}.json.pending",
        state["state"] / f".airgap-hardware-base-capture-{SOURCE}.json.pending",
        state["state"] / f"airgap-hardware-base-capture-{SOURCE}-v2.json",
        state["state"] / f".airgap-hardware-base-capture-{SOURCE}-v2.json.pending",
        state["state"] / "airgap-watchdog-results" / f"{SOURCE}-watch.json",
        state["state"] / "airgap-watchdog-results" / f".{SOURCE}-watch.json.pending",
        state["state"] / "airgap-watchdog-results" / f"{SOURCE}-check.json",
        state["state"] / "airgap-watchdog-results" / f".{SOURCE}-check.json.pending",
        state["state"] / ".airgap-hardware-lock.json.pending",
    ]
    if any(path.exists() or path.is_symlink() for path in absent):
        raise C.BootstrapError("interrupted absence frontier differs")
    for path in (
        state["receipts"] / f"12-interrupted-first-boot-resume-authorization-{SOURCE}.json",
        state["quarantine"] / f"interrupted-first-boot-transaction-{SOURCE}.json",
        state["quarantine"] / f"interrupted-first-boot-stopped-proof-{SOURCE}.json",
        state["receipts"] / f"12-interrupted-first-boot-quarantine-{SOURCE}.json",
    ):
        _reject_final_pending(path)
def _fresh_absent(state: dict[str, Path]) -> None:
    receipt = state["receipts"] / f"12-interrupted-first-boot-quarantine-{FRESH}.json"
    authorization = state["receipts"] / f"12-interrupted-first-boot-resume-authorization-{FRESH}.json"
    transaction = state["quarantine"] / f"interrupted-first-boot-transaction-{FRESH}.json"
    proof = state["quarantine"] / f"interrupted-first-boot-stopped-proof-{FRESH}.json"
    paths = C._fresh_recovery_artifacts(state, FRESH) + [receipt, receipt.parent / f".{receipt.name}.pending", authorization, authorization.parent / f".{authorization.name}.pending", transaction, transaction.parent / f".{transaction.name}.pending", proof, proof.parent / f".{proof.name}.pending"]
    paths += [state["quarantine"] / f"interrupted-first-boot-{key}-{FRESH}" for key in ORDER]
    if any(path.exists() or path.is_symlink() for path in paths):
        raise C.BootstrapError("fresh interrupted-recovery namespace differs")
def _process_home(lock: dict[str, Any], transaction_exists: bool) -> dict[str, int]:
    final = Path(lock["paths"]["lima_process_home"])
    pending = final.parent / f".{final.name}-{SOURCE}.pending"
    if not transaction_exists and any(path.exists() or path.is_symlink() for path in (final, pending)):
        raise C.BootstrapError("process HOME predates transaction")
    if final.exists() or final.is_symlink():
        if pending.exists() or pending.is_symlink():
            raise C.BootstrapError("process HOME state is ambiguous")
        item = C._assert_real(final, kind="directory", uid=454, gid=454, mode=0o700)
        return {"device": item.st_dev, "inode": item.st_ino}
    if not pending.exists() and not pending.is_symlink():
        pending.mkdir(mode=0o700)
        os.chown(pending, 454, 454)
        os.chmod(pending, 0o700)
    else:
        item = pending.lstat()
        if pending.is_symlink() or not stat.S_ISDIR(item.st_mode) or item.st_uid not in {0, 454} or item.st_gid not in {0, 454} or stat.S_IMODE(item.st_mode) != 0o700 or any(pending.iterdir()) or _acl(pending):
            raise C.BootstrapError("pending process HOME differs")
        os.chown(pending, 454, 454)
    C._sync_directory(pending); C._sync_directory(pending.parent)
    C._rename_exclusive(pending, final)
    item = C._assert_real(final, kind="directory", uid=454, gid=454, mode=0o700)
    return {"device": item.st_dev, "inode": item.st_ino}
def _empty_lima_store(lock: dict[str, Any], limactl: Path) -> None:
    result = subprocess.run(
        [str(limactl), "--log-level=error", "list", "--format=json"],
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env=C._environment(lock), cwd=C._process_home(lock),
        preexec_fn=C._drop_preexec(454, 454),
        timeout=30, check=False,
    )
    if result.returncode != 0 or result.stdout or result.stderr:
        raise C.BootstrapError("post-quarantine Lima store is not empty")
def _installing(lock: dict[str, Any], state: dict[str, Path], completing_manifest: str) -> bool:
    path = state["state"] / ".hardened-vm.INSTALLING.json"
    if not path.exists() and not path.is_symlink():
        return False
    content = C._read_bound(path, uid=0, gid=0, mode=0o400, maximum=4096); C._no_named_acl(path)
    expected = {
        "controller_manifest_sha256": completing_manifest,
        "hardened_plan_sha256": lock["pins"]["hardened_plan_sha256"],
        "kind": "trading-desk.router-bootstrap.installing",
        "networks_first_boot_sha256": lock["pins"]["networks_first_boot_sha256"],
        "phase": "hardened-vm",
        "predecessor_vm_receipt_sha256": lock["pins"]["predecessor_vm_receipt_sha256"],
        "schema_version": 1,
    }
    if content != C._canonical_json(expected):
        raise C.BootstrapError("recreated VM INSTALLING marker differs")
    return True
def _resume_authorization(lock: dict[str, Any], state: dict[str, Path], completing_manifest: str, transaction_sha256: str) -> tuple[str, str, dict[str, Any]]:
    if C.SHA256_RE.fullmatch(TRANSACTION_SHA256) is None or transaction_sha256 != TRANSACTION_SHA256:
        raise C.BootstrapError("predecessor transaction digest is not authorized")
    stop_line = {
        "executor_started": False, "mainnet_authorized": False,
        "network_reconnect_authorized": False,
        "router_key_generation_authorized": False,
        "unconstrained_vm_start_authorized": False,
        "venue_credentials_authorized": False, "venue_writes_authorized": False,
    }
    if lock.get("stop_line") != stop_line:
        raise C.BootstrapError("resume authorization stop line differs")
    path = state["receipts"] / f"12-interrupted-first-boot-resume-authorization-{SOURCE}.json"
    _reject_final_pending(path)
    content = C._read_bound(path, uid=0, gid=0, mode=0o400, maximum=4096); C._no_named_acl(path)
    expected = {
        "completing_recovery_controller_manifest_sha256": completing_manifest,
        "initiating_recovery_controller_manifest_sha256": PREDECESSOR_RECOVERY_MANIFEST,
        "kind": "trading-desk.router-bootstrap.interrupted-first-boot-resume-authorization",
        "mainnet_authorized": False,
        "network_changes_authorized": False,
        "recreation_authorized": True,
        "schema_version": 1, "source_session_id": SOURCE,
        "stop_line": stop_line,
        "transaction_sha256": transaction_sha256,
        "venue_writes_authorized": False,
    }
    if content != C._canonical_json(expected):
        raise C.BootstrapError("interrupted recovery resume authorization differs")
    return str(path), C._sha256_bytes(content), expected
def _transaction(lock: dict[str, Any], state: dict[str, Path], content: bytes) -> dict[str, Any]:
    value = C._load_json_bytes(content, "interrupted transaction")
    paths = _paths(lock, state)
    fixed = {
        "failed_controller_manifest_sha256": FAILED_MANIFEST, "fresh_session_id": FRESH,
        "kind": "trading-desk.router-bootstrap.interrupted-first-boot-transaction",
        "moves": [{"destination": str(paths[key][1]), "key": key, "source": str(paths[key][0])} for key in ORDER],
        "schema_version": 1, "source_session_id": SOURCE,
    }
    if set(value) != set(fixed) | {"instance", "library", "old_receipt08", "recovery_controller_manifest_sha256", "runtime", "stationary_logs", "sudoers"} or {key: value.get(key) for key in fixed} != fixed or value.get("recovery_controller_manifest_sha256") != PREDECESSOR_RECOVERY_MANIFEST:
        raise C.BootstrapError("interrupted transaction differs")
    return value
def _retained(lock: dict[str, Any], state: dict[str, Path], value: dict[str, Any]) -> None:
    paths = _paths(lock, state)
    receipt, specification = _old_receipt(lock, paths["receipt08"][1])
    if (
        _library(paths["library"][1]) != value["library"]
        or _opaque_instance(paths["instance"][1], receipt) != value["instance"]
        or _runtime(paths["runtime"][1], cleared=True) != value["runtime"]
        or _sudoers(paths["sudoers"][1], cleared=True) != value["sudoers"]
        or specification != value["old_receipt08"]
        or _stationary(state) != value["stationary_logs"]
        or any(paths[key][0].exists() or paths[key][0].is_symlink() for key in ("library", "runtime", "sudoers"))
    ):
        raise C.BootstrapError("retained interrupted evidence differs")
    for key in ("base", "hardware_lock", "preparing", "starting"):
        _fixed(paths[key][1], key)
        if paths[key][0].exists() or paths[key][0].is_symlink():
            raise C.BootstrapError("interrupted source evidence reappeared")
def _proof(lock: dict[str, Any], state: dict[str, Path], transaction_sha256: str) -> tuple[dict[str, Any], bytes]:
    source = state["quarantine"] / f"interrupted-first-boot-stopped-proof-{SOURCE}.json"
    _reject_final_pending(source)
    proof_content = C._read_bound(source, uid=0, gid=0, mode=0o400, maximum=64 * 1024); C._no_named_acl(source)
    if C._sha256_bytes(proof_content) != STOPPED_PROOF_SHA256:
        raise C.BootstrapError("predecessor stopped proof digest differs")
    proof = C._load_json_bytes(proof_content, "interrupted stopped proof")
    home = C._assert_real(Path(lock["paths"]["lima_process_home"]), kind="directory", uid=454, gid=454, mode=0o700)
    proof_expected = {
        "kind": "trading-desk.router-bootstrap.interrupted-first-boot-stopped-proof",
        "process_home_device": home.st_dev, "process_home_inode": home.st_ino,
        "schema_version": 1, "source_session_id": SOURCE,
        "status_sha256": proof.get("status_sha256"), "transaction_sha256": transaction_sha256,
        "vm_status": "Stopped",
    }
    if proof != proof_expected or C.SHA256_RE.fullmatch(proof.get("status_sha256", "")) is None:
        raise C.BootstrapError("interrupted stopped proof differs")
    return proof, proof_content
def _receipt(lock: dict[str, Any], state: dict[str, Path], value: dict[str, Any], transaction_sha256: str, completing_manifest: str) -> tuple[dict[str, Any], str]:
    _proof_value, proof_content = _proof(lock, state, transaction_sha256)
    authorization_path, authorization_sha256, authorization = _resume_authorization(lock, state, completing_manifest, transaction_sha256)
    home = Path(lock["paths"]["lima_process_home"]).stat()
    transaction_path = state["quarantine"] / f"interrupted-first-boot-transaction-{SOURCE}.json"
    expected = {
        "automatic_retry_authorized": False, "credentials_accessed": False,
        "disk_reuse_authorized": False, "failed_controller_manifest_sha256": FAILED_MANIFEST,
        "fresh_session_id": FRESH,
        "kind": "trading-desk.router-bootstrap.interrupted-first-boot-quarantine",
        "mainnet_authorized": False, "network_changes_performed": False,
        "process_home_device": home.st_dev, "process_home_inode": home.st_ino,
        "quarantined_paths": [item["destination"] for item in value["moves"]],
        "resume_authorization": authorization,
        "resume_authorization_path": authorization_path,
        "resume_authorization_sha256": authorization_sha256,
        "initiating_recovery_controller_manifest_sha256": PREDECESSOR_RECOVERY_MANIFEST,
        "completing_recovery_controller_manifest_sha256": completing_manifest,
        "recreation_authorized": True, "schema_version": 1,
        "source_session_id": SOURCE, "source_vm_status": "Stopped", "start_invoked": True,
        "stopped_proof_sha256": C._sha256_bytes(proof_content),
        "transaction_path": str(transaction_path), "transaction_sha256": transaction_sha256,
        "venue_writes_authorized": False, "vm_boot_observed": True,
    }
    path = state["receipts"] / f"12-interrupted-first-boot-quarantine-{SOURCE}.json"
    _reject_final_pending(path)
    content = C._read_bound(path, uid=0, gid=0, mode=0o400, maximum=128 * 1024); C._no_named_acl(path)
    actual = C._load_json_bytes(content, "interrupted quarantine receipt")
    if actual != expected:
        raise C.BootstrapError("interrupted quarantine receipt differs")
    return actual, C._sha256_bytes(content)
def _handoff(lock: dict[str, Any], state: dict[str, Path], digest: str, completing_manifest: str) -> None:
    path = state["quarantine"] / f"interrupted-first-boot-transaction-{SOURCE}.json"
    _reject_final_pending(path)
    content = C._read_bound(path, uid=0, gid=0, mode=0o400, maximum=256 * 1024); C._no_named_acl(path)
    transaction = _transaction(lock, state, content)
    _retained(lock, state, transaction)
    _value, observed = _receipt(lock, state, transaction, C._sha256_bytes(content), completing_manifest)
    sources = {key: source.exists() or source.is_symlink() for key, (source, _destination) in _paths(lock, state).items()}
    installing = _installing(lock, state, completing_manifest)
    if (
        observed != digest or any(present for key, present in sources.items() if key not in {"instance", "receipt08"})
        or (sources["instance"] and not installing)
        or (sources["receipt08"] and (not installing or _new_receipt(lock, state, digest, completing_manifest, C._sha256_bytes(content), route_installing=False) is None))
    ):
        raise C.BootstrapError("interrupted recreate handoff differs")
    _quiescent(lock, state); _fresh_absent(state)
def _new_receipt(lock: dict[str, Any], state: dict[str, Path], digest: str, completing_manifest: str, transaction_sha256: str, *, route_installing: bool = True) -> tuple[Path, str] | None:
    _resume_authorization(lock, state, completing_manifest, transaction_sha256)
    path = Path(lock["paths"]["hardened_vm_receipt"])
    instance = Path(lock["paths"]["lima_home"]) / lock["guest"]["instance_name"]
    if not path.exists() and not path.is_symlink():
        return None
    content = C._read_bound(path, uid=0, gid=0, mode=0o400, maximum=256 * 1024); C._no_named_acl(path)
    value = C._load_json_bytes(content, "recreated receipt08")
    if (
        value.get("interrupted_first_boot_quarantine_receipt_sha256") != digest
        or value.get("active_controller_manifest_sha256") != completing_manifest
        or value.get("disk_sha256") != lock["pins"]["predecessor_disk_sha256"]
        or value.get("vm_status") != "Stopped" or value.get("vm_started") is not False
        or (value.get("ready_for_attended_airgapped_start"), value.get("network_changes_performed"), value.get("network_reconnect_authorized"), value.get("venue_writes_authorized"), value.get("mainnet_authorized")) != (True, False, False, False, False)
        or not instance.is_dir()
    ):
        raise C.BootstrapError("recreated receipt08 differs")
    C._hardened_instance_evidence(lock, value, allow_runtime_files=False)
    if _installing(lock, state, completing_manifest) and route_installing:
        return None
    return path, C._sha256_bytes(content)
def recover(args: argparse.Namespace) -> int:
    C._verify_bundle(args.expected_controller_manifest_sha256)
    lock = C._load_lock()
    if not lock["phases"]["interrupted_first_boot_recovery_enabled"]:
        raise C.BootstrapError("interrupted first-boot recovery is disabled")
    state = C._require_existing_state(lock)
    C._verify_system_tools(lock)
    C._assert_attended_root_tty()
    C._assert_host_identity(lock)
    before_network = C._network_snapshot()
    paths = _paths(lock, state)
    transaction_path = state["quarantine"] / f"interrupted-first-boot-transaction-{SOURCE}.json"
    receipt_path = state["receipts"] / f"12-interrupted-first-boot-quarantine-{SOURCE}.json"
    _quiescent(lock, state); _fresh_absent(state)
    transaction_exists = transaction_path.exists() or transaction_path.is_symlink()
    _reject_final_pending(transaction_path)
    if not transaction_exists:
        raise C.BootstrapError("predecessor recovery transaction is absent")
    transaction_content = C._read_bound(transaction_path, uid=0, gid=0, mode=0o400, maximum=256 * 1024); C._no_named_acl(transaction_path)
    transaction = _transaction(lock, state, transaction_content)
    transaction_sha256 = C._sha256_bytes(transaction_content)
    if args.expected_controller_manifest_sha256 == PREDECESSOR_RECOVERY_MANIFEST:
        raise C.BootstrapError("completing recovery controller did not advance")
    authorization_path, authorization_sha256, authorization = _resume_authorization(lock, state, args.expected_controller_manifest_sha256, transaction_sha256)
    if receipt_path.exists() or receipt_path.is_symlink():
        _retained(lock, state, transaction)
        _receipt_value, digest = _receipt(lock, state, transaction, transaction_sha256, args.expected_controller_manifest_sha256)
    else:
        current = {key: C._recovery_current_path(*move) for key, move in paths.items()}
        for key in ("base", "hardware_lock", "preparing", "starting"):
            _fixed(current[key], key)
        receipt08, receipt_spec = _old_receipt(lock, current["receipt08"])
        if (
            _library(current["library"]) != transaction["library"]
            or _opaque_instance(current["instance"], receipt08) != transaction["instance"]
            or _runtime(current["runtime"], cleared=None) != transaction["runtime"]
            or _sudoers(current["sudoers"], cleared=None) != transaction["sudoers"]
            or receipt_spec != transaction["old_receipt08"] or _stationary(state) != transaction["stationary_logs"]
        ):
            raise C.BootstrapError("interrupted evidence changed")
        if current["library"] == paths["library"][0]:
            C._rename_exclusive(*paths["library"])
        home = _process_home(lock, True)
        _quiescent(lock, state)
        limactl = C._limactl(lock)
        proof_path = state["quarantine"] / f"interrupted-first-boot-stopped-proof-{SOURCE}.json"
        instance_current = C._recovery_current_path(*paths["instance"])
        if instance_current == paths["instance"][0]:
            status = C._status(lock, limactl)
            if status.get("sshLocalPort") != 50506:
                raise C.BootstrapError("interrupted stopped status differs")
            proof = {
                "kind": "trading-desk.router-bootstrap.interrupted-first-boot-stopped-proof",
                "process_home_device": home["device"], "process_home_inode": home["inode"],
                "schema_version": 1, "source_session_id": SOURCE,
                "status_sha256": C._sha256_bytes(C._canonical_json(status)),
                "transaction_sha256": transaction_sha256, "vm_status": "Stopped",
            }
            C._atomic_receipt(state["quarantine"], proof_path.name, proof)
        _proof_value, proof_content = _proof(lock, state, transaction_sha256)
        _quiescent(lock, state)
        C._resume_recovery_moves((paths["instance"],))
        runtime = C._recovery_current_path(*paths["runtime"])
        if runtime == paths["runtime"][0]:
            pid = runtime / "td-router-ingress_socket_vmnet.pid"
            if _acl(pid):
                C._clear_router_pid_read_acl(pid)
            C._resume_recovery_moves((paths["runtime"],))
        sudoers = C._recovery_current_path(*paths["sudoers"])
        if sudoers == paths["sudoers"][0]:
            if _acl(sudoers):
                C._clear_router_sudoers_read_acl(sudoers)
            os.chmod(sudoers, 0o400)
            C._sync_file(sudoers)
            C._resume_recovery_moves((paths["sudoers"],))
        for key in ORDER:
            if key not in {"library", "instance", "runtime", "sudoers"}:
                C._resume_recovery_moves((paths[key],))
        _quiescent(lock, state)
        _empty_lima_store(lock, limactl)
        if any(path.exists() or path.is_symlink() for path, _destination in paths.values()):
            raise C.BootstrapError("live Lima instance remains")
        _retained(lock, state, transaction)
        receipt = {
            "automatic_retry_authorized": False, "credentials_accessed": False,
            "disk_reuse_authorized": False, "failed_controller_manifest_sha256": FAILED_MANIFEST,
            "fresh_session_id": FRESH,
            "kind": "trading-desk.router-bootstrap.interrupted-first-boot-quarantine",
            "mainnet_authorized": False, "network_changes_performed": False,
            "process_home_device": home["device"], "process_home_inode": home["inode"],
            "quarantined_paths": [item["destination"] for item in transaction["moves"]],
            "resume_authorization": authorization,
            "resume_authorization_path": authorization_path,
            "resume_authorization_sha256": authorization_sha256,
            "initiating_recovery_controller_manifest_sha256": PREDECESSOR_RECOVERY_MANIFEST,
            "completing_recovery_controller_manifest_sha256": args.expected_controller_manifest_sha256,
            "recreation_authorized": True, "schema_version": 1,
            "source_session_id": SOURCE, "source_vm_status": "Stopped", "start_invoked": True,
            "stopped_proof_sha256": C._sha256_bytes(proof_content),
            "transaction_path": str(transaction_path), "transaction_sha256": transaction_sha256,
            "venue_writes_authorized": False, "vm_boot_observed": True,
        }
        _fresh_absent(state)
        if C._network_snapshot() != before_network:
            raise C.BootstrapError("network changed during quarantine")
        _path, digest = C._atomic_receipt(state["receipts"], receipt_path.name, receipt)
        _receipt(lock, state, transaction, transaction_sha256, args.expected_controller_manifest_sha256)
    recreated = _new_receipt(lock, state, digest, args.expected_controller_manifest_sha256, transaction_sha256)
    if recreated is None:
        os.close(state["lock_descriptor"])
        state["lock_descriptor"] = -1
        setattr(args, "_interrupted_quarantine_receipt_sha256", digest)
        setattr(args, "_interrupted_authorization_validator", lambda lock, state, digest: _handoff(lock, state, digest, args.expected_controller_manifest_sha256))
        C._apply_hardened_vm(args)
        recreated = _new_receipt(lock, state, digest, args.expected_controller_manifest_sha256, transaction_sha256)
        if recreated is None:
            raise C.BootstrapError("recreated receipt08 is absent")
    print(f"interrupted_first_boot_quarantine_receipt_sha256={digest}")
    print(f"recreated_hardened_vm_receipt={recreated[0]}")
    print(f"recreated_hardened_vm_receipt_sha256={recreated[1]}")
    print(f"fresh_session_id={FRESH}")
    print("vm_status=Stopped")
    print("network_reconnect_authorized=false")
    return 0
def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("phase", choices=["recover-interrupted-first-boot"])
    parser.add_argument("--expected-controller-manifest-sha256", required=True)
    args = parser.parse_args()
    try:
        return recover(args)
    except (C.BootstrapError, OSError, KeyError, TypeError, ValueError) as error:
        print(f"router_interrupted_recovery_failed: {error}", file=C.sys.stderr)
        return 2
if __name__ == "__main__":
    raise SystemExit(main())
