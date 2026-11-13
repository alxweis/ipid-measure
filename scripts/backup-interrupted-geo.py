#!/usr/bin/env python3
"""Preserve the four known interrupted Geo RT runs; never resume or commit them.

Run as root on a stopped ICMP VM. S3 commands use the measurement user's existing
configuration. Sources remain untouched. Every object is read back and SHA256
verified before a separate recovery receipt is published.
"""

import argparse
import ast
import ctypes
import ctypes.util
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import json
import os
import pwd
from pathlib import Path
import subprocess
import stat
import re
import tempfile


CAMPAIGN = "geo-full-20261107-r1"
RUNS = {
    "sa": ("icmp_2026-11-08_03-04-51", "icmp_2026-11-07_03-50-17", "26566"),
    "af": ("icmp_2026-11-08_03-27-48", "icmp_2026-11-07_04-10-15", "24756"),
    "as": ("icmp_2026-11-08_03-15-32", "icmp_2026-11-07_04-00-21", "26384"),
    "au": ("icmp_2026-11-08_03-37-59", "icmp_2026-11-07_04-20-21", "24145"),
}
CHUNK = 8 << 20
LOG_ROOT = Path("/var/log/ipid-recovery")


def set_acl(path, text, default=False):
    """Set a narrow Linux ACL without installing packages on live VMs."""
    library = ctypes.util.find_library("acl")
    if not library:
        raise RuntimeError("libacl is unavailable; no permission fallback applied")
    lib = ctypes.CDLL(library, use_errno=True)
    lib.acl_from_text.argtypes = [ctypes.c_char_p]
    lib.acl_from_text.restype = ctypes.c_void_p
    lib.acl_valid.argtypes = [ctypes.c_void_p]
    lib.acl_valid.restype = ctypes.c_int
    lib.acl_set_file.argtypes = [ctypes.c_char_p, ctypes.c_int, ctypes.c_void_p]
    lib.acl_set_file.restype = ctypes.c_int
    lib.acl_free.argtypes = [ctypes.c_void_p]
    lib.acl_free.restype = ctypes.c_int
    acl = lib.acl_from_text(text.encode())
    if not acl:
        raise OSError(ctypes.get_errno(), "Cannot parse metadata ACL")
    try:
        if lib.acl_valid(acl) or lib.acl_set_file(os.fsencode(path), 0x4000 if default else 0x8000, acl):
            raise OSError(ctypes.get_errno(), "Cannot set metadata ACL", str(path))
    finally:
        lib.acl_free(acl)


def prepare_metadata(workspace, mid, user="aweis"):
    uid = pwd.getpwnam(user).pw_uid
    parent = workspace / "recovery-backup"
    local = parent / mid
    for directory in (parent, local):
        directory.mkdir(mode=0o700, exist_ok=True)
        if directory.is_symlink() or directory.resolve() != directory or not directory.is_dir():
            raise RuntimeError(f"Unexpected metadata directory: {directory}")
        if directory.stat().st_uid not in {os.geteuid(), uid}:
            raise RuntimeError(f"Unexpected metadata owner: {directory}")
    # The uploader can traverse the private parent and read metadata, but does
    # not get write permission or access to other users' homes/credentials.
    set_acl(parent, f"u::rwx,u:{uid}:--x,g::---,m::--x,o::---")
    access = f"u::rwx,u:{uid}:r-x,g::---,m::r-x,o::---"
    set_acl(local, access)
    set_acl(local, access, default=True)
    for path in (*local.glob("original-scanner-*.journal.jsonl"), *local.glob("backup-verified-*.json")):
        if path.is_symlink() or not path.is_file() or path.stat().st_uid not in {os.geteuid(), uid}:
            raise RuntimeError(f"Unexpected metadata file: {path}")
        set_acl(path, f"u::rw-,u:{uid}:r--,g::---,m::r--,o::---")
    return local


def run(argv, **kwargs):
    return subprocess.run(argv, check=True, **kwargs)


def identity(path):
    value = path.stat()
    return value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns


def digest_stream(stream):
    digest = hashlib.sha256()
    size = 0
    while chunk := stream.read(CHUNK):
        digest.update(chunk)
        size += len(chunk)
    return {"size_bytes": size, "sha256": digest.hexdigest()}


def evidence(path):
    if path.is_symlink() or not path.is_file():
        raise RuntimeError(f"Not a regular source file: {path}")
    before = identity(path)
    with path.open("rb") as stream:
        value = digest_stream(stream)
    if identity(path) != before or value["size_bytes"] != before[2]:
        raise RuntimeError(f"Source changed while hashing: {path}")
    return value, before


def assert_unchanged(path, before):
    if path.is_symlink() or identity(path) != before:
        raise RuntimeError(f"Source changed during backup: {path}")


@contextmanager
def runner_lock(workspace):
    import fcntl
    # Match the controller's flock, without creating/replacing any state file.
    with (workspace / ".runner.lock").open("r+") as stream:
        fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield


def assert_inactive():
    state = run(
        ["systemctl", "show", "measurement-ipid.service", "-p", "ActiveState", "--value"],
        capture_output=True, text=True,
    ).stdout.strip()
    if state not in {"inactive", "failed"}:
        raise RuntimeError(f"Measurement service is {state}; refusing backup")
    running = subprocess.run([
        "pgrep", "-u", "aweis", "-f",
        r"[r]un-continental|[/]bin/measure-(ipid|zmap|interprotocol)( |$)",
    ], capture_output=True, text=True)
    if running.returncode != 1:
        raise RuntimeError(f"Cannot establish that measurements stopped: {running.stdout}")


class Store:
    def __init__(self, user="aweis"):
        self.command = ["sudo", "-H", "-u", user, "s3cmd"]

    def exists(self, uri):
        result = run(self.command + ["ls", uri], capture_output=True, text=True)
        return any(line.split() and line.split()[-1] == uri
                   for line in result.stdout.splitlines())

    def remote_size(self, uri):
        result = run(self.command + ["ls", uri], capture_output=True, text=True)
        for line in result.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 4 and parts[-1] == uri and parts[-2].isdigit():
                return int(parts[-2])
        return None

    def verify(self, uri, expected):
        # Read back without downloading another 50-75 GB file to the VM disk.
        with tempfile.TemporaryFile() as error:
            process = subprocess.Popen(
                self.command + ["get", "--no-progress", uri, "-"],
                stdout=subprocess.PIPE, stderr=error,
            )
            try:
                with process.stdout:
                    actual = digest_stream(process.stdout)
                status = process.wait()
            except BaseException:
                process.kill()
                process.wait()
                raise
            if status:
                error.seek(0)
                raise RuntimeError(f"S3 read-back failed ({status}): {error.read(8192)!r}")
        if actual != expected:
            raise RuntimeError(f"S3 size/SHA256 mismatch: {uri}; expected={expected}, actual={actual}")

    def preserve(self, path, uri, expected, before):
        assert_unchanged(path, before)
        if not self.exists(uri):
            print(f"Uploading {path} -> {uri}", flush=True)
            run(self.command + [
                "put", "--no-progress", "--multipart-chunk-size-mb=1024", str(path), uri,
            ])
        print(f"Reading back and verifying: {uri}", flush=True)
        self.verify(uri, expected)
        assert_unchanged(path, before)


def validate_workspace(repo, site):
    mid, zid, _ = RUNS[site]
    workspace = repo / "parallel" / CAMPAIGN / site / "icmp"
    if workspace.is_symlink() or workspace.resolve() != workspace:
        raise RuntimeError("Unexpected workspace or symlink")
    state = json.loads((workspace / "state.json").read_text())
    if state.get("version") != 1 or set(state.get("steps", {})) != {"icmp-rt", "zmap-icmp"}:
        raise RuntimeError("Unexpected steps; inspect before backing up")
    for step, expected in (("icmp-rt", mid), ("zmap-icmp", zid)):
        if state["steps"][step]["id"] != expected:
            raise RuntimeError(f"Unexpected {step} ID")
    rt = workspace / "ipid/raw" / mid
    data = rt / "ipid.pq"
    if data.stat().st_size < 12:
        raise RuntimeError("RT file too short")
    with data.open("rb") as stream:
        first = stream.read(4)
        stream.seek(-4, 2)
        last = stream.read(4)
    if first != b"PAR1" or last != b"PAR1":
        raise RuntimeError("RT file has no closed Parquet signature")
    return workspace, rt, state


def checkpoint_log(path, sources, root):
    """Recover exact per-file read-back proofs from a private original log."""
    verified = {}
    current = None
    remote = None
    for line in path.read_text(errors="strict").splitlines():
        if line.startswith("Hashing: "):
            current = Path(line[len("Hashing: "):])
            remote = None
        elif line.startswith("Reading back and verifying: "):
            remote = line[len("Reading back and verifying: "):]
        elif line.startswith("VERIFIED: "):
            name, raw = line[len("VERIFIED: "):].split(": ", 1)
            if name not in sources or current != sources[name] or name in verified:
                raise RuntimeError("Ambiguous or mismatched prior file verification")
            value = ast.literal_eval(raw)
            if (not isinstance(value, dict) or set(value) != {"size_bytes", "sha256"}
                or type(value["size_bytes"]) is not int or value["size_bytes"] <= 0
                or not isinstance(value["sha256"], str)
                or not re.fullmatch(r"[0-9a-f]{64}", value["sha256"])):
                raise RuntimeError("Invalid prior file verification")
            if remote != f"{root}/sha256-{value['sha256']}/{name}":
                raise RuntimeError("Prior read-back URI differs from the expected recovery object")
            verified[name] = value
    return verified


def continue_backup(args):
    """Finish metadata after a failed attempt; never repeat bulk read-back."""
    if os.geteuid() != 0:
        raise RuntimeError("Run this preservation continuation as root")
    repo = Path(args.repo).resolve()
    workspace, rt, state = validate_workspace(repo, args.site)
    with runner_lock(workspace):
        assert_inactive()
        workspace, rt, state = validate_workspace(repo, args.site)
        mid, zid, _ = RUNS[args.site]
        local = prepare_metadata(workspace, mid)
        old_log = Path(args.continue_from_log)
        if (old_log.parent != LOG_ROOT or old_log.is_symlink() or not old_log.is_file()
            or not re.fullmatch(rf"{args.site}-\d{{8}}T\d{{6,18}}Z\.log", old_log.name)):
            raise RuntimeError("Unexpected original backup-log path")
        log_stat = old_log.stat()
        if log_stat.st_uid != 0 or log_stat.st_mode & (stat.S_IWGRP | stat.S_IWOTH) or log_stat.st_size > 8 << 20:
            raise RuntimeError("Backup log is not private root-owned checkpoint evidence")
        raw = old_log.read_text()
        if "BACKUP VERIFIED; originals unchanged." in raw:
            print("Original backup already completed; no continuation needed.", flush=True)
            return
        journal_paths = {
            Path(line[len("Hashing: "):]) for line in raw.splitlines()
            if line.startswith(f"Hashing: {local}/original-scanner-") and line.endswith(".journal.jsonl")
        }
        if len(journal_paths) != 1:
            raise RuntimeError("No unambiguous frozen journal in the original attempt")
        journal = journal_paths.pop()
        if journal.parent != local or journal.is_symlink() or not journal.is_file():
            raise RuntimeError("Unexpected frozen journal source")
        sources = {
            "ipid.pq": rt / "ipid.pq",
            "ipid.snapshot.yaml": rt / "ipid.snapshot.yaml",
            "state.json": workspace / "state.json",
            "zmap.pq": workspace / "zmap/raw" / zid / "zmap.pq",
            "zmap.snapshot.yaml": workspace / "zmap/raw" / zid / "zmap.snapshot.yaml",
            "original-scanner.journal.jsonl": journal,
        }
        root = f"{args.s3_root.rstrip('/')}/recovery/{CAMPAIGN}/{args.site}/icmp/{mid}"
        verified = checkpoint_log(old_log, sources, root)
        if set(sources) - {"original-scanner.journal.jsonl"} - set(verified):
            raise RuntimeError("Prior attempt has not verified all five original data/config files; refusing expensive automatic retry")
        # Reuse the earlier full remote read-backs as this same attempt would;
        # a HEAD/list-size check detects missing/truncated objects, not arbitrary
        # later equal-size administrative overwrites (Object Lock is not used).
        # The old process lost its in-memory inode/mtime table. Bulk source
        # hashes refer to the earlier verification, not a new local content
        # check. The RT resume admission independently rehashes those local
        # sources before probing, so do not duplicate that expensive read here.
        store = Store()
        manifest = {
            "version": 1, "purpose": "interrupted-rt-preservation-not-measurement-completion",
            "campaign_id": CAMPAIGN, "site": args.site, "measurement_id": mid,
            "zmap_id": zid, "state_binding": state["binding"], "files": {},
            "prior_verification_log": {"path": str(old_log), "sha256": evidence(old_log)[0]["sha256"]},
            "bulk_source_validation": "Earlier full SHA256 read-back proof reused; current local/remote sizes checked. Resume must independently revalidate current local content.",
        }
        identities = {}
        for name, path in sources.items():
            if name in verified and name.endswith(".pq"):
                if path.is_symlink() or not path.is_file():
                    raise RuntimeError(f"Unexpected bulk source: {path}")
                before = identity(path)
                expected = verified[name]
                if before[2] != expected["size_bytes"]:
                    raise RuntimeError(f"Prior verified source/object differs or is missing: {name}")
            else:
                print(f"Hashing local metadata: {path}", flush=True)
                expected, before = evidence(path)
            uri = f"{root}/sha256-{expected['sha256']}/{name}"
            if name in verified:
                if expected != verified[name] or store.remote_size(uri) != expected["size_bytes"]:
                    raise RuntimeError(f"Prior verified source/object differs or is missing: {name}")
                print(f"REUSED prior full read-back proof: {name}: {expected}", flush=True)
            else:
                store.preserve(path, uri, expected, before)
                print(f"VERIFIED: {name}: {expected}", flush=True)
            manifest["files"][name] = {**expected, "uri": uri, "local_path": str(path)}
            identities[path] = before
        assert_inactive()
        for path, before in identities.items():
            assert_unchanged(path, before)
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
        receipt = local / f"backup-verified-{stamp}.json"
        with receipt.open("x") as stream:
            json.dump(manifest, stream, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        value, before = evidence(receipt)
        uri = f"{root}/receipts/sha256-{value['sha256']}/backup-verified.json"
        store.preserve(receipt, uri, value, before)
        print(f"BACKUP VERIFIED; originals unchanged. Receipt: {uri}", flush=True)


def backup(args):
    if os.geteuid() != 0:
        raise RuntimeError("Run this preservation script as root")
    repo = Path(args.repo).resolve()
    workspace, rt, state = validate_workspace(repo, args.site)
    with runner_lock(workspace):
        assert_inactive()
        # Re-read after acquiring the same lock as run-continental.
        workspace, rt, state = validate_workspace(repo, args.site)
        mid, zid, pid = RUNS[args.site]
        local = prepare_metadata(workspace, mid)
        log = run([
            "journalctl", "--utc", "_SYSTEMD_UNIT=measurement-ipid.service", f"_PID={pid}",
            "-g", r"replies_final\[|records before error|interrupt received|estimated_time_left=",
            "-n", "12", "--no-pager", "-o", "json",
        ], capture_output=True, text=True).stdout
        # Unique metadata snapshot; subsequent retries never rewrite prior snapshots.
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
        log_path = local / f"original-scanner-{stamp}.journal.jsonl"
        with log_path.open("x") as stream:
            stream.write(log)
        sources = {
            "ipid.pq": rt / "ipid.pq",
            "ipid.snapshot.yaml": rt / "ipid.snapshot.yaml",
            "state.json": workspace / "state.json",
            "zmap.pq": workspace / "zmap/raw" / zid / "zmap.pq",
            "zmap.snapshot.yaml": workspace / "zmap/raw" / zid / "zmap.snapshot.yaml",
            "original-scanner.journal.jsonl": log_path,
        }
        store = Store()
        root = f"{args.s3_root.rstrip('/')}/recovery/{CAMPAIGN}/{args.site}/icmp/{mid}"
        manifest = {
            "version": 1, "purpose": "interrupted-rt-preservation-not-measurement-completion",
            "campaign_id": CAMPAIGN, "site": args.site, "measurement_id": mid,
            "zmap_id": zid, "state_binding": state["binding"], "files": {},
        }
        identities = {}
        for name, path in sources.items():
            print(f"Hashing: {path}", flush=True)
            expected, before = evidence(path)
            uri = f"{root}/sha256-{expected['sha256']}/{name}"
            store.preserve(path, uri, expected, before)
            manifest["files"][name] = {**expected, "uri": uri, "local_path": str(path)}
            identities[path] = before
            print(f"VERIFIED: {name}: {expected}", flush=True)
        assert_inactive()
        for path, before in identities.items():
            assert_unchanged(path, before)
        receipt = local / f"backup-verified-{stamp}.json"
        with receipt.open("x") as stream:
            json.dump(manifest, stream, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        receipt_evidence, before = evidence(receipt)
        uri = f"{root}/receipts/sha256-{receipt_evidence['sha256']}/backup-verified.json"
        store.preserve(receipt, uri, receipt_evidence, before)
        print(f"BACKUP VERIFIED; originals unchanged. Receipt: {uri}", flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--site", required=True, choices=RUNS)
    parser.add_argument("--repo", default="/mnt/data01/ipid-measure")
    parser.add_argument("--s3-root", default="s3://netds3o:aweis/ipid-2/raw")
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--repair-metadata-access-only", action="store_true")
    modes.add_argument("--continue-from-log")
    args = parser.parse_args()
    if args.repair_metadata_access_only:
        if os.geteuid() != 0:
            raise RuntimeError("Run metadata-access repair as root")
        workspace, _, _ = validate_workspace(Path(args.repo).resolve(), args.site)
        assert_inactive()
        local = prepare_metadata(workspace, RUNS[args.site][0])
        print(f"Metadata access repaired: {local}; no process restarted or file contents changed.")
    elif args.continue_from_log:
        continue_backup(args)
    else:
        backup(args)

