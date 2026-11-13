#!/usr/bin/env python3
"""Preserve the four known interrupted Geo RT runs; never resume or commit them.

Run as root on a stopped ICMP VM. S3 commands use the measurement user's existing
configuration. Sources remain untouched. Newly preserved objects are read back
and SHA256 verified. Already committed ZMap objects are referenced through their
original scoped completion marker instead of uploaded/read back again.
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
import signal
import time
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
OLD_REVISION = "925067f98b37380f96bc16380d2981e721010066"


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

    def metadata(self, uri):
        data = run(self.command + ["get", "--no-progress", uri, "-"], capture_output=True).stdout
        if len(data) > 1 << 20:
            raise RuntimeError("Oversized scoped completion metadata")
        return data

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


def original_zmap(store, s3_root, workspace, site, zid):
    """Reference the already committed raw ZMap; never copy/read its S3 body."""
    root = f"{s3_root.rstrip('/')}/continental/{CAMPAIGN}/{site}/zmap/{zid}"
    uri = root + "/measurement-complete.json"
    raw = store.metadata(uri)
    marker = json.loads(raw)
    if marker.get("version") != 1 or marker.get("measurement_id") != zid:
        raise RuntimeError("Original ZMap completion marker has the wrong identity")
    files, identities = {}, {}
    for name in ("zmap.pq", "zmap.snapshot.yaml"):
        value = marker.get("files", {}).get(name)
        if (not isinstance(value, dict) or type(value.get("size_bytes")) is not int
            or value["size_bytes"] <= 0 or not isinstance(value.get("sha256"), str)
            or not re.fullmatch(r"[0-9a-f]{64}", value["sha256"])):
            raise RuntimeError(f"Original ZMap marker omits valid evidence: {name}")
        path = workspace / "zmap/raw" / zid / name
        if path.is_symlink() or not path.is_file() or path.resolve() != path:
            raise RuntimeError(f"Unexpected original ZMap source: {path}")
        before = identity(path)
        evidence_value = {"size_bytes": value["size_bytes"], "sha256": value["sha256"]}
        if before[2] != value["size_bytes"] or store.remote_size(root + "/" + name) != value["size_bytes"]:
            raise RuntimeError(f"Original committed ZMap object/source missing or size changed: {name}")
        if name.endswith(".yaml") and evidence(path)[0] != evidence_value:
            raise RuntimeError("Original ZMap snapshot differs from scoped commit")
        files[name] = {**evidence_value, "uri": root + "/" + name, "local_path": str(path)}
        identities[path] = before
    reference = {"version": 1, "measurement_id": zid, "completion_uri": uri,
                 "completion_sha256": hashlib.sha256(raw).hexdigest(),
                 "validation": "Existing scoped commit and object/local sizes; no duplicate ZMap upload or fresh remote body read-back. Resume rehashes local targets."}
    return files, reference, identities


def process(pid):
    root = Path('/proc') / str(pid)
    try:
        fields = (root / 'stat').read_text().rsplit(') ', 1)[1].split()
        if fields[0] == 'Z':
            return None
        args = (root / 'cmdline').read_bytes().decode().rstrip('\0').split('\0')
        return {'pid': pid, 'ppid': int(fields[1]), 'state': fields[0], 'start': fields[19], 'uid': root.stat().st_uid, 'args': args}
    except FileNotFoundError:
        return None

def legacy_process(log_path, site):
    pidfile = Path(str(log_path) + '.pid')
    if pidfile.is_symlink() or not pidfile.is_file() or pidfile.stat().st_uid != 0 or pidfile.stat().st_mode & 0o022:
        raise RuntimeError('Missing trusted backup PID file')
    current = process(int(pidfile.read_text().strip()))
    if current is None:
        return None
    args = current['args']
    expected = '/var/lib/ipid-recovery-tools/' + OLD_REVISION + '/backup-interrupted-geo.py'
    if current['uid'] != 0 or expected not in args or '--site' not in args or args[args.index('--site') + 1] != site:
        raise RuntimeError('Backup PID no longer matches the known process; no signal sent')
    return current

def same_process(saved):
    current = process(saved['pid'])
    return current is not None and current['start'] == saved['start'] and current['args'] == saved['args'] and current['uid'] == saved['uid']

def signal_saved(saved, value):
    if same_process(saved):
        try:
            os.kill(saved['pid'], value)
        except ProcessLookupError:
            pass

def children_of(pid):
    children = []
    for entry in Path('/proc').glob('[0-9]*'):
        try:
            fields = (entry / 'stat').read_text().rsplit(') ', 1)[1].split()
            if int(fields[1]) != pid:
                continue
            child = process(int(entry.name))
            if child is not None:
                children.append(child)
        except (FileNotFoundError, ProcessLookupError):
            continue
    return children

def wait_stopped(saved):
    deadline = time.monotonic() + 2
    while True:
        current = process(saved['pid'])
        if current is None:
            return
        if current['start'] != saved['start'] or current['args'] != saved['args'] or current['uid'] != saved['uid']:
            raise RuntimeError('Backup process identity changed while pausing')
        if current['state'] == 'T':
            return
        if time.monotonic() >= deadline:
            raise RuntimeError('Backup process did not stop; no termination')
        time.sleep(0.01)

def stop_legacy(saved, root):
    """Freeze the spawner briefly; validate all children before terminating it."""
    if saved is None or not same_process(saved):
        return
    signal_saved(saved, signal.SIGSTOP)
    terminated = False
    children = []
    try:
        wait_stopped(saved)
        if not same_process(saved):
            return
        pending = [saved['pid']]
        while pending:
            pid = pending.pop()
            for child in children_of(pid):
                args = child['args']
                if child['uid'] not in {0, pwd.getpwnam('aweis').pw_uid}:
                    raise RuntimeError('Unexpected backup child owner')
                if not any(Path(x).name == 's3cmd' for x in args) or not any(x.startswith(root + '/') for x in args):
                    raise RuntimeError('Unexpected backup child; original backup continued, no termination')
                if not any(x in args for x in ('ls', 'get', 'put', 'info')):
                    raise RuntimeError('Unexpected S3 operation in backup child')
                children.append(child)
                signal_saved(child, signal.SIGSTOP)
                wait_stopped(child)
                pending.append(child['pid'])
        # SIGCONT delivers the pending default SIGTERM to the stopped Python parent.
        signal_saved(saved, signal.SIGTERM)
        signal_saved(saved, signal.SIGCONT)
        deadline = time.monotonic() + 15
        while same_process(saved) and time.monotonic() < deadline:
            time.sleep(0.1)
        if same_process(saved):
            raise RuntimeError('Old backup parent did not exit; no replacement started')
        terminated = True
        for child in reversed(children):
            signal_saved(child, signal.SIGTERM)
            signal_saved(child, signal.SIGCONT)
        deadline = time.monotonic() + 15
        while any(same_process(x) for x in children) and time.monotonic() < deadline:
            time.sleep(0.1)
        if any(same_process(x) for x in children):
            raise RuntimeError('Old backup child still active; no replacement started')
    finally:
        for child in reversed(children):
            signal_saved(child, signal.SIGCONT)
        if not terminated:
            signal_saved(saved, signal.SIGCONT)


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
        if not journal_paths:
            # The old process creates this frozen export before its file loop,
            # but only prints its Hashing line when it reaches the last item.
            journal_paths = set(local.glob("original-scanner-*.journal.jsonl"))
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
        if {"ipid.pq", "ipid.snapshot.yaml", "state.json"} - set(verified):
            raise RuntimeError("Prior attempt has not verified IPID, its snapshot and state; refusing expensive automatic retry")
        # Reuse the earlier full remote read-backs as this same attempt would;
        # a HEAD/list-size check detects missing/truncated objects, not arbitrary
        # later equal-size administrative overwrites (Object Lock is not used).
        # The old process lost its in-memory inode/mtime table. Bulk source
        # hashes refer to the earlier verification, not a new local content
        # check. The RT resume admission independently rehashes those local
        # sources before probing, so do not duplicate that expensive read here.
        store = Store()
        zmap_files, zmap_reference, zmap_identities = original_zmap(store, args.s3_root, workspace, args.site, zid)
        manifest = {
            "version": 1, "purpose": "interrupted-rt-preservation-not-measurement-completion",
            "campaign_id": CAMPAIGN, "site": args.site, "measurement_id": mid,
            "zmap_id": zid, "state_binding": state["binding"], "files": {},
            "prior_verification_log": {"path": str(old_log), "sha256": evidence(old_log)[0]["sha256"]},
            "bulk_source_validation": "Earlier full SHA256 read-back proof reused; current local/remote sizes checked. Resume must independently revalidate current local content.",
            "zmap_reference": zmap_reference,
        }
        identities = dict(zmap_identities)
        for name, path in sources.items():
            if name in zmap_files:
                if name in verified and verified[name] != {k:zmap_files[name][k] for k in ("size_bytes","sha256")}:
                    raise RuntimeError("Original ZMap reference differs from the earlier verified target source")
                manifest["files"][name] = zmap_files[name]
                print(f"REFERENCED original committed ZMap: {name}: {zmap_files[name]['uri']}", flush=True)
                continue
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


def handoff_zmap(args):
    """Wait for indispensable IPID proofs, then skip the duplicate ZMap stage."""
    import fcntl
    if os.geteuid() != 0:
        raise RuntimeError("Run this guarded handoff as root")
    workspace, rt, state = validate_workspace(Path(args.repo).resolve(), args.site)
    assert_inactive()
    mid, zid, _ = RUNS[args.site]
    local = prepare_metadata(workspace, mid)
    old_log = Path(args.handoff_zmap_from_log)
    if (old_log.parent != LOG_ROOT or old_log.is_symlink() or not old_log.is_file()
        or old_log.stat().st_uid != 0 or old_log.stat().st_mode & 0o022 or old_log.stat().st_size > 8 << 20
        or not re.fullmatch(rf"{args.site}-\d{{8}}T\d{{6,18}}Z\.log", old_log.name)):
        raise RuntimeError("Untrusted original backup log; no process stopped")
    print("Checking the original published ZMap objects; no new ZMap upload will be started.", flush=True)
    # Establish a usable reference before ever signalling the old backup.
    original_zmap(Store(), args.s3_root, workspace, args.site, zid)
    journal = local / "original-scanner.journal.jsonl"
    candidates = set(local.glob("original-scanner-*.journal.jsonl"))
    raw = old_log.read_text()
    printed = {Path(line[len("Hashing: "):]) for line in raw.splitlines()
               if line.startswith(f"Hashing: {local}/original-scanner-") and line.endswith(".journal.jsonl")}
    if printed:
        candidates = printed
    if len(candidates) != 1:
        raise RuntimeError("Frozen original journal is ambiguous; no process stopped")
    journal = candidates.pop()
    sources = {"ipid.pq": rt / "ipid.pq", "ipid.snapshot.yaml": rt / "ipid.snapshot.yaml",
               "state.json": workspace / "state.json", "zmap.pq": workspace / "zmap/raw" / zid / "zmap.pq",
               "zmap.snapshot.yaml": workspace / "zmap/raw" / zid / "zmap.snapshot.yaml",
               "original-scanner.journal.jsonl": journal}
    root = f"{args.s3_root.rstrip('/')}/recovery/{CAMPAIGN}/{args.site}/icmp/{mid}"
    critical = {"ipid.pq", "ipid.snapshot.yaml", "state.json"}
    deadline = time.monotonic() + 48 * 3600
    last_message = 0
    with (local / ".zmap-reference-watch.lock").open("a") as watcher:
        fcntl.flock(watcher, fcntl.LOCK_EX | fcntl.LOCK_NB)
        while True:
            if time.monotonic() > deadline:
                raise RuntimeError("Handoff wait expired; no automatic bulk retry")
            if "BACKUP VERIFIED; originals unchanged." in old_log.read_text():
                print("Original backup already completed; no duplicate transfer started by this tool.", flush=True)
                return
            current = legacy_process(old_log, args.site)
            try:
                verified = checkpoint_log(old_log, sources, root)
            except (SyntaxError, ValueError):
                if current is None:
                    raise
                time.sleep(5)
                continue
            if critical - set(verified):
                if current is None:
                    raise RuntimeError("Original backup stopped before all indispensable IPID proofs; no automatic re-upload")
                if time.monotonic() - last_message >= 60:
                    print("Keeping the original IPID upload/read-back running; waiting for IPID, snapshot and state proofs.", flush=True)
                    last_message = time.monotonic()
                time.sleep(5)
                continue
            if current is not None and "zmap.pq" in verified:
                # The old duplicate body already finished; let its tiny final
                # metadata complete rather than interrupting it needlessly.
                time.sleep(5)
                continue
            if current is not None:
                assert_inactive()
                print(f"IPID proofs complete; stopping only validated obsolete backup tree {current['pid']}.", flush=True)
                stop_legacy(current, root)
            args.continue_from_log = str(old_log)
            try:
                continue_backup(args)
                return
            except BlockingIOError:
                if time.monotonic() - last_message >= 60:
                    print("Another preservation process still owns the runner lock; waiting without stopping it.", flush=True)
                    last_message = time.monotonic()
                time.sleep(5)


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
        zmap_files, zmap_reference, zmap_identities = original_zmap(store, args.s3_root, workspace, args.site, zid)
        root = f"{args.s3_root.rstrip('/')}/recovery/{CAMPAIGN}/{args.site}/icmp/{mid}"
        manifest = {
            "version": 1, "purpose": "interrupted-rt-preservation-not-measurement-completion",
            "campaign_id": CAMPAIGN, "site": args.site, "measurement_id": mid,
            "zmap_id": zid, "state_binding": state["binding"], "files": {},
            "zmap_reference": zmap_reference,
        }
        identities = dict(zmap_identities)
        for name, path in sources.items():
            if name in zmap_files:
                manifest["files"][name] = zmap_files[name]
                print(f"REFERENCED original committed ZMap: {name}: {zmap_files[name]['uri']}", flush=True)
                continue
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
    modes.add_argument("--handoff-zmap-from-log")
    args = parser.parse_args()
    if args.repair_metadata_access_only:
        if os.geteuid() != 0:
            raise RuntimeError("Run metadata-access repair as root")
        workspace, _, _ = validate_workspace(Path(args.repo).resolve(), args.site)
        assert_inactive()
        local = prepare_metadata(workspace, RUNS[args.site][0])
        print(f"Metadata access repaired: {local}; no process restarted or file contents changed.")
    elif args.handoff_zmap_from_log:
        handoff_zmap(args)
    elif args.continue_from_log:
        continue_backup(args)
    else:
        backup(args)

