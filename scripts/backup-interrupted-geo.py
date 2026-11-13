#!/usr/bin/env python3
"""Preserve the four known interrupted Geo RT runs; never resume or commit them.

Run as root on a stopped ICMP VM. S3 commands use the measurement user's existing
configuration. Sources remain untouched. Every object is read back and SHA256
verified before a separate recovery receipt is published.
"""

import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile


CAMPAIGN = "geo-full-20261107-r1"
RUNS = {
    "sa": ("icmp_2026-11-08_03-04-51", "icmp_2026-11-07_03-50-17", "26566"),
    "af": ("icmp_2026-11-08_03-27-48", "icmp_2026-11-07_04-10-15", "24756"),
    "as": ("icmp_2026-11-08_03-15-32", "icmp_2026-11-07_04-00-21", "26384"),
    "au": ("icmp_2026-11-08_03-37-59", "icmp_2026-11-07_04-20-21", "24145"),
}
CHUNK = 8 << 20


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
        local = workspace / "recovery-backup" / mid
        local.mkdir(parents=True, exist_ok=True, mode=0o700)
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
    backup(parser.parse_args())
