import importlib.util
import io
import json
import os
import pwd
import subprocess
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch


spec = importlib.util.spec_from_file_location(
    "backup_interrupted_geo", Path(__file__).with_name("backup-interrupted-geo.py")
)
backup = importlib.util.module_from_spec(spec)
spec.loader.exec_module(backup)


FAKE_S3 = '''
import hashlib
from pathlib import Path
import shutil
import sys
root = Path(sys.argv[1])
args = sys.argv[2:]
uri = args[-1] if args[0] != "get" else args[-2]
path = root / hashlib.sha256(uri.encode()).hexdigest()
if args[0] == "ls":
    if path.exists():
        print("2026-11-13 12:00", path.stat().st_size, uri)
elif args[0] == "put":
    shutil.copyfile(args[-2], path)
elif args[0] == "get":
    if not path.exists():
        sys.exit(4)
    with path.open("rb") as source:
        shutil.copyfileobj(source, sys.stdout.buffer)
else:
    sys.exit(5)
'''


class PreservationTests(unittest.TestCase):
    def setUp(self):
        if os.environ.get("IPID_REQUIRE_ACL_TEST") == "1":
            self.assertEqual(os.geteuid(), 0, "CI must exercise the root-to-uploader boundary")
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.remote = self.root / "remote"
        self.remote.mkdir()
        fake = self.root / "fake_s3.py"
        fake.write_text(FAKE_S3)
        self.store = backup.Store()
        self.store.command = [sys.executable, str(fake), str(self.remote)]
        self.source = self.root / "source"
        self.source.write_bytes(b"original evidence\x00\xff")
        real_account = backup.pwd.getpwnam
        accounts = patch.object(backup.pwd, "getpwnam", side_effect=lambda name: real_account("nobody" if name == "aweis" else name))
        accounts.start()
        self.addCleanup(accounts.stop)
        self.acl_supported = True
        try:
            backup.set_acl(self.root, "u::rwx,g::---,o::---")
        except OSError as exc:
            if exc.errno != 95:
                raise
            if os.environ.get("IPID_REQUIRE_ACL_TEST") == "1":
                raise AssertionError("CI must run the real POSIX ACL regression test") from exc
            # WSL1 does not implement POSIX ACLs. Exercise continuation logic
            # there, but require the real cross-user test on Linux CI.
            self.acl_supported = False
            acl_mock = patch.object(backup, "set_acl")
            acl_mock.start()
            self.addCleanup(acl_mock.stop)

    def tearDown(self):
        self.temporary.cleanup()

    def remote_path(self, uri):
        return self.remote / backup.hashlib.sha256(uri.encode()).hexdigest()

    def test_round_trip_checks_every_byte_and_retains_source(self):
        value, before = backup.evidence(self.source)
        self.store.preserve(self.source, "s3://backup/a", value, before)
        self.assertEqual(self.source.read_bytes(), b"original evidence\x00\xff")
        self.assertEqual(self.remote_path("s3://backup/a").read_bytes(), self.source.read_bytes())
        # Existing verified objects are read back again rather than overwritten.
        self.store.preserve(self.source, "s3://backup/a", value, before)

    def test_existing_corrupt_object_is_not_overwritten_or_accepted(self):
        uri = "s3://backup/a"
        self.remote_path(uri).write_bytes(b"corrupt")
        value, before = backup.evidence(self.source)
        with self.assertRaisesRegex(RuntimeError, "SHA256 mismatch"):
            self.store.preserve(self.source, uri, value, before)
        self.assertEqual(self.remote_path(uri).read_bytes(), b"corrupt")
        self.assertEqual(self.source.read_bytes(), b"original evidence\x00\xff")

    def test_changed_source_is_rejected_before_upload(self):
        value, before = backup.evidence(self.source)
        self.source.write_bytes(b"changed source")
        with self.assertRaisesRegex(RuntimeError, "Source changed"):
            self.store.preserve(self.source, "s3://backup/a", value, before)
        self.assertFalse(self.remote_path("s3://backup/a").exists())

    def test_read_back_process_failure_is_not_a_verified_backup(self):
        with self.assertRaisesRegex(RuntimeError, "read-back failed"):
            self.store.verify("s3://backup/missing", backup.digest_stream(io.BytesIO(b"")))

    def make_workspace(self):
        mid, zid, _ = backup.RUNS["sa"]
        ws = self.root / "parallel" / backup.CAMPAIGN / "sa/icmp"
        rt = ws / "ipid/raw" / mid
        zmap = ws / "zmap/raw" / zid
        rt.mkdir(parents=True)
        zmap.mkdir(parents=True)
        (ws / ".runner.lock").touch()
        (ws / "state.json").write_text(json.dumps({
            "version": 1, "binding": "binding",
            "steps": {"icmp-rt": {"id": mid}, "zmap-icmp": {"id": zid}},
        }))
        (rt / "ipid.pq").write_bytes(b"PAR1original-recordsPAR1")
        (rt / "ipid.snapshot.yaml").write_text("payload: icmp\n")
        (zmap / "zmap.pq").write_bytes(b"PAR1original-targetsPAR1")
        (zmap / "zmap.snapshot.yaml").write_text("payload: icmp\n")
        return ws, rt

    def test_partial_or_different_campaign_state_is_refused(self):
        ws, rt = self.make_workspace()
        backup.validate_workspace(self.root, "sa")
        (rt / "ipid.pq").write_bytes(b"PAR1unfinished-file")
        with self.assertRaisesRegex(RuntimeError, "closed Parquet"):
            backup.validate_workspace(self.root, "sa")
        (rt / "ipid.pq").write_bytes(b"PAR1original-recordsPAR1")
        state = json.loads((ws / "state.json").read_text())
        state["steps"]["icmp-rt"]["id"] = "icmp_other"
        (ws / "state.json").write_text(json.dumps(state))
        with self.assertRaisesRegex(RuntimeError, "Unexpected icmp-rt"):
            backup.validate_workspace(self.root, "sa")

    @unittest.skipIf(sys.platform == "win32", "Controller uses Unix flock")
    def test_receipt_published_only_after_all_sources_read_back(self):
        ws, rt = self.make_workspace()
        original = (rt / "ipid.pq").read_bytes()
        original_state = (ws / "state.json").read_bytes()
        args = backup.argparse.Namespace(repo=str(self.root), site="sa", s3_root="s3://backup/raw")
        real_run = backup.run

        def run(argv, **kwargs):
            if argv[0] == "journalctl":
                return backup.subprocess.CompletedProcess(argv, 0, stdout="retained journal\n")
            return real_run(argv, **kwargs)

        with patch.object(backup.os, "geteuid", return_value=0), \
             patch.object(backup, "assert_inactive"), \
             patch.object(backup, "Store", return_value=self.store), \
             patch.object(backup, "run", side_effect=run):
            backup.backup(args)
        self.assertEqual((rt / "ipid.pq").read_bytes(), original)
        self.assertEqual((ws / "state.json").read_bytes(), original_state)
        receipts = list((ws / "recovery-backup").glob("*/backup-verified-*.json"))
        self.assertEqual(len(receipts), 1)
        receipt = json.loads(receipts[0].read_text())
        self.assertEqual(len(receipt["files"]), 6)
        for entry in receipt["files"].values():
            self.assertTrue(self.remote_path(entry["uri"]).is_file())
        self.assertFalse((rt / "measurement-complete.json").exists())
        self.assertEqual(len(list(self.remote.iterdir())), 7)

    @unittest.skipIf(sys.platform == "win32", "Controller uses Unix flock")
    def test_holds_the_controller_lock_exclusively(self):
        ws, _ = self.make_workspace()
        with backup.runner_lock(ws):
            with self.assertRaises(BlockingIOError):
                with backup.runner_lock(ws):
                    self.fail("Second writer acquired the controller lock")

    @unittest.skipUnless(sys.platform == "linux" and os.geteuid() == 0, "Requires Linux root and an unprivileged actor")
    def test_private_root_metadata_readable_by_uploader_including_future_receipt(self):
        if not self.acl_supported:
            self.skipTest("Host filesystem does not implement POSIX ACLs; real Linux CI must run this test")
        ws, _ = self.make_workspace()
        self.root.chmod(0o755)
        mid = backup.RUNS["sa"][0]
        local = ws / "recovery-backup" / mid
        previous = os.umask(0o077)
        try:
            local.mkdir(parents=True, mode=0o700)
            old = local / "original-scanner-test.journal.jsonl"
            old.write_text("frozen journal\n")
            actor = ["runuser", "-u", "nobody", "--"]
            before = subprocess.run(actor + ["cat", str(old)], capture_output=True)
            self.assertNotEqual(before.returncode, 0)
            value = backup.evidence(old)[0]
            backup.prepare_metadata(ws, mid, user="nobody")
            after = subprocess.run(actor + ["cat", str(old)], check=True, capture_output=True)
            self.assertEqual(after.stdout, b"frozen journal\n")
            receipt = local / "backup-verified-test.json"
            receipt.write_text("new receipt\n")
            got = subprocess.run(actor + ["cat", str(receipt)], check=True, capture_output=True)
            self.assertEqual(got.stdout, b"new receipt\n")
            denied = subprocess.run(actor + [sys.executable, "-c", "import sys; open(sys.argv[1], 'a').write('changed')", str(old)], capture_output=True)
            self.assertNotEqual(denied.returncode, 0)
            self.assertEqual(backup.evidence(old)[0], value)
            self.assertEqual(old.stat().st_mode & 0o007, 0)
            self.assertEqual(receipt.stat().st_mode & 0o007, 0)
        finally:
            os.umask(previous)

    def checkpoint_fixture(self):
        ws, rt = self.make_workspace()
        mid, zid, _ = backup.RUNS["sa"]
        local = backup.prepare_metadata(ws, mid)
        journal = local / "original-scanner-test.journal.jsonl"
        journal.write_text("frozen scanner journal\n")
        sources = {"ipid.pq": rt / "ipid.pq", "ipid.snapshot.yaml": rt / "ipid.snapshot.yaml",
                   "state.json": ws / "state.json", "zmap.pq": ws / "zmap/raw" / zid / "zmap.pq",
                   "zmap.snapshot.yaml": ws / "zmap/raw" / zid / "zmap.snapshot.yaml",
                   "original-scanner.journal.jsonl": journal}
        root = f"s3://backup/raw/recovery/{backup.CAMPAIGN}/sa/icmp/{mid}"
        lines = []
        for name, path in sources.items():
            lines.append(f"Hashing: {path}")
            if name == "original-scanner.journal.jsonl":
                continue
            value, _ = backup.evidence(path)
            uri = f"{root}/sha256-{value['sha256']}/{name}"
            self.remote_path(uri).write_bytes(path.read_bytes())
            lines += [f"Reading back and verifying: {uri}", f"VERIFIED: {name}: {value}"]
        logs = self.root / "logs"
        logs.mkdir()
        path = logs / "sa-20261113T140459479575969Z.log"
        path.write_text("\n".join(lines) + "\nmetadata upload failed\n")
        path.chmod(0o600)
        args = backup.argparse.Namespace(repo=str(self.root), site="sa", s3_root="s3://backup/raw", continue_from_log=str(path))
        return ws, rt, sources, logs, args

    @unittest.skipUnless(sys.platform == "linux" and os.geteuid() == 0, "Original log must be root-owned")
    def test_metadata_continuation_reuses_proofs_without_bulk_get_or_put(self):
        ws, rt, sources, logs, args = self.checkpoint_fixture()
        originals = {name: path.read_bytes() for name, path in sources.items()}
        with patch.object(backup, "LOG_ROOT", logs), patch.object(backup, "assert_inactive"), \
             patch.object(backup, "Store", return_value=self.store), \
             patch.object(self.store, "verify", wraps=self.store.verify) as verify:
            backup.continue_backup(args)
        uris = [call.args[0] for call in verify.call_args_list]
        self.assertEqual(len(uris), 2)
        self.assertTrue(uris[0].endswith("/original-scanner.journal.jsonl"))
        self.assertTrue(uris[1].endswith("/backup-verified.json"))
        for name, path in sources.items():
            self.assertEqual(path.read_bytes(), originals[name])
        receipts = list((ws / "recovery-backup").glob("*/backup-verified-*.json"))
        self.assertEqual(len(receipts), 1)
        manifest = json.loads(receipts[0].read_text())
        self.assertEqual(len(manifest["files"]), 6)
        self.assertIn("prior_verification_log", manifest)
        self.assertFalse((rt / "measurement-complete.json").exists())

    @unittest.skipUnless(sys.platform == "linux" and os.geteuid() == 0, "Original log must be root-owned")
    def test_metadata_continuation_refuses_changed_source_or_missing_remote(self):
        ws, _, sources, logs, args = self.checkpoint_fixture()
        original = sources["ipid.pq"].read_bytes()
        value, _ = backup.evidence(sources["ipid.pq"])
        root = f"s3://backup/raw/recovery/{backup.CAMPAIGN}/sa/icmp/{backup.RUNS['sa'][0]}"
        for kind in ("source", "remote"):
            with self.subTest(kind=kind):
                sources["ipid.pq"].write_bytes(original)
                if kind == "source":
                    sources["ipid.pq"].write_bytes(b"PAR1changed-recordsPAR1")
                else:
                    self.remote_path(f"{root}/sha256-{value['sha256']}/ipid.pq").unlink()
                with patch.object(backup, "LOG_ROOT", logs), patch.object(backup, "assert_inactive"), patch.object(backup, "Store", return_value=self.store):
                    with self.assertRaisesRegex(RuntimeError, "differs or is missing"):
                        backup.continue_backup(args)
                self.assertFalse(list((ws / "recovery-backup").glob("*/backup-verified-*.json")))

    @unittest.skipUnless(sys.platform == "linux" and os.geteuid() == 0, "Original log must be root-owned")
    def test_continuation_rejects_writable_or_mismatched_checkpoint_log(self):
        _, _, _, logs, args = self.checkpoint_fixture()
        path = Path(args.continue_from_log)
        original = path.read_text()
        with patch.object(backup, "LOG_ROOT", logs), patch.object(backup, "assert_inactive"), patch.object(backup, "Store", return_value=self.store):
            path.chmod(0o666)
            with self.assertRaisesRegex(RuntimeError, "private root-owned"):
                backup.continue_backup(args)
            path.chmod(0o600)
            path.write_text(original.replace("Reading back and verifying: s3://backup/", "Reading back and verifying: s3://other/", 1))
            with self.assertRaisesRegex(RuntimeError, "read-back URI differs"):
                backup.continue_backup(args)


if __name__ == "__main__":
    unittest.main()

