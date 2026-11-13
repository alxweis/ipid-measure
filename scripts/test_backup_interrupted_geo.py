import importlib.util
import io
import json
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


if __name__ == "__main__":
    unittest.main()
