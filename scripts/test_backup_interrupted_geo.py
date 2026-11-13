import importlib.util
import io
import json
import os
import pwd
import signal
import subprocess
import time
from types import SimpleNamespace
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

    def seed_original_zmap(self, ws):
        zid = backup.RUNS['sa'][1]
        root = f's3://backup/raw/continental/{backup.CAMPAIGN}/sa/zmap/{zid}'
        marker = {'version': 1, 'measurement_id': zid, 'files': {}}
        for name in ('zmap.pq', 'zmap.snapshot.yaml'):
            path = ws / 'zmap/raw' / zid / name
            marker['files'][name] = backup.evidence(path)[0]
            self.remote_path(root + '/' + name).write_bytes(path.read_bytes())
        self.remote_path(root + '/measurement-complete.json').write_text(json.dumps(marker))
        return root, marker

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
        self.seed_original_zmap(ws)
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
        self.assertEqual(len(list(self.remote.iterdir())), 8)
        self.assertIn('zmap_reference', receipt)
        self.assertIn('/continental/', receipt['files']['zmap.pq']['uri'])

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
        self.seed_original_zmap(ws)
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
        real_evidence = backup.evidence
        def small_metadata_only(path):
            if path.suffix == ".pq":
                self.fail("Continuation must not duplicate the later resume admission's bulk source read")
            return real_evidence(path)
        with patch.object(backup, "LOG_ROOT", logs), patch.object(backup, "assert_inactive"), \
             patch.object(backup, "Store", return_value=self.store), \
             patch.object(backup, "evidence", side_effect=small_metadata_only), \
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
        self.assertIn('zmap_reference', manifest)
        self.assertFalse((rt / "measurement-complete.json").exists())

    def test_original_zmap_references_scoped_commit_without_bulk_reads_or_upload(self):
        ws, _ = self.make_workspace()
        root, marker = self.seed_original_zmap(ws)
        real = backup.evidence
        def metadata_only(path):
            self.assertNotEqual(path.name, 'zmap.pq')
            return real(path)
        with patch.object(backup, 'evidence', side_effect=metadata_only), \
             patch.object(self.store, 'verify', side_effect=AssertionError('No body read-back')), \
             patch.object(self.store, 'preserve', side_effect=AssertionError('No upload')):
            files, reference, _ = backup.original_zmap(self.store, 's3://backup/raw', ws, 'sa', backup.RUNS['sa'][1])
        self.assertEqual(files['zmap.pq']['uri'], root + '/zmap.pq')
        self.assertEqual(files['zmap.pq']['sha256'], marker['files']['zmap.pq']['sha256'])
        self.assertEqual(reference['completion_uri'], root + '/measurement-complete.json')

    def test_original_zmap_missing_or_wrong_commit_is_refused_without_fallback(self):
        ws, _ = self.make_workspace()
        root, marker = self.seed_original_zmap(ws)
        path = self.remote_path(root + '/measurement-complete.json')
        original = path.read_bytes()
        for kind in ('missing', 'identity', 'size', 'snapshot'):
            with self.subTest(kind=kind):
                value = json.loads(original)
                if kind == 'missing':
                    path.unlink()
                else:
                    if kind == 'identity': value['measurement_id'] = 'wrong'
                    if kind == 'size': value['files']['zmap.pq']['size_bytes'] += 1
                    if kind == 'snapshot': value['files']['zmap.snapshot.yaml']['sha256'] = '0' * 64
                    path.write_text(json.dumps(value))
                with patch.object(self.store, 'preserve', side_effect=AssertionError('No fallback upload')):
                    with self.assertRaises((RuntimeError, subprocess.CalledProcessError)):
                        backup.original_zmap(self.store, 's3://backup/raw', ws, 'sa', backup.RUNS['sa'][1])
                path.write_bytes(original)

    @unittest.skipUnless(sys.platform == 'linux' and os.geteuid() == 0, 'Original log must be root-owned')
    def test_handoff_waits_for_ipid_proof_then_stops_only_backup_and_finishes_metadata(self):
        ws, _, sources, logs, args = self.checkpoint_fixture()
        path = Path(args.continue_from_log)
        full = path.read_text()
        # Old backup has only just started the IPID read-back. The frozen
        # journal exists but its Hashing line is not printed until much later.
        critical = full.split('Hashing: ' + str(sources['zmap.pq']))[0]
        incomplete = critical.split('VERIFIED: ipid.pq:')[0]
        path.write_text(incomplete)
        args.handoff_zmap_from_log = str(path)
        saved = {'pid': 123}
        active = [True]
        def advance(seconds):
            stop.assert_not_called()
            path.write_text(critical)
        def stopped(*unused): active[0] = False
        with patch.object(backup, 'LOG_ROOT', logs), patch.object(backup, 'assert_inactive'), \
             patch.object(backup, 'Store', return_value=self.store), \
             patch.object(backup, 'legacy_process', side_effect=lambda *a: saved if active[0] else None), \
             patch.object(backup, 'stop_legacy', side_effect=stopped) as stop, \
             patch.object(backup.time, 'sleep', side_effect=advance), \
             patch.object(self.store, 'preserve', wraps=self.store.preserve) as preserve:
            backup.handoff_zmap(args)
        stop.assert_called_once()
        self.assertEqual(len(preserve.call_args_list), 2)
        self.assertTrue(all(call.args[0].suffix != '.pq' for call in preserve.call_args_list))
        receipt = json.loads(next((ws / 'recovery-backup').glob('*/backup-verified-*.json')).read_text())
        self.assertIn('zmap_reference', receipt)

    @unittest.skipUnless(sys.platform == 'linux' and os.geteuid() == 0, 'Original log must be root-owned')
    def test_handoff_missing_original_commit_does_not_signal_backup(self):
        ws, _, _, logs, args = self.checkpoint_fixture()
        zid = backup.RUNS['sa'][1]
        self.remote_path(f's3://backup/raw/continental/{backup.CAMPAIGN}/sa/zmap/{zid}/measurement-complete.json').unlink()
        args.handoff_zmap_from_log = args.continue_from_log
        with patch.object(backup, 'LOG_ROOT', logs), patch.object(backup, 'assert_inactive'), \
             patch.object(backup, 'Store', return_value=self.store), patch.object(backup, 'stop_legacy') as stop:
            with self.assertRaises(subprocess.CalledProcessError):
                backup.handoff_zmap(args)
        stop.assert_not_called()

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


@unittest.skipIf(sys.platform == 'win32', 'Linux process identity and flock')
class HandoffProcessTests(unittest.TestCase):
    def spawn_tree(self, directory, valid):
        child = Path(directory) / ('s3cmd' if valid else 'unexpected.py')
        child.write_text('import time\ntime.sleep(120)\n')
        parent = Path(directory) / 'parent.py'
        parent.write_text('import subprocess,sys\np=subprocess.Popen([sys.executable,sys.argv[1],"get",sys.argv[2],"-"])\nprint(p.pid,flush=True)\np.wait()\n')
        proc = subprocess.Popen([sys.executable, str(parent), str(child), 's3://backup/root/file'], stdout=subprocess.PIPE, text=True)
        child_pid = int(proc.stdout.readline().strip())
        time.sleep(0.1)
        return proc, child_pid

    def cleanup_tree(self, proc, child_pid):
        for pid in (child_pid, proc.pid):
            current = backup.process(pid)
            if current:
                backup.signal_saved(current, signal.SIGCONT)
                backup.signal_saved(current, signal.SIGTERM)
        proc.wait(timeout=5)
        proc.stdout.close()

    def test_real_signal_handoff_stops_only_validated_backup_tree(self):
        with tempfile.TemporaryDirectory() as directory:
            proc, child_pid = self.spawn_tree(directory, True)
            try:
                with patch.object(backup.pwd, 'getpwnam', return_value=SimpleNamespace(pw_uid=os.getuid())):
                    backup.stop_legacy(backup.process(proc.pid), 's3://backup/root')
                proc.wait(timeout=5)
                self.assertIsNone(backup.process(child_pid))
            finally:
                self.cleanup_tree(proc, child_pid)

    def test_unexpected_child_is_not_terminated_and_parent_is_continued(self):
        with tempfile.TemporaryDirectory() as directory:
            proc, child_pid = self.spawn_tree(directory, False)
            try:
                with patch.object(backup.pwd, 'getpwnam', return_value=SimpleNamespace(pw_uid=os.getuid())):
                    with self.assertRaisesRegex(RuntimeError, 'Unexpected backup child'):
                        backup.stop_legacy(backup.process(proc.pid), 's3://backup/root')
                self.assertIsNotNone(backup.process(proc.pid))
                self.assertIsNotNone(backup.process(child_pid))
                self.assertNotEqual(backup.process(proc.pid)['state'], 'T')
            finally:
                self.cleanup_tree(proc, child_pid)

    def test_reused_pid_identity_is_not_signalled(self):
        saved = {'pid': 123, 'start': 'old', 'args': ['old'], 'uid': 0}
        with patch.object(backup, 'process', return_value={**saved, 'start': 'new'}), patch.object(backup.os, 'kill') as kill:
            backup.signal_saved(saved, signal.SIGTERM)
            kill.assert_not_called()


if __name__ == "__main__":
    unittest.main()

