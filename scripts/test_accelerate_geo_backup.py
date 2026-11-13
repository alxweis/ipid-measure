import importlib.util
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, patch

spec = importlib.util.spec_from_file_location('fast_backup', Path(__file__).with_name('accelerate-geo-backup.py'))
fast = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fast)


class DecisionTests(unittest.TestCase):
    def test_preserves_uploads_with_half_the_data_done(self):
        self.assertFalse(fast.decision(10**10, 5*10**9, 10**6, 50*10**6)[0])

    def test_switches_only_for_large_predicted_gain(self):
        self.assertTrue(fast.decision(10**10, 10**9, 10**6, 15*10**6)[0])
        self.assertFalse(fast.decision(10**10, 10**9, 10*10**6, 15*10**6)[0])

    def test_unknown_old_rate_preserves_progress(self):
        self.assertFalse(fast.decision(10**10, 10**9, None, 50*10**6)[0])
        self.assertFalse(fast.decision(10**10, 0, None, 10**6)[0])
        self.assertTrue(fast.decision(10**10, 0, None, 10*10**6)[0])


class RcloneTests(unittest.TestCase):
    def test_corrupt_binary_archive_is_not_executed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / ('rclone-' + fast.VERSION)
            target.mkdir(mode=0o755)
            (target / ('rclone-' + fast.VERSION + '-linux-amd64.zip')).write_bytes(b'bad archive')
            with self.assertRaisesRegex(RuntimeError, 'SHA256 mismatch'):
                fast.install_rclone(root)
            self.assertFalse((target / 'rclone').exists())

    def test_credentials_stay_in_environment_and_copy_has_bounded_buffers(self):
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / 'config'
            config.write_text('[default]\nhost_base = s3.zih.tu-dresden.de\nuse_https = True\naccess_key = test-access\nsecret_key = test-secret\n')
            account = SimpleNamespace(pw_dir=directory, pw_name='aweis', pw_uid=1234, pw_gid=1234)
            child = MagicMock()
            child.wait.return_value = 0
            with patch.object(fast.pwd, 'getpwnam', return_value=account), \
                 patch.object(fast.os, 'getgrouplist', return_value=[1234]), \
                 patch.dict(os.environ, {'RCLONE_S3_ENDPOINT': 'https://unexpected', 'AWS_SECRET_ACCESS_KEY': 'unwanted'}), \
                 patch.object(fast.subprocess, 'Popen', return_value=child) as spawn:
                client = fast.Rclone(Path('/trusted/rclone'), config)
                client.copy(Path('/source'), fast.ROOT + '/test/file')
            args, kwargs = spawn.call_args
            command = args[0]
            self.assertIn('copyto', command)
            self.assertNotIn('sync', command)
            self.assertNotIn('move', command)
            self.assertNotIn('test-secret', command)
            self.assertIn('--immutable', command)
            self.assertIn('--s3-disable-checksum', command)
            self.assertNotIn('--s3-no-head', command)
            self.assertEqual(command[command.index('--transfers') + 1], '1')
            self.assertEqual(command[command.index('--s3-upload-concurrency') + 1], '8')
            self.assertEqual(command[command.index('--s3-chunk-size') + 1], '32Mi')
            self.assertEqual(kwargs['env']['RCLONE_CONFIG_IPIDFAST_SECRET_ACCESS_KEY'], 'test-secret')
            self.assertNotIn('RCLONE_S3_ENDPOINT', kwargs['env'])
            self.assertNotIn('AWS_SECRET_ACCESS_KEY', kwargs['env'])


@unittest.skipIf(sys.platform == 'win32', 'Linux process identity and flock')
class HandoffTests(unittest.TestCase):
    def spawn_tree(self, directory, valid):
        child = Path(directory) / ('s3cmd' if valid else 'unexpected.py')
        child.write_text('import time\ntime.sleep(120)\n')
        parent = Path(directory) / 'parent.py'
        parent.write_text('import subprocess,sys\np=subprocess.Popen([sys.executable,sys.argv[1],"get",sys.argv[2],"-"])\nprint(p.pid,flush=True)\np.wait()\n')
        proc = subprocess.Popen([sys.executable, str(parent), str(child), fast.ROOT + '/sa/file'], stdout=subprocess.PIPE, text=True)
        child_pid = int(proc.stdout.readline().strip())
        time.sleep(0.1)
        return proc, child_pid

    def cleanup_tree(self, proc, child_pid):
        for pid in (child_pid, proc.pid):
            current = fast.process(pid)
            if current:
                fast.signal_saved(current, signal.SIGCONT)
                fast.signal_saved(current, signal.SIGTERM)
        proc.wait(timeout=5)
        proc.stdout.close()

    def test_real_signal_handoff_stops_only_validated_backup_tree(self):
        with tempfile.TemporaryDirectory() as directory:
            proc, child_pid = self.spawn_tree(directory, True)
            try:
                with patch.object(fast.pwd, 'getpwnam', return_value=SimpleNamespace(pw_uid=os.getuid())):
                    fast.stop_legacy(fast.process(proc.pid), fast.ROOT + '/sa')
                proc.wait(timeout=5)
                self.assertIsNone(fast.process(child_pid))
            finally:
                self.cleanup_tree(proc, child_pid)

    def test_unexpected_child_is_not_terminated_and_parent_is_continued(self):
        with tempfile.TemporaryDirectory() as directory:
            proc, child_pid = self.spawn_tree(directory, False)
            try:
                with patch.object(fast.pwd, 'getpwnam', return_value=SimpleNamespace(pw_uid=os.getuid())):
                    with self.assertRaisesRegex(RuntimeError, 'Unexpected backup child'):
                        fast.stop_legacy(fast.process(proc.pid), fast.ROOT + '/sa')
                self.assertIsNotNone(fast.process(proc.pid))
                self.assertIsNotNone(fast.process(child_pid))
                state = (Path('/proc') / str(proc.pid) / 'stat').read_text().rsplit(') ', 1)[1].split()[0]
                self.assertNotEqual(state, 'T')
            finally:
                self.cleanup_tree(proc, child_pid)

    def test_reused_pid_identity_is_not_signalled(self):
        saved = {'pid': 123, 'start': 'old', 'args': ['old'], 'uid': 0}
        with patch.object(fast, 'process', return_value={**saved, 'start': 'new'}), patch.object(fast.os, 'kill') as kill:
            fast.signal_saved(saved, signal.SIGTERM)
            kill.assert_not_called()


@unittest.skipIf(sys.platform == 'win32', 'Linux root metadata and flock')
class CopyTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.repo = self.root / 'repo'
        mid, zid, _ = fast.old.RUNS['sa']
        self.workspace = self.repo / 'parallel' / fast.old.CAMPAIGN / 'sa/icmp'
        self.rt = self.workspace / 'ipid/raw' / mid
        self.zmap = self.workspace / 'zmap/raw' / zid
        self.rt.mkdir(parents=True)
        self.zmap.mkdir(parents=True)
        (self.workspace / '.runner.lock').touch()
        (self.workspace / 'state.json').write_text(json.dumps({'version': 1, 'binding': 'original-binding', 'steps': {'icmp-rt': {'id': mid}, 'zmap-icmp': {'id': zid}}}))
        (self.rt / 'ipid.pq').write_bytes(b'PAR1original-resultsPAR1')
        (self.rt / 'ipid.snapshot.yaml').write_text('payload: icmp\n')
        (self.zmap / 'zmap.pq').write_bytes(b'PAR1original-targetsPAR1')
        (self.zmap / 'zmap.snapshot.yaml').write_text('payload: icmp\n')
        journal = self.workspace / 'recovery-backup' / mid
        journal.mkdir(parents=True)
        (journal / 'original-scanner-one.journal.jsonl').write_text('original journal\n')
        self.logroot = self.root / 'logs'
        self.logroot.mkdir()
        self.uri = fast.ROOT + '/sa/icmp/' + mid + '/sha256-' + 'a'*64 + '/ipid.pq'
        (self.logroot / 'sa-one.log').write_text('Uploading file -> ' + self.uri + '\n')
        (self.logroot / 'sa-one.log').chmod(0o600)
        self.snapshot = {p: p.read_bytes() for p in self.workspace.rglob('*') if p.is_file()}
        self.objects = {self.uri: (self.rt / 'ipid.pq').read_bytes()}
        self.copies = []
        objects, copies = self.objects, self.copies
        class Store:
            def size(self, uri):
                return len(objects[uri]) if uri in objects else None
            def progress(self, uri):
                return 0, None
        class Rclone:
            def copy(self, path, uri, timeout=None):
                if uri in objects:
                    raise AssertionError('Existing object unexpectedly overwritten')
                copies.append((path, uri))
                objects[uri] = path.read_bytes()
        self.store, self.rclone = Store(), Rclone()

    def tearDown(self):
        self.temporary.cleanup()

    def execute(self, benchmark=None):
        account = SimpleNamespace(pw_uid=os.getuid(), pw_gid=os.getgid())
        with patch.object(fast, 'CONTROL_ROOT', self.root / 'control'), \
             patch.object(fast, 'LOG_ROOT', self.logroot), \
             patch.object(fast.pwd, 'getpwnam', return_value=account), \
             patch.object(fast.old, 'assert_inactive'), \
             patch.object(fast, 'legacy_process', return_value={'pid': 1}), \
             patch.object(fast, 'stop_legacy') as stop, \
             patch.object(fast, 'install_rclone', return_value=Path('/fake/rclone')), \
             patch.object(fast, 'Rclone', return_value=self.rclone), \
             patch.object(fast, 'Store', return_value=self.store), \
             patch.object(fast.old, 'evidence', side_effect=AssertionError('Unexpected bulk hash pre-read')), \
             patch.object(fast, 'benchmark', side_effect=benchmark):
            self.stop = stop
            fast.accelerate(SimpleNamespace(site='sa', repo=str(self.repo)))

    def test_completed_rt_object_is_reused_and_sources_and_state_are_unchanged(self):
        self.execute()
        self.assertFalse(any(p == self.rt / 'ipid.pq' for p, _ in self.copies))
        for path, value in self.snapshot.items():
            self.assertEqual(path.read_bytes(), value)
        receipts = [json.loads(data) for uri, data in self.objects.items() if uri.endswith('/backup-uploaded.json')]
        self.assertEqual(len(receipts), 1)
        self.assertEqual(len(receipts[0]['files']), 6)
        self.assertEqual(receipts[0]['files']['ipid.pq']['uri'], self.uri)
        self.assertIn('no full read-back', receipts[0]['verification'])
        self.assertFalse((self.rt / 'measurement-complete.json').exists())

    def test_wrong_remote_size_fails_before_signalling_original_backup(self):
        self.objects[self.uri] = b'wrong'
        with self.assertRaisesRegex(RuntimeError, 'size mismatch'):
            self.execute()
        self.stop.assert_not_called()
        self.assertEqual(self.copies, [])

    def test_failed_preflight_does_not_stop_original_backup(self):
        self.objects.clear()
        with self.assertRaisesRegex(RuntimeError, 'preflight failed'):
            self.execute(benchmark=lambda *args: (_ for _ in ()).throw(RuntimeError('preflight failed')))
        self.stop.assert_not_called()
        self.assertEqual(self.copies, [])

    def test_replacement_upload_keeps_all_originals_and_uses_new_destination(self):
        self.objects.clear()
        self.execute(benchmark=lambda *args: 10_000_000)
        self.assertTrue(any(p == self.rt / 'ipid.pq' for p, _ in self.copies))
        self.assertNotIn(self.uri, self.objects)
        self.assertTrue(any('/fast-' in uri and uri.endswith('/ipid.pq') for uri in self.objects))
        for path, value in self.snapshot.items():
            self.assertEqual(path.read_bytes(), value)

    def test_advanced_upload_is_allowed_to_finish_then_reused(self):
        self.objects.clear()
        original_size = self.store.size
        calls = [0]
        def size(uri):
            if uri == self.uri:
                calls[0] += 1
                if calls[0] >= 4:
                    self.objects[uri] = (self.rt / 'ipid.pq').read_bytes()
            return original_size(uri)
        self.store.size = size
        self.store.progress = lambda uri: (15, 100)
        with patch.object(fast.time, 'sleep'), patch.object(fast, 'same_process', return_value=True):
            self.execute(benchmark=lambda *args: 10_000_000)
        self.assertFalse(any(p == self.rt / 'ipid.pq' for p, _ in self.copies))
        self.stop.assert_called_once()

    def test_upload_failure_publishes_no_success_receipt_and_retains_sources(self):
        self.objects.clear()
        def fail(path, uri, timeout=None):
            raise RuntimeError('upload failed')
        self.rclone.copy = fail
        with self.assertRaisesRegex(RuntimeError, 'upload failed'):
            self.execute(benchmark=lambda *args: 10_000_000)
        self.assertFalse(any(uri.endswith('/backup-uploaded.json') for uri in self.objects))
        for path, value in self.snapshot.items():
            self.assertEqual(path.read_bytes(), value)


if __name__ == '__main__':
    unittest.main()
