#!/usr/bin/env python3
"""Bounded, upload-only handoff of the four November 13 Geo backups.

No probes, source deletion, measurement state edits, remote deletion, or body GETs.
Credentials stay in memory. A published receipt records size verification only.
"""
import argparse
import configparser
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import signal
import subprocess
import time
import urllib.request
import uuid
import zipfile

spec = importlib.util.spec_from_file_location('preservation', Path(__file__).with_name('backup-interrupted-geo.py'))
old = importlib.util.module_from_spec(spec)
spec.loader.exec_module(old)
ROOT = 's3://netds3o:aweis/ipid-2/raw/recovery/' + old.CAMPAIGN
OLD_REVISION = '925067f98b37380f96bc16380d2981e721010066'
VERSION = 'v1.76.0'
ARCHIVE_SHA256 = 'b00f00b3266c3764413afe599d3ec316f6f43b3e0ea8a0bc1d186d2133e46df7'
CONTROL_ROOT = Path('/var/lib/ipid-recovery-tools/fast-backup')
LOG_ROOT = Path('/var/log/ipid-recovery')
S3_FLAGS = ['--immutable', '--size-only', '--transfers', '1',
            '--s3-upload-concurrency', '8', '--s3-chunk-size', '32Mi',
            '--s3-upload-cutoff', '64Mi', '--s3-disable-checksum',
            '--s3-leave-parts-on-error', '--s3-no-check-bucket',
            '--stats', '10s', '--stats-one-line', '--log-level', 'INFO']


def log(message):
    print(datetime.now(timezone.utc).isoformat(), message, flush=True)


def write_json(path, value):
    with path.open('x', encoding='utf-8') as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write('\n')
        stream.flush()
        os.fsync(stream.fileno())
    account = pwd.getpwnam('aweis')
    os.chown(path, account.pw_uid, account.pw_gid)
    os.chmod(path, 0o600)


def install_rclone(root):
    if os.uname().machine != 'x86_64':
        raise RuntimeError('Only the known Linux amd64 VMs are supported')
    directory = root / ('rclone-' + VERSION)
    directory.mkdir(mode=0o755, parents=True, exist_ok=True)
    if directory.is_symlink() or directory.stat().st_uid != 0 or directory.stat().st_mode & 0o022:
        raise RuntimeError('Unsafe rclone installation directory')
    os.chmod(directory, 0o755)
    archive = directory / ('rclone-' + VERSION + '-linux-amd64.zip')
    if archive.is_symlink():
        raise RuntimeError('Unexpected archive symlink')
    if not archive.exists():
        url = 'https://github.com/rclone/rclone/releases/download/' + VERSION + '/' + archive.name
        log('Downloading pinned rclone binary; no package manager or service restart')
        request = urllib.request.Request(url, headers={'User-Agent': 'IPID-recovery-backup'})
        with urllib.request.urlopen(request, timeout=60) as incoming, archive.open('xb') as output:
            shutil.copyfileobj(incoming, output, 1 << 20)
    with archive.open('rb') as stream:
        digest = old.digest_stream(stream)['sha256']
    if digest != ARCHIVE_SHA256:
        raise RuntimeError('rclone archive SHA256 mismatch; no handoff performed')
    binary = directory / 'rclone'
    if binary.is_symlink():
        raise RuntimeError('Unexpected binary symlink')
    with zipfile.ZipFile(archive) as bundle:
        member = 'rclone-' + VERSION + '-linux-amd64/rclone'
        if not binary.exists():
            with bundle.open(member) as source, binary.open('xb') as output:
                shutil.copyfileobj(source, output, 1 << 20)
            os.chmod(binary, 0o555)
        # Verify an already extracted binary too; never trust version text alone.
        with bundle.open(member) as source, binary.open('rb') as existing:
            if old.digest_stream(source) != old.digest_stream(existing):
                raise RuntimeError('Installed rclone differs from verified archive')
    return binary


class Store:
    def __init__(self):
        self.command = ['sudo', '-H', '-u', 'aweis', 's3cmd']

    def call(self, *args):
        result = subprocess.run(self.command + list(args), check=True, capture_output=True, text=True)
        return result.stdout

    def size(self, uri):
        for line in self.call('ls', uri).splitlines():
            fields = line.split()
            if len(fields) >= 4 and fields[-1] == uri and fields[-2].isdigit():
                return int(fields[-2])
        return None

    def progress(self, uri):
        matches = []
        for line in self.call('multipart', 's3://netds3o:aweis').splitlines():
            fields = line.split()
            if len(fields) == 3 and fields[1] == uri:
                matches.append(fields[2])
        if len(matches) > 1:
            raise RuntimeError('Multiple old multipart uploads for the same object; inspect before handoff')
        if not matches:
            return 0, None
        rows = []
        for line in self.call('listmp', uri, matches[0]).splitlines():
            fields = line.split()
            if len(fields) == 4 and fields[1].isdigit() and fields[3].isdigit():
                rows.append((datetime.fromisoformat(fields[0].replace('Z', '+00:00')), int(fields[3])))
        rows.sort()
        rate = None
        if len(rows) > 1:
            seconds = (rows[-1][0] - rows[0][0]).total_seconds()
            if seconds > 0:
                rate = sum(size for _, size in rows[1:]) / seconds
        return sum(size for _, size in rows), rate


class Rclone:
    def __init__(self, binary, config_path=None):
        account = pwd.getpwnam('aweis')
        self.account = account
        config = configparser.ConfigParser(interpolation=None, strict=False)
        with (config_path or Path(account.pw_dir) / '.s3cfg').open() as stream:
            config.read_file(stream)
        values = config['default']
        if values.get('host_base') != 's3.zih.tu-dresden.de' or not values.getboolean('use_https', fallback=True):
            raise RuntimeError('Unexpected S3 endpoint; no handoff performed')
        if values.get('proxy_host', '').strip():
            raise RuntimeError('Custom S3 proxy needs explicit review')
        self.env = {key: value for key, value in os.environ.items()
                    if not key.startswith(('RCLONE_', 'AWS_'))}
        self.env.update(HOME=account.pw_dir, USER=account.pw_name, LOGNAME=account.pw_name)
        settings = {'TYPE': 's3', 'PROVIDER': 'Other', 'ENDPOINT': 'https://s3.zih.tu-dresden.de',
                    'ACCESS_KEY_ID': values['access_key'], 'SECRET_ACCESS_KEY': values['secret_key'],
                    'REGION': 'us-east-1', 'FORCE_PATH_STYLE': 'true',
                    'V2_AUTH': str(values.getboolean('signature_v2', fallback=False)).lower()}
        if not settings['ACCESS_KEY_ID'] or not settings['SECRET_ACCESS_KEY']:
            raise RuntimeError('Missing existing S3 credentials')
        if values.get('access_token', '').strip():
            settings['SESSION_TOKEN'] = values['access_token']
        self.env.update({'RCLONE_CONFIG_IPIDFAST_' + key: value for key, value in settings.items()})
        self.binary = str(binary)

    def copy(self, source, uri, timeout=None):
        if not uri.startswith('s3://netds3o:aweis/ipid-2/raw/'):
            raise RuntimeError('Unexpected destination')
        command = [self.binary, '--config', '/dev/null', 'copyto', str(source),
                   'ipidfast:' + uri[5:], *S3_FLAGS]
        process = subprocess.Popen(command, env=self.env, user=self.account.pw_uid,
                                   group=self.account.pw_gid,
                                   extra_groups=os.getgrouplist(self.account.pw_name, self.account.pw_gid))
        try:
            status = process.wait(timeout=timeout)
            if status:
                raise RuntimeError(f'rclone upload failed ({status}); originals retained')
        except BaseException:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
            raise


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


def stop_legacy(saved, root):
    """Freeze the spawner briefly; validate all children before terminating it."""
    if saved is None or not same_process(saved):
        return
    signal_saved(saved, signal.SIGSTOP)
    terminated = False
    try:
        deadline = time.monotonic() + 2
        while same_process(saved) and process(saved['pid'])['state'] != 'T':
            if time.monotonic() >= deadline:
                raise RuntimeError('Backup parent did not stop; no termination')
            time.sleep(0.01)
        if not same_process(saved):
            return
        pending = [saved['pid']]
        children = []
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
        deadline = time.monotonic() + 15
        while any(same_process(x) for x in children) and time.monotonic() < deadline:
            time.sleep(0.1)
        if any(same_process(x) for x in children):
            raise RuntimeError('Old backup child still active; no replacement started')
    finally:
        if not terminated:
            signal_saved(saved, signal.SIGCONT)


def decision(size, done, rate, benchmark):
    # Deliberately pessimistic disk allowance, based on the observed ~22.6 MB/s.
    effective = min(benchmark, 20_000_000)
    if done >= size * 0.5:
        return False, 'At least half the object is already uploaded; keep this progress'
    if done == 0:
        return effective >= 5_000_000, 'No completed old parts; use tested rclone if at least 5 MB/s'
    if not rate or effective <= 0:
        return False, 'No reliable old progress rate; preserve existing upload'
    old_seconds = (size - done) / rate
    new_seconds = size / effective
    replace = new_seconds <= old_seconds * 0.6 and old_seconds - new_seconds >= 600
    return replace, f'Estimated old remaining={old_seconds/3600:.2f}h, new whole upload={new_seconds/3600:.2f}h'


def logged_objects(text, root, sources):
    by_path = {str(path): name for name, path in sources.items()}
    current = None
    result = {}
    for line in text.splitlines():
        if line.startswith('Hashing: '):
            current = by_path.get(line[len('Hashing: '):])
        if current:
            matches = re.findall(re.escape(root) + r'/sha256-[0-9a-f]{64}/' + re.escape(current) + r'(?=\s|$)', line)
            if matches:
                result[current] = matches[-1]
    return result


def benchmark(rclone, store, control, site, token):
    stat = os.statvfs('/dev/shm')
    available = next(int(x.split()[1]) * 1024 for x in Path('/proc/meminfo').read_text().splitlines() if x.startswith('MemAvailable:'))
    if min(stat.f_bavail * stat.f_frsize, available) < 1024**3:
        raise RuntimeError('Less than 1 GiB RAM headroom; no cutover')
    path = Path('/dev/shm') / ('ipid-rclone-test-' + token + '.bin')
    with path.open('xb') as stream:
        for _ in range(256):
            stream.write(os.urandom(1024**2))
    os.chown(path, rclone.account.pw_uid, rclone.account.pw_gid)
    os.chmod(path, 0o600)
    uri = f's3://netds3o:aweis/ipid-2/raw/diagnostics/{old.CAMPAIGN}/rclone/{site}/{token}/test.bin'
    log('Testing rclone multipart upload from RAM; existing uploads untouched')
    start = time.monotonic()
    rclone.copy(path, uri, timeout=300)
    seconds = time.monotonic() - start
    if store.size(uri) != path.stat().st_size:
        raise RuntimeError('rclone preflight object size mismatch; old backup untouched')
    rate = path.stat().st_size / seconds
    log(f'rclone test: {rate/1e6:.2f} MB/s, {seconds:.1f}s; test file retained at {path}')
    return rate


@contextmanager
def job_lock(root, site):
    import fcntl
    root.mkdir(parents=True, exist_ok=True, mode=0o755)
    if root.is_symlink() or root.stat().st_uid != 0 or root.stat().st_mode & 0o022:
        raise RuntimeError('Unsafe handoff control directory')
    os.chmod(root, 0o755)
    with (root / (site + '.lock')).open('a+') as stream:
        fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield


def accelerate(args):
    if os.geteuid() != 0:
        raise RuntimeError('Run as root')
    control_root = CONTROL_ROOT
    with job_lock(control_root, args.site):
        old.assert_inactive()
        workspace, rt, state = old.validate_workspace(Path(args.repo).resolve(), args.site)
        if not isinstance(state.get('binding'), str) or not state['binding']:
            raise RuntimeError('Missing original configuration binding')
        mid, zid, _ = old.RUNS[args.site]
        root = f'{ROOT}/{args.site}/icmp/{mid}'
        logs = list(LOG_ROOT.glob(args.site + '-*.log'))
        if not logs:
            raise RuntimeError('Original backup log required')
        log_path = max(logs, key=lambda x: x.stat().st_mtime_ns)
        if log_path.is_symlink() or log_path.stat().st_uid != 0 or log_path.stat().st_mode & 0o022:
            raise RuntimeError('Untrusted original backup log')
        text = log_path.read_text(errors='replace')
        if 'BACKUP VERIFIED; originals unchanged. Receipt:' in text:
            log('Original full-verification backup already completed; no change needed')
            return
        matches = re.findall(re.escape(root) + r'/sha256-[0-9a-f]{64}/ipid\.pq', text)
        if not matches:
            raise RuntimeError('Original RT SHA256/upload URI not yet logged; old backup untouched')
        original_uri = matches[0]
        journal_files = list((workspace / 'recovery-backup' / mid).glob('original-scanner-*.journal.jsonl'))
        if not journal_files:
            raise RuntimeError('Retained original scanner journal missing')
        sources = {'ipid.pq': rt / 'ipid.pq', 'ipid.snapshot.yaml': rt / 'ipid.snapshot.yaml',
                   'state.json': workspace / 'state.json',
                   'zmap.pq': workspace / 'zmap/raw' / zid / 'zmap.pq',
                   'zmap.snapshot.yaml': workspace / 'zmap/raw' / zid / 'zmap.snapshot.yaml',
                   'original-scanner.journal.jsonl': min(journal_files, key=lambda x: x.name)}
        for path in sources.values():
            if path.is_symlink() or not path.is_file() or not path.resolve().is_relative_to(workspace):
                raise RuntimeError('Unexpected source file')
        identities = {path: old.identity(path) for path in sources.values()}
        known_objects = logged_objects(text, root, sources)
        known_objects['ipid.pq'] = original_uri
        saved = legacy_process(log_path, args.site)
        token = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ') + '-' + uuid.uuid4().hex
        control = control_root / token
        control.mkdir(mode=0o755)
        os.chmod(control, 0o755)
        binary = install_rclone(control_root)
        rclone, store = Rclone(binary), Store()
        size = identities[sources['ipid.pq']][2]
        remote_size = store.size(original_uri)
        if remote_size is not None and remote_size != size:
            raise RuntimeError('Existing RT object size mismatch; nothing overwritten')
        replace = False
        plan = {'site': args.site, 'old_backup': saved, 'original_rt_uri': original_uri,
                'verification': 'upload-success-and-object-size; no full read-back',
                'reason': 'Completed original RT object is reused', 'replace_rt_upload': False}
        if remote_size is None:
            if saved is None:
                raise RuntimeError('Incomplete RT object without trusted old backup process; inspect before replacing')
            test_rate = benchmark(rclone, store, control, args.site, token)
            done, old_rate = store.progress(original_uri)
            replace, reason = decision(size, done, old_rate, test_rate)
            plan.update(old_completed_bytes=done, old_bytes_per_second=old_rate,
                        test_bytes_per_second=test_rate, replace_rt_upload=replace, reason=reason)
            log(f'RT handoff: {reason}; replace={replace}')
            if not replace:
                if saved is None:
                    raise RuntimeError('No old uploader to retain; no replacement authorized by speed check')
                log('Keeping advanced/current RT upload; switch to rclone only after it finishes')
                while store.size(original_uri) is None:
                    if not same_process(saved):
                        raise RuntimeError('Old backup ended before completed RT object became visible')
                    time.sleep(15)
                if store.size(original_uri) != size:
                    raise RuntimeError('Completed old RT upload has wrong size')
        old.assert_inactive()
        for path, before in identities.items():
            old.assert_unchanged(path, before)
        # A completed object always wins over restarting its upload.
        plan['completed_rt_visible_before_handoff'] = store.size(original_uri) == size
        write_json(control / 'handoff-plan.json', plan)
        log('Controlled backup handoff; measurement service and source files remain untouched')
        stop_legacy(saved, root)
        with old.runner_lock(workspace):
            old.assert_inactive()
            prefix = root + '/fast-' + token
            receipt = {'version': 1, 'purpose': 'interrupted-rt-preservation-not-measurement-completion',
                       'verification': 'upload-success-and-object-size; no full read-back',
                       'campaign_id': old.CAMPAIGN, 'site': args.site, 'measurement_id': mid,
                       'zmap_id': zid, 'state_binding': state['binding'], 'files': {}}
            for name, path in sources.items():
                before = identities[path]
                old.assert_unchanged(path, before)
                candidate = known_objects.get(name)
                candidate_size = store.size(candidate) if candidate else None
                if candidate_size is not None and candidate_size != before[2]:
                    raise RuntimeError('Existing original backup object has wrong size; not overwritten')
                uri = candidate if candidate_size == before[2] else prefix + '/' + name
                remote_size = store.size(uri)
                if remote_size is not None and remote_size != before[2]:
                    raise RuntimeError('Existing backup object has unexpected size; not overwritten')
                if remote_size is None:
                    log(f'Parallel rclone upload: {path} -> {uri}')
                    rclone.copy(path, uri)
                if store.size(uri) != before[2]:
                    raise RuntimeError('Remote object size does not match source')
                old.assert_unchanged(path, before)
                receipt['files'][name] = {'uri': uri, 'size_bytes': before[2],
                                          'local_path': str(path), 'source_identity': list(before)}
                log(f'UPLOAD CONFIRMED (size): {name}')
            old.assert_inactive()
            for path, before in identities.items():
                old.assert_unchanged(path, before)
            receipt_path = control / 'backup-uploaded.json'
            write_json(receipt_path, receipt)
            uri = prefix + '/backup-uploaded.json'
            rclone.copy(receipt_path, uri)
            if store.size(uri) != receipt_path.stat().st_size:
                raise RuntimeError('Receipt upload size mismatch')
            log('BACKUP UPLOADED; originals unchanged; size checks only. Receipt: ' + uri)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--site', required=True, choices=old.RUNS)
    parser.add_argument('--repo', default='/mnt/data01/ipid-measure')
    arguments = parser.parse_args()
    def interrupted(signum, frame):
        raise InterruptedError('Acceleration helper interrupted; originals retained')
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    accelerate(arguments)
