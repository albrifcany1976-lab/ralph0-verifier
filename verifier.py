#!/usr/bin/env python3
"""Host-side supervisor. Never imports candidate code. Python standard library only."""
import argparse
import ast
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import selectors
import shutil
import signal
import subprocess
import tarfile
import tempfile
import time
import uuid

ROOT = Path(__file__).resolve().parent
CFG = json.loads((ROOT / 'config.json').read_text())
HEX40 = re.compile(r'[0-9a-f]{40}')
HEX64 = re.compile(r'[0-9a-f]{64}')
LOG_LIMIT = 2 * 1024 * 1024


class Stop(RuntimeError):
    pass


def require(condition, reason):
    if not condition:
        raise Stop(reason)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def write_json(path, data):
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True) + '\n')


def bounded(args, *, cwd=None, env=None, seconds=60, limit=LOG_LIMIT, on_limit=None):
    """Bound subprocess output/time. Kill container via callback before its CLI."""
    started = time.monotonic()
    p = subprocess.Popen(args, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                         stdout=subprocess.PIPE, stderr=subprocess.STDOUT, start_new_session=True)
    chunks = bytearray()
    reason = None
    sel = selectors.DefaultSelector()
    sel.register(p.stdout, selectors.EVENT_READ)
    try:
        while sel.get_map():
            if time.monotonic() - started >= seconds:
                reason = 'TIMEOUT'
                break
            for key, _ in sel.select(min(0.1, max(0, seconds - (time.monotonic() - started)))):
                part = os.read(key.fd, 65536)
                if not part:
                    sel.unregister(key.fileobj)
                elif len(chunks) + len(part) > limit:
                    chunks.extend(part[:max(0, limit - len(chunks))])
                    reason = 'OUTPUT_LIMIT'
                    break
                else:
                    chunks.extend(part)
            if reason:
                break
        if reason is None:
            try:
                p.wait(timeout=max(0.01, seconds - (time.monotonic() - started)))
            except subprocess.TimeoutExpired:
                reason = 'TIMEOUT'
        if reason and on_limit:
            on_limit()
    finally:
        # Also clean descendants of the trusted host command. The Docker daemon
        # is NOT a child; sandbox cleanup below is separately mandatory.
        try:
            os.killpg(p.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        p.wait(timeout=10)
        sel.close()
        p.stdout.close()
    return {'returncode': p.returncode, 'stop': reason,
            'seconds': round(time.monotonic() - started, 3), 'output': bytes(chunks)}


def checked(args, **kwargs):
    r = bounded(args, **kwargs)
    require(r['stop'] is None and r['returncode'] == 0,
            'Command failed: ' + args[0] + ' (' + str(r['stop'] or r['returncode']) + ')')
    return r['output']


def git(repo, *args, **kwargs):
    env = dict(os.environ)
    for k in list(env):
        if k.startswith('GIT_'):
            del env[k]
    env.update(GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL='/dev/null',
               GIT_TERMINAL_PROMPT='0', GIT_NO_REPLACE_OBJECTS='1')
    return checked(['git', '-c', 'core.hooksPath=/dev/null', '-c', 'credential.helper=',
                    '-c', 'http.sslVerify=true', '-c', 'http.sslCAInfo=/etc/ssl/certs/ca-certificates.crt',
                    '--git-dir=' + str(repo), *args], env=env, **kwargs)


def validate_raw_diff(raw, allow_empty=False):
    if not raw:
        require(allow_empty, 'REJECTED_EMPTY_DIFF')
        return
    items = raw.split(b'\0')
    require(len(items) == 3 and items[-1] == b'' and items[1] == CFG['source'].encode(),
            'REJECTED_SCOPE')
    require(re.fullmatch(rb':100644 100644 [0-9a-f]{40} [0-9a-f]{40} M', items[0]) is not None,
            'REJECTED_TYPE_OR_MODE')


def gate(repo, candidate, qualify=False):
    require(HEX40.fullmatch(candidate) is not None, 'INVALID_CANDIDATE_SHA')
    for sha in (CFG['base'], candidate):
        require(git(repo, 'rev-parse', '--verify', sha + '^{commit}').strip().decode() == sha,
                'COMMIT_IDENTITY_MISMATCH')
    raw = git(repo, 'diff', '--raw', '-z', '--no-renames', '--abbrev=40',
              CFG['base'], candidate, '--')
    validate_raw_diff(raw, allow_empty=qualify and candidate == CFG['base'])
    patch = git(repo, 'diff', '--no-ext-diff', '--no-textconv', '--no-renames',
                '--full-index', '--binary', CFG['base'], candidate, '--')
    source = git(repo, 'show', candidate + ':' + CFG['source'], limit=256 * 1024)
    require(b'\0' not in source and b'GIT binary patch' not in patch, 'REJECTED_BINARY')
    source.decode('utf-8')
    ast.parse(source)  # Parses bytes; never executes or imports them.
    return patch, source


def safe_extract(data, destination):
    """Only the trusted base is exported; reject links, traversal and device nodes."""
    with tarfile.open(fileobj=io.BytesIO(data)) as archive:
        members = archive.getmembers()
        require(len(members) <= 30000, 'ARCHIVE_MEMBER_LIMIT')
        require(sum(m.size for m in members) <= 256 * 1024 * 1024, 'ARCHIVE_SIZE_LIMIT')
        for member in members:
            path = PurePosixPath(member.name)
            require(not path.is_absolute() and '..' not in path.parts and str(path) != '.', 'ARCHIVE_PATH')
            require(member.isfile() or member.isdir(), 'ARCHIVE_LINK_OR_SPECIAL')
            target = destination.joinpath(*path.parts)
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                with archive.extractfile(member) as f:
                    target.write_bytes(f.read())
                target.chmod(0o755 if member.mode & 0o111 else 0o644)


def reconstruct(repo, source, work):
    patch = (ROOT / 'regression.patch').read_bytes()
    require(digest(patch) == CFG['patch_sha256'], 'PATCH_IDENTITY')
    a, b = work / 'base', work / 'candidate'
    a.mkdir()
    safe_extract(git(repo, 'archive', CFG['base'], seconds=90, limit=256 * 1024 * 1024), a)
    require(digest((a / CFG['test']).read_bytes()) == CFG['base_test_sha256'], 'BASE_TEST_IDENTITY')
    checked(['git', '-c', 'core.hooksPath=/dev/null', 'apply', '--check', str(ROOT / 'regression.patch')], cwd=a)
    checked(['git', '-c', 'core.hooksPath=/dev/null', 'apply', str(ROOT / 'regression.patch')], cwd=a)
    test = (a / CFG['test']).read_bytes()
    require(digest(test) == CFG['patched_test_sha256'], 'PATCHED_TEST_IDENTITY')
    names = [n.name for n in ast.parse(test).body if isinstance(n, ast.FunctionDef) and n.name.startswith('test_')]
    require(names == CFG['tests'], 'TEST_COLLECTION_CHANGED')
    require(test.decode().splitlines()[CFG['failure_line'] - 1].strip() == CFG['failure_source'], 'FAILURE_SITE_CHANGED')
    shutil.copytree(a, b)
    (b / CFG['source']).write_bytes(source)
    # Both trees are built from base. The candidate tree is never checked out.
    return a, b


def parse_result(output, exitcode, baseline):
    text = output.decode('utf-8', errors='strict')
    identity_lines = re.findall(r'^RALPH_IDENTITY (.+)$', text, re.M)
    require(len(identity_lines) == 1, 'MISSING_OR_DUPLICATE_IDENTITY')
    identity = json.loads(identity_lines[0])
    require(identity == {'python': CFG['python'], 'mpmath': CFG['mpmath'],
                         'sympy_file': '/source/sympy/__init__.py', 'assertions': True}, 'WRONG_RUNTIME')
    summaries = list(re.finditer(r'tests finished: (\d+) passed,\s*(?:(\d+) failed,\s*)?in [0-9.]+ seconds', text))
    require(len(summaries) == 1 and text.count('tests finished:') == 1, 'INVALID_TEST_SUMMARY')
    before = text[:summaries[0].start()]
    records = re.findall(r'^(test_\w+) (ok|F)(?:\s+\[(?:OK|FAIL)\])?\s*$', before, re.M)
    require(len(records) == len(CFG['tests']) and len(dict(records)) == len(records), 'MISSING_OR_DUPLICATE_TEST')
    results = dict(records)
    require(set(results) == set(CFG['tests']), 'TEST_NAMES_MISMATCH')
    expected = {n: ('F' if baseline and n == 'test_monomials' else 'ok') for n in CFG['tests']}
    require(results == expected, 'UNEXPECTED_INDIVIDUAL_RESULTS')
    passed, failed = summaries[0].groups()
    require((int(passed), int(failed or 0), exitcode) == ((10, 1, 1) if baseline else (11, 0, 0)), 'COUNTS_OR_EXIT_MISMATCH')
    if baseline:
        require('AssertionError' in text and CFG['failure_source'] in text,
                'WRONG_BASELINE_FAILURE')
        require(re.search(r'test_monomials\.py[\"\x27]?, line ' + str(CFG['failure_line']) + r'\b', text) is not None,
                'WRONG_FAILURE_LOCATION')
    return {'identity': identity, 'results': results, 'passed': int(passed), 'failed': int(failed or 0)}


def create_args(name, image, source=None):
    args = ['docker', 'create', '--name', name, '--pull=never', '--platform=linux/amd64',
            '--user=65532:65532', '--network=none', '--cap-drop=ALL',
            '--security-opt=no-new-privileges', '--read-only', '--memory=2g',
            '--memory-swap=2g', '--cpus=2', '--pids-limit=128', '--shm-size=64m',
            '--tmpfs=/tmp:rw,nosuid,nodev,noexec,size=256m,mode=1777',
            '--log-driver=none', '--restart=no', '--workdir=/tmp',
            '--env=PYTHONDONTWRITEBYTECODE=1', '--env=PYTHONHASHSEED=1',
            '--mount=type=bind,src=' + str(ROOT / 'control') + ',dst=/control,readonly']
    if source:
        args.append('--mount=type=bind,src=' + str(source) + ',dst=/source,readonly')
    return args + ['--entrypoint=python', image]


def check_container(obj, image, source):
    h = obj['HostConfig']
    require(obj['Image'] == image and obj['Config']['User'] == '65532:65532', 'CONTAINER_IDENTITY')
    require(h['ReadonlyRootfs'] and not h['Privileged'] and h['NetworkMode'] == 'none', 'CONTAINER_BOUNDARY')
    require(h.get('CapDrop') == ['ALL'] and not h.get('CapAdd') and not h.get('Devices'), 'CAPABILITIES')
    require(any(x.startswith('no-new-privileges') for x in h.get('SecurityOpt', [])), 'NO_NEW_PRIVILEGES')
    require(h.get('PidMode', '') == '' and h.get('IpcMode') in ('private', ''), 'NAMESPACE_SHARING')
    require(h['Memory'] == 2 * 1024**3 and h['MemorySwap'] == h['Memory'] and
            h['NanoCpus'] == 2 * 10**9 and h['PidsLimit'] == 128 and h['ShmSize'] == 64 * 1024**2, 'RESOURCE_LIMITS')
    require(h['LogConfig']['Type'] == 'none' and h['RestartPolicy']['Name'] == 'no', 'LOG_OR_RESTART_POLICY')
    binds = {m['Destination']: m for m in obj['Mounts'] if m['Type'] == 'bind'}
    expected = {'/control': str(ROOT / 'control')}
    if source:
        expected['/source'] = str(source)
    require(set(binds) == set(expected) and all(not binds[k]['RW'] and binds[k]['Source'] == v for k, v in expected.items()), 'BIND_MOUNTS')
    require(not any(m['Type'] not in ('bind', 'tmpfs') for m in obj['Mounts']), 'UNEXPECTED_VOLUME')
    require(h['Tmpfs'] == {'/tmp': 'rw,nosuid,nodev,noexec,size=256m,mode=1777'}, 'TMPFS_LIMIT')
    require(not any(x.startswith(('GITHUB_', 'ACTIONS_')) for x in obj['Config'].get('Env', [])), 'CREDENTIAL_ENV')


def require_terminated(state):
    require(not state['Running'] and not state.get('Restarting') and state['Pid'] == 0,
            'STOP_UNKNOWN_CONTAINER_STILL_RUNNING')


class Sandbox:
    def __init__(self, image, evidence):
        self.image, self.evidence = image, evidence
        self.active = None

    def inspect(self, name):
        return json.loads(checked(['docker', 'inspect', name], seconds=10))[0]

    def stop(self):
        if self.active:
            checked(['docker', 'kill', self.active], seconds=10)

    def run(self, label, command, source=None, seconds=600):
        name = 'ralph0-' + uuid.uuid4().hex
        self.active = name
        created = False
        try:
            checked(create_args(name, self.image, source) + command, seconds=30)
            created = True
            before = self.inspect(name)
            check_container(before, self.image, source)
            # Do not persist Config.Env: allowlisted non-secret inspection fields only.
            write_json(self.evidence / (label + '-boundary.json'),
                       {'image': before['Image'], 'host_config': before['HostConfig'], 'mounts': before['Mounts']})
            r = bounded(['docker', 'start', '-a', name], seconds=seconds, on_limit=self.stop)
            state = self.inspect(name)['State']
            require_terminated(state)
            meta = {k: v for k, v in r.items() if k != 'output'}
            meta.update(container_exit=state['ExitCode'], oom=state.get('OOMKilled', False), terminated=True)
            (self.evidence / (label + '.log')).write_bytes(r['output'])
            write_json(self.evidence / (label + '.json'), meta)
            require(not state.get('OOMKilled'), 'OOM_STOP')
            r['container_exit'] = state['ExitCode']
            return r
        finally:
            if created:
                state = self.inspect(name)['State']
                if state['Running']:
                    self.stop()
                    state = self.inspect(name)['State']
                require_terminated(state)
                checked(['docker', 'rm', name], seconds=10)
            self.active = None


def probes(box):
    original = (ROOT / 'control/canary').read_bytes()
    r = box.run('canary', ['-B', '/control/probe.py', 'canary'], seconds=15)
    require(r['stop'] is None and r['container_exit'] == 0, 'CANARY_PROBE_FAILED')
    require(json.loads(r['output']) == {'read': True, 'scratch': True, 'write_denied': True}, 'CANARY_OUTPUT')
    require((ROOT / 'control/canary').read_bytes() == original, 'CANARY_CHANGED')
    r = box.run('timeout', ['-B', '/control/probe.py', 'timeout'], seconds=3)
    require(r['stop'] == 'TIMEOUT' and b'PROBE_CHILD_STARTED' in r['output'], 'TIMEOUT_PROBE_FAILED')
    try:
        validate_raw_diff(b':100644 100644 ' + b'1'*40 + b' ' + b'2'*40 + b' M\0' + CFG['test'].encode() + b'\0')
    except Stop as e:
        require(str(e) == 'REJECTED_SCOPE', 'WRONG_SCOPE_REJECTION')
    else:
        raise Stop('SCOPE_PROBE_FAILED')


def build_runtime(work, evidence):
    require(checked(['dpkg-query', '-W', '-f=${Version}', 'ca-certificates']).strip(), 'NO_HOST_CA_PACKAGE')
    version = checked(['dpkg-query', '-W', '-f=${Version}', 'ca-certificates']).decode()
    checked(['dpkg', '--compare-versions', version, 'ge', '20260816ubuntu0.24.04.1'])
    iid = work / 'runtime.iid'
    r = bounded(['docker', 'build', '--platform=linux/amd64', '--no-cache', '--iidfile', str(iid),
                 str(ROOT / 'runtime')], seconds=900, limit=4 * 1024 * 1024)
    (evidence / 'runtime-build.log').write_bytes(r['output'])
    require(r['stop'] is None, 'STOP_UNKNOWN_RUNTIME_BUILD_' + str(r['stop']))
    require(r['returncode'] == 0, 'RUNTIME_BUILD_FAILED')
    image = iid.read_text().strip()
    require(re.fullmatch(r'sha256:[0-9a-f]{64}', image) is not None, 'INVALID_RUNTIME_IMAGE_ID')
    return image


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('mode', choices=['inspect', 'qualify', 'verify'])
    parser.add_argument('--candidate', default=CFG['base'])
    parser.add_argument('--evidence', required=True, type=Path)
    args = parser.parse_args()
    require(HEX40.fullmatch(args.candidate) is not None, 'INVALID_CANDIDATE_SHA')
    require(args.mode != 'qualify' or args.candidate == CFG['base'], 'QUALIFY_REQUIRES_BASE')
    evidence = args.evidence.resolve()
    evidence.mkdir(parents=True, exist_ok=False)
    report = {'task': CFG['task'], 'mode': args.mode, 'base': CFG['base'], 'candidate': args.candidate,
              'verdict': 'STOP', 'run_id': os.environ.get('GITHUB_RUN_ID'),
              'run_attempt': os.environ.get('GITHUB_RUN_ATTEMPT'),
              'verifier_commit': os.environ.get('GITHUB_SHA'), 'patch_sha256': CFG['patch_sha256']}
    box = None
    started = time.monotonic()
    def interrupted(signum, frame):
        raise Stop('CANCELLED_SIGNAL_' + str(signum))
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    try:
        # Before network operations. Git is explicitly pinned to this OS CA file.
        version = checked(['dpkg-query', '-W', '-f=${Version}', 'ca-certificates']).decode()
        checked(['dpkg', '--compare-versions', version, 'ge', '20260816ubuntu0.24.04.1'])
        with tempfile.TemporaryDirectory(prefix='ralph0-') as tmp:
            work = Path(tmp)
            work.chmod(0o755)  # Docker non-root must traverse source paths.
            repo = work / 'objects.git'
            checked(['git', '-c', 'core.hooksPath=/dev/null', 'init', '--bare', '--template=', str(repo)])
            for sha in dict.fromkeys((CFG['base'], args.candidate)):
                git(repo, 'fetch', '--no-tags', '--depth=1', CFG['repository'], sha, seconds=180)
            patch, source = gate(repo, args.candidate, qualify=args.mode == 'qualify')
            report.update(diff_sha256=digest(patch), source_sha256=digest(source))
            (evidence / 'candidate.patch').write_bytes(patch)
            if args.mode == 'inspect':
                report['verdict'] = 'REVIEW_REQUIRED'
                return 0
            if args.mode == 'verify':
                approvals = json.loads((ROOT / 'reviewed_candidates.json').read_text())
                require(any(a.get('candidate') == args.candidate and a.get('diff_sha256') == digest(patch)
                            and isinstance(a.get('reviewer'), str) and a['reviewer'].strip() for a in approvals),
                        'NO_REVIEW_FOR_EXACT_DIFF')
            a, b = reconstruct(repo, source, work)
            image = build_runtime(work, evidence)
            report['runtime_image'] = image
            box = Sandbox(image, evidence)
            probes(box)
            report['probes'] = 'PASSED'
            runtime = box.run('runtime-metadata', ['-I', '-c',
                "from pathlib import Path; print(Path('/opt/tls-check.json').read_text()); print(Path('/opt/packages.txt').read_text())"], seconds=15)
            require(runtime['stop'] is None and runtime['container_exit'] == 0, 'RUNTIME_METADATA_FAILED')
            for label, tree, baseline in [('base', a, True), ('candidate', b, args.mode == 'qualify')]:
                r = box.run(label, ['-B', '/control/inner.py'], source=tree)
                require(r['stop'] is None, label.upper() + '_' + str(r['stop']))
                report[label + '_results'] = parse_result(r['output'], r['container_exit'], baseline)
            report['verdict'] = 'DRY_RUN_DETECTED_BUG' if args.mode == 'qualify' else 'VERIFIED_FOR_THIS_TASK'
            return 0
    except Exception as e:
        # Do not echo exception text from arbitrary candidate source/logs to Actions.
        report['verdict'] = 'STOP_UNKNOWN' if (box and box.active) or str(e).startswith('STOP_UNKNOWN') else 'STOP'
        report['error_type'] = type(e).__name__
        report['reason'] = str(e)[:1000] if isinstance(e, Stop) else 'Supervisor error; inspect implementation and evidence'
        return 1
    finally:
        report['elapsed_seconds'] = round(time.monotonic() - started, 3)
        report['artifacts'] = {p.name: digest(p.read_bytes()) for p in sorted(evidence.iterdir()) if p.is_file()}
        write_json(evidence / 'report.json', report)
        # Only bounded fixed-format fields are printed; logs remain untrusted artifacts.
        print('RALPH0_VERDICT=' + report['verdict'])


if __name__ == '__main__':
    raise SystemExit(main())
