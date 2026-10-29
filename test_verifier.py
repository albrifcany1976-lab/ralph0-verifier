import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import verifier as v


def output(baseline=False):
    identity = {'python': '3.9.25', 'mpmath': '1.3.0', 'sympy_file': '/source/sympy/__init__.py', 'assertions': True}
    s = 'RALPH_IDENTITY ' + json.dumps(identity) + '\n'
    for name in v.CFG['tests']:
        s += name + (' F\n' if baseline and name == 'test_monomials' else ' ok\n')
    s += '=== tests finished: ' + ('10 passed, 1 failed' if baseline else '11 passed') + ', in 0.03 seconds ===\n'
    if baseline:
        s += 'File "/source/sympy/polys/tests/test_monomials.py", line 116, in test_monomials\n'
        s += v.CFG['failure_source'] + '\nAssertionError\n'
    return s.encode()


class GateTests(unittest.TestCase):
    def raw(self, path=None, old='100644', new='100644', status='M'):
        return (':' + old + ' ' + new + ' ' + '1'*40 + ' ' + '2'*40 + ' ' + status).encode() + b'\0' + (path or v.CFG['source']).encode() + b'\0'

    def test_allowed_source(self):
        v.validate_raw_diff(self.raw())

    def test_scope_rejection(self):
        with self.assertRaisesRegex(v.Stop, 'SCOPE'):
            v.validate_raw_diff(self.raw(v.CFG['test']))

    def test_extra_file_rejected_not_filtered(self):
        with self.assertRaises(v.Stop):
            v.validate_raw_diff(self.raw() + self.raw('README.md'))

    def test_symlink_rejected(self):
        with self.assertRaises(v.Stop):
            v.validate_raw_diff(self.raw(new='120000'))

    def test_mode_change_rejected(self):
        with self.assertRaises(v.Stop):
            v.validate_raw_diff(self.raw(new='100755'))

    def test_delete_rejected(self):
        with self.assertRaises(v.Stop):
            v.validate_raw_diff(self.raw(status='D'))

    def test_empty_only_in_dry_run(self):
        with self.assertRaises(v.Stop):
            v.validate_raw_diff(b'')
        v.validate_raw_diff(b'', allow_empty=True)

    def test_real_git_diff_and_modes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            def git(*args):
                return subprocess.check_output(['git', '-C', tmp, *args], stderr=subprocess.DEVNULL).strip().decode()
            git('init', '--template=')
            git('config', 'user.name', 'Synthetic test')
            git('config', 'user.email', 'test@example.invalid')
            p = root / v.CFG['source']; p.parent.mkdir(parents=True)
            p.write_text('value = 1\n')
            git('add', '.'); git('commit', '-m', 'synthetic base')
            base = git('rev-parse', 'HEAD')
            p.write_text('value = 2\n')
            git('commit', '-am', 'synthetic candidate')
            sha = git('rev-parse', 'HEAD')
            with patch.dict(v.CFG, {'base': base}):
                delta, body = v.gate(root / '.git', sha)
                self.assertEqual(body, b'value = 2\n')
                self.assertIn(b'+value = 2', delta)
                (root / 'outside').write_text('outside')
                git('add', '.'); git('commit', '-m', 'outside scope')
                with self.assertRaisesRegex(v.Stop, 'SCOPE'):
                    v.gate(root / '.git', git('rev-parse', 'HEAD'))


class ResultTests(unittest.TestCase):
    def test_exact_success(self):
        self.assertEqual(v.parse_result(output(), 0, False)['passed'], 11)

    def test_exact_baseline_failure(self):
        self.assertEqual(v.parse_result(output(True), 1, True)['failed'], 1)

    def test_zero_exit_alone_is_not_success(self):
        with self.assertRaises(v.Stop):
            v.parse_result(b'PASS\n', 0, False)

    def test_missing_test(self):
        with self.assertRaises(v.Stop):
            v.parse_result(output().replace(b'test_Monomial ok\n', b''), 0, False)

    def test_duplicate_test(self):
        with self.assertRaises(v.Stop):
            v.parse_result(output().replace(b'test_Monomial ok\n', b'test_Monomial ok\n'*2), 0, False)

    def test_skip_rejected(self):
        with self.assertRaises(v.Stop):
            v.parse_result(output().replace(b'test_Monomial ok', b'test_Monomial s'), 0, False)

    def test_wrong_baseline_line(self):
        with self.assertRaises(v.Stop):
            v.parse_result(output(True).replace(b'line 116', b'line 117'), 1, True)

    def test_wrong_baseline_exception(self):
        with self.assertRaises(v.Stop):
            v.parse_result(output(True).replace(b'AssertionError', b'ImportError'), 1, True)

    def test_wrong_exit_code(self):
        with self.assertRaises(v.Stop):
            v.parse_result(output(), 1, False)

    def test_optimization_rejected(self):
        with self.assertRaises(v.Stop):
            v.parse_result(output().replace(b'"assertions": true', b'"assertions": false'), 0, False)

    def test_other_sympy_import_rejected(self):
        with self.assertRaises(v.Stop):
            v.parse_result(output().replace(b'/source/sympy/', b'/site-packages/sympy/'), 0, False)

    def test_duplicate_summary(self):
        with self.assertRaises(v.Stop):
            v.parse_result(output() + b'tests finished: 11 passed, in 0.01 seconds\n', 0, False)


class BoundTests(unittest.TestCase):
    def test_timeout_calls_external_stop(self):
        called = []
        r = v.bounded([sys.executable, '-c', 'import time; time.sleep(30)'], seconds=0.1, on_limit=lambda: called.append(True))
        self.assertEqual(r['stop'], 'TIMEOUT')
        self.assertEqual(called, [True])
        self.assertIsNotNone(r['returncode'])

    def test_output_limit_calls_external_stop(self):
        called = []
        r = v.bounded([sys.executable, '-c', 'print("x"*100000)'], limit=100, on_limit=lambda: called.append(True))
        self.assertEqual(r['stop'], 'OUTPUT_LIMIT')
        self.assertEqual(len(r['output']), 100)
        self.assertEqual(called, [True])

    def test_nonzero_is_preserved(self):
        r = v.bounded([sys.executable, '-c', 'raise SystemExit(7)'])
        self.assertEqual(r['returncode'], 7)
        self.assertIsNone(r['stop'])

    def test_docker_controls_are_present(self):
        args = v.create_args('fixture', 'sha256:' + '0'*64, Path('/fixture'))
        for value in ['--network=none', '--read-only', '--user=65532:65532', '--cap-drop=ALL', '--security-opt=no-new-privileges', '--log-driver=none', '--pids-limit=128']:
            self.assertIn(value, args)
        self.assertFalse(any('docker.sock' in a for a in args))
        self.assertEqual(args[-2:], ['--entrypoint=python', 'sha256:' + '0'*64])


class ArchiveTests(unittest.TestCase):
    def archive(self, name, symlink=False):
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode='w') as t:
            info = tarfile.TarInfo(name)
            if symlink:
                info.type = tarfile.SYMTYPE; info.linkname = '/etc/passwd'
                t.addfile(info)
            else:
                info.size = 2; t.addfile(info, io.BytesIO(b'ok'))
        return buf.getvalue()

    def test_regular_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            v.safe_extract(self.archive('dir/file'), Path(tmp))
            self.assertEqual((Path(tmp)/'dir/file').read_text(), 'ok')

    def test_traversal(self):
        with tempfile.TemporaryDirectory() as tmp, self.assertRaises(v.Stop):
            v.safe_extract(self.archive('../outside'), Path(tmp))

    def test_symlink(self):
        with tempfile.TemporaryDirectory() as tmp, self.assertRaises(v.Stop):
            v.safe_extract(self.archive('link', True), Path(tmp))


class RegressionArtifactTests(unittest.TestCase):
    def test_exact_upstream_bytes_and_patch_application(self):
        fixture = v.ROOT/'tests/fixtures/test_monomials_base.txt'
        body = fixture.read_bytes()
        import hashlib
        self.assertEqual(hashlib.sha1(b'blob '+str(len(body)).encode()+b'\0'+body).hexdigest(), '482cbee30dfd6716e97285ae4e766c25098c1eac')
        self.assertEqual(v.digest(body), v.CFG['base_test_sha256'])
        self.assertEqual(v.digest((v.ROOT/'regression.patch').read_bytes()), v.CFG['patch_sha256'])
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); target = root/v.CFG['test']
            target.parent.mkdir(parents=True); target.write_bytes(body)
            subprocess.run(['git', 'apply', str(v.ROOT/'regression.patch')], cwd=root, check=True)
            changed = target.read_bytes()
            self.assertEqual(v.digest(changed), v.CFG['patched_test_sha256'])
            self.assertEqual(changed.decode().splitlines()[115].strip(), v.CFG['failure_source'])
            names = [n.name for n in v.ast.parse(changed).body if isinstance(n, v.ast.FunctionDef) and n.name.startswith('test_')]
            self.assertEqual(names, v.CFG['tests'])


class BoundaryTests(unittest.TestCase):
    def fixture(self):
        return {'Image': 'sha256:' + '1'*64, 'Config': {'User': '65532:65532', 'Env': []},
                'Mounts': [{'Type': 'bind', 'Source': str(v.ROOT/'control'), 'Destination': '/control', 'RW': False}],
                'HostConfig': {'ReadonlyRootfs': True, 'Privileged': False, 'NetworkMode': 'none',
                  'CapDrop': ['ALL'], 'CapAdd': None, 'Devices': [], 'SecurityOpt': ['no-new-privileges'],
                  'PidMode': '', 'IpcMode': 'private', 'Memory': 2*1024**3, 'MemorySwap': 2*1024**3,
                  'NanoCpus': 2*10**9, 'PidsLimit': 128, 'ShmSize': 64*1024**2,
                  'LogConfig': {'Type': 'none'}, 'RestartPolicy': {'Name': 'no'},
                  'Tmpfs': {'/tmp': 'rw,nosuid,nodev,noexec,size=256m,mode=1777'}}}

    def test_expected_boundary(self):
        v.check_container(self.fixture(), 'sha256:' + '1'*64, None)

    def test_relaxed_boundaries_rejected(self):
        changes = [('Privileged', True), ('NetworkMode', 'host'), ('PidsLimit', 0),
                   ('ReadonlyRootfs', False), ('MemorySwap', -1), ('PidMode', 'host'),
                   ('SecurityOpt', []), ('CapAdd', ['SYS_ADMIN'])]
        for key, value in changes:
            with self.subTest(key=key), self.assertRaises(v.Stop):
                obj = self.fixture(); obj['HostConfig'][key] = value
                v.check_container(obj, obj['Image'], None)

    def test_writable_reference_rejected(self):
        obj = self.fixture(); obj['Mounts'][0]['RW'] = True
        with self.assertRaises(v.Stop): v.check_container(obj, obj['Image'], None)

    def test_socket_mount_rejected(self):
        obj = self.fixture(); obj['Mounts'].append({'Type': 'bind', 'Source': '/var/run/docker.sock', 'Destination': '/var/run/docker.sock', 'RW': True})
        with self.assertRaises(v.Stop): v.check_container(obj, obj['Image'], None)

    def test_token_environment_rejected(self):
        obj = self.fixture(); obj['Config']['Env'] = ['ACTIONS_RUNTIME_TOKEN=synthetic']
        with self.assertRaises(v.Stop): v.check_container(obj, obj['Image'], None)

    def test_exit_requires_pid_zero(self):
        v.require_terminated({'Running': False, 'Pid': 0})
        for state in [{'Running': True, 'Pid': 123}, {'Running': False, 'Pid': 123}, {'Running': False, 'Pid': 0, 'Restarting': True}]:
            with self.subTest(state=state), self.assertRaisesRegex(v.Stop, 'STOP_UNKNOWN'):
                v.require_terminated(state)


if __name__ == '__main__':
    unittest.main()
