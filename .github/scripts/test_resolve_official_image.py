"""Fault-injection tests for official image resolution and its downstream consumers."""
import concurrent.futures
import contextlib
import io
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

import resolve_official_image as resolver

ROOT = Path(__file__).resolve().parents[2]


def image_json(profile, reference, **overrides):
    repository = reference.split(':', 1)[0]
    image = {'Os': 'linux', 'Architecture': 'amd64',
             'RepoDigests': [repository + '@' + resolver.PROFILES[profile][1]]}
    image.update(overrides)
    return json.dumps([image])


class ResolverTests(unittest.TestCase):
    def run_scenario(self, failures=(), profile='node', inspect=None):
        calls, delays = [], []
        failures = iter(failures)

        def command(args, timeout):
            calls.append((args, timeout))
            if args[1] == 'pull':
                failure = next(failures, None)
                if isinstance(failure, BaseException):
                    raise failure
                return (1, '', failure) if failure else (0, '', '')
            return inspect if inspect is not None else (0, image_json(profile, args[-1]), '')

        stdout, stderr = io.StringIO(), io.StringIO()
        with patch.object(resolver, 'command', command), patch.object(resolver.time, 'sleep', delays.append), \
                contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = resolver.main([profile])
        return code, stdout.getvalue(), stderr.getvalue(), calls, delays

    def test_primary_success_without_secondary(self):
        code, out, _, calls, delays = self.run_scenario()
        self.assertEqual(code, 0)
        self.assertEqual(out, resolver.references('node')[0] + '\n')
        self.assertEqual([c[0][1] for c in calls], ['pull', 'image'])
        self.assertEqual(calls[0][0][2:4], ['--platform', 'linux/amd64'])
        self.assertEqual(calls[0][1], 180)
        self.assertEqual(delays, [])

    def test_primary_retry_succeeds(self):
        code, out, _, calls, delays = self.run_scenario(['429 Too Many Requests'])
        self.assertEqual(code, 0)
        self.assertEqual(out.strip(), resolver.references('node')[0])
        self.assertEqual(len(calls), 3)
        self.assertEqual(delays, [5])

    def test_secondary_preserves_content_and_effective_reference(self):
        code, out, _, calls, delays = self.run_scenario(['Data limit exceeded'] * 2, 'postgres')
        self.assertEqual(code, 0)
        self.assertEqual(out.strip(), resolver.references('postgres')[1])
        self.assertEqual([c[0][-1] for c in calls[:3]],
                         [resolver.references('postgres')[0]] * 2 + [resolver.references('postgres')[1]])
        self.assertEqual(delays, [5])

    def test_both_sources_fail_with_four_attempt_bound_and_redacted_output(self):
        code, out, err, calls, delays = self.run_scenario(['429 token=PRIVATE_SENTINEL'] * 4)
        self.assertEqual(code, 1)
        self.assertEqual(out, '')
        self.assertNotIn('PRIVATE_SENTINEL', err)
        self.assertEqual(len(calls), 4)
        self.assertEqual(delays, [5, 5])

    def test_hard_unknown_and_mixed_errors_stop_immediately(self):
        for error in ['manifest unknown', 'manifest not found', 'invalid reference format',
                      'unsupported platform', 'no matching manifest', 'insufficient scope',
                      'permission denied', 'Cannot connect to the Docker daemon',
                      'digest mismatch', 'digest verification failed', 'unknown registry response',
                      'manifest unknown; 429', 'invalid argument; EOF']:
            with self.subTest(error=error):
                code, out, _, calls, delays = self.run_scenario([error])
                self.assertEqual((code, out, len(calls), delays), (1, '', 1, []))

    def test_known_transient_signatures(self):
        for error in ['toomanyrequests', 'rate limit exceeded', 'unauthorized: authentication required',
                      'anonymous authentication required', 'connection reset by peer',
                      'temporary failure in name resolution', 'i/o timeout', 'TLS handshake timeout',
                      'context deadline exceeded', 'unexpected EOF']:
            with self.subTest(error=error):
                self.assertEqual(self.run_scenario([error])[0], 0)

    def test_pull_timeout_is_bounded_transient(self):
        code, out, _, calls, _ = self.run_scenario(
            [subprocess.TimeoutExpired('docker', 180)] * 2)
        self.assertEqual(code, 0)
        self.assertEqual(out.strip(), resolver.references('node')[1])
        self.assertEqual(len(calls), 4)

    def test_inspection_failure_never_falls_back(self):
        for result in [(1, '', 'SECRET'), (0, 'invalid-json SECRET', ''), (0, '[]', ''),
                       (0, 'null', ''), (0, '[42]', '')]:
            with self.subTest(result=result):
                code, out, err, calls, _ = self.run_scenario(inspect=result)
                self.assertEqual((code, out, len(calls)), (1, '', 2))
                self.assertNotIn('SECRET', err)

    def test_platform_digest_and_repository_mismatch(self):
        reference = resolver.references('node')[0]
        for overrides in [{'Architecture': 'arm64'}, {'Os': 'windows'},
                          {'RepoDigests': ['node@' + resolver.PROFILES['node'][1]]},
                          {'RepoDigests': [reference.split(':')[0] + '@sha256:' + '0' * 64]}]:
            with self.subTest(overrides=overrides):
                code, out, _, calls, _ = self.run_scenario(
                    inspect=(0, image_json('node', reference, **overrides), ''))
                self.assertEqual((code, out, len(calls)), (1, '', 2))

    def test_normalized_hub_digest_is_accepted(self):
        for repo in ['node', 'library/node', 'docker.io/library/node']:
            code, out, _, _, _ = self.run_scenario(['429'] * 2, inspect=(0, image_json(
                'node', resolver.references('node')[1],
                RepoDigests=[repo + '@' + resolver.PROFILES['node'][1]]), ''))
            self.assertEqual(code, 0)
            self.assertEqual(out.strip(), resolver.references('node')[1])

    def test_unknown_profile_extra_parameters_and_source_rejected(self):
        for argv in [[], ['unknown'], ['node', '--source=evil'], ['docker.io/library/node']]:
            with patch.object(resolver, 'command') as command, contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(resolver.main(argv), 2)
                command.assert_not_called()

    def test_cancel_during_pull_or_backoff_has_no_reference_or_fallback(self):
        for cancellation in [KeyboardInterrupt(), resolver.Cancelled()]:
            code, out, _, calls, _ = self.run_scenario([cancellation])
            self.assertEqual((code, out, len(calls)), (130, '', 1))
        with patch.object(resolver, 'command', return_value=(1, '', '429')) as command, \
                patch.object(resolver.time, 'sleep', side_effect=resolver.Cancelled()), \
                contextlib.redirect_stdout(io.StringIO()) as out, contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(resolver.main(['node']), 130)
            self.assertEqual(out.getvalue(), '')
            self.assertEqual(command.call_count, 1)


class ProcessAndWiringTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.folder = Path(self.temp.name)
        self.env = os.environ.copy()
        self.env['PATH'] = str(self.folder) + os.pathsep + self.env['PATH']
        self.env.pop('SIGNACORE_NODE_IMAGE', None)
        self.env['FAKE_LOG'] = str(self.folder / 'calls.jsonl')
        fake = self.folder / 'docker'
        fake.write_text('''#!''' + sys.executable + '''
import json, os, sys, time
from pathlib import Path
args = sys.argv[1:]
with open(os.environ['FAKE_LOG'], 'a') as f:
    f.write(json.dumps({'args':args, 'pid':os.getpid()})+'\\n')
if args[0] == 'pull' and os.environ.get('FAKE_HARD_ERROR'):
    print('manifest unknown; SECRET_SENTINEL', file=sys.stderr); sys.exit(1)
if args[0] == 'pull' and os.environ.get('FAKE_PRIMARY_FAILURE') and args[-1].startswith('public.ecr.aws/'):
    print('429 SECRET_SENTINEL', file=sys.stderr); sys.exit(1)
if os.environ.get('FAKE_SLEEP'):
    time.sleep(60)
if args[:2] == ['image','inspect']:
    ref=args[-1]; repo=ref.split(':',1)[0]; digest=ref.split('@')[1]
    print(json.dumps([{'Os':'linux','Architecture':'amd64','RepoDigests':[repo+'@'+digest]}]))
''')
        fake.chmod(0o755)
        # Execute the real resolver entry point with only backoff elided in fault injection.
        python = self.folder / 'python3'
        python.write_text('#!' + sys.executable + '\nimport sys\n'
                          + 'sys.path.insert(0, ' + repr(str(ROOT / '.github/scripts')) + ')\n'
                          + 'import resolve_official_image as r\nr.time.sleep=lambda _: None\n'
                          + 'sys.exit(r.main(sys.argv[2:]))\n')
        python.chmod(0o755)

    def calls(self):
        log = Path(self.env['FAKE_LOG'])
        return [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []

    def run_build(self, override=None):
        env = self.env.copy()
        if override is not None:
            env['SIGNACORE_NODE_IMAGE'] = override
        return subprocess.run(['bash', str(ROOT / 'build.sh')], env=env, capture_output=True, text=True)

    def test_default_build_has_no_override_and_keeps_context(self):
        self.assertEqual(self.run_build().returncode, 0)
        args = self.calls()[0]['args']
        self.assertNotIn('--build-arg', args)
        self.assertEqual(Path(args[-1]).resolve(), ROOT)

    def test_allowed_build_override_reaches_docker_arg(self):
        for reference in resolver.references('node'):
            self.assertEqual(self.run_build(reference).returncode, 0)
            args = self.calls()[-1]['args']
            self.assertEqual(args[args.index('--build-arg')+1], 'NODE_IMAGE=' + reference)
        dockerfile = (ROOT / 'src/SignaCore.Host/Dockerfile').read_text()
        self.assertIn('ARG NODE_IMAGE=public.ecr.aws/docker/library/node:24-alpine\nFROM ${NODE_IMAGE}', dockerfile)

    def test_unknown_build_override_rejected_before_docker(self):
        for reference in ['evil/node:24-alpine', 'docker.io/library/node:24-alpine',
                          resolver.references('postgres')[1], resolver.references('node')[1] + '\nEVIL=1']:
            self.assertEqual(self.run_build(reference).returncode, 2)
        self.assertEqual(self.calls(), [])

    def step(self, name):
        text = (ROOT / '.github/workflows/ci.yml').read_text()
        block = text.split('      - name: ' + name + '\n', 1)[1].split('\n      - ', 1)[0]
        return '\n'.join(line[10:] for line in block.split('        run: |\n', 1)[1].splitlines())

    def test_each_job_exports_effective_reference_only_after_success(self):
        for name, profile, variable in [('Resolve official Node image', 'node', 'SIGNACORE_NODE_IMAGE'),
                                        ('Pre-pull PostgreSQL image', 'postgres', 'SIGNACORE_POSTGRES_IMAGE'),
                                        ('Pre-pull database images', 'postgres', 'SIGNACORE_POSTGRES_IMAGE')]:
            with self.subTest(step=name):
                env = self.env.copy(); envfile = self.folder / 'github-env'
                envfile.write_text(''); env['GITHUB_ENV'] = str(envfile)
                env['FAKE_PRIMARY_FAILURE'] = '1'
                result = subprocess.run(['bash', '-e', '-c', self.step(name)], cwd=ROOT,
                                        env=env, capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(envfile.read_text(), variable + '=' + resolver.references(profile)[1] + '\n')
                # A hard error must not publish a partial reference or any raw response.
                envfile.write_text('')
                env['FAKE_HARD_ERROR'] = '1'
                result = subprocess.run(['/bin/bash', '-e', '-c', self.step(name)], cwd=ROOT,
                                        env=env, capture_output=True, text=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(envfile.read_text(), '')
                self.assertNotIn('SECRET_SENTINEL', result.stderr)

    def test_workflow_consumers_and_original_gates_remain(self):
        workflow = (ROOT / '.github/workflows/ci.yml').read_text()
        self.assertEqual(workflow.count('resolve_official_image.py postgres'), 2)
        self.assertIn('"$SIGNACORE_POSTGRES_IMAGE"', self.step('Start PostgreSQL'))
        self.assertIn('run: bash build.sh', workflow)
        for marker in ['name: Build & Test', 'name: Database Contract Matrix',
                       'Scan image for high and critical vulnerabilities', 'Generate image SBOM',
                       'Reference BFF database contracts', 'verify_oidc_matrix.py reports',
                       'Setup Mode assertions', 'Token issuance end-to-end', 'consumed refresh token replay was accepted']:
            self.assertIn(marker, workflow)
        for file in (ROOT / 'tests').rglob('*.cs'):
            if 'new PostgreSqlBuilder' in file.read_text():
                # Input can be factored within a class or into a sibling partial member.
                self.assertIn('SIGNACORE_POSTGRES_IMAGE', ''.join(
                    f.read_text() for f in file.parent.glob(file.stem.split('.')[0] + '*.cs')))

    def test_concurrent_resolvers_are_independent(self):
        def run(profile):
            return subprocess.run([sys.executable, str(ROOT / '.github/scripts/resolve_official_image.py'), profile],
                                  env=self.env, capture_output=True, text=True)
        with concurrent.futures.ThreadPoolExecutor() as pool:
            results = list(pool.map(run, ['node', 'postgres']))
        for profile, result in zip(['node', 'postgres'], results):
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, resolver.references(profile)[0] + '\n')
        self.assertEqual(len(self.calls()), 4)

    def test_real_sigterm_stops_child_and_does_not_publish(self):
        self.env['FAKE_SLEEP'] = '1'
        process = subprocess.Popen([sys.executable, str(ROOT / '.github/scripts/resolve_official_image.py'), 'node'],
                                   env=self.env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            deadline = time.monotonic() + 5
            while not self.calls() and time.monotonic() < deadline:
                time.sleep(.01)
            self.assertTrue(self.calls())
            process.send_signal(signal.SIGTERM)
            stdout, stderr = process.communicate(timeout=5)
            self.assertEqual(process.returncode, 130)
            self.assertEqual(stdout, '')
            self.assertIn('category=cancelled', stderr)
            self.assertEqual(len(self.calls()), 1)
            with self.assertRaises(ProcessLookupError):
                os.kill(self.calls()[0]['pid'], 0)
        finally:
            if process.poll() is None:
                process.kill(); process.communicate()

    def test_real_timeout_reaps_child(self):
        self.env['FAKE_SLEEP'] = '1'
        with patch.dict(os.environ, self.env):
            with self.assertRaises(subprocess.TimeoutExpired):
                resolver.command(['docker', 'pull', 'unused'], .1)
        self.assertEqual(len(self.calls()), 1)
        with self.assertRaises(ProcessLookupError):
            os.kill(self.calls()[0]['pid'], 0)


if __name__ == '__main__':
    unittest.main()
