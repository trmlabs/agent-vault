#!/usr/bin/env python3
"""Verify strict executable initialization and controlled Vault re-login locally.

Uses one disposable Vault container and a fresh temporary broker store. No
Kubernetes server, caller admission, destination request or network policy is
exercised. Requires Docker, Go and OpenSSL. Never points at an existing Vault.
"""
import argparse
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import subprocess
import tempfile
import time
import urllib.request

VAULT_IMAGE = 'hashicorp/vault:1.19.4@sha256:b5f675b0bf681568cd7354c697fe4ce953024312d6d23ee7216deda60c192bad'
HTTP = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def command(args, **kwargs):
    # Never surface subprocess arguments or captured output: they may hold proof.
    result = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            timeout=300, **kwargs)
    if result.returncode:
        raise RuntimeError('subprocess failed')
    return result.stdout.decode().strip()


def request(url, body=None, headers=None, method=None):
    req = urllib.request.Request(url, data=None if body is None else json.dumps(body).encode(),
                                 headers={'Content-Type': 'application/json', **(headers or {})}, method=method)
    with HTTP.open(req, timeout=5) as response:
        return json.loads(response.read() or '{}')


def free_port():
    with socket.socket() as listener:
        listener.bind(('127.0.0.1', 0))
        return listener.getsockname()[1]


def stop(process):
    if process is None:
        return
    process.terminate()
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=10)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--docker-host', required=True, help='explicit disposable local unix:// Docker socket')
    args = parser.parse_args()
    if not args.docker_host.startswith('unix:///'):
        parser.error('use an explicit disposable local Unix Docker socket')
    for tool in ('docker', 'go', 'openssl'):
        if not shutil.which(tool):
            parser.error('required tool missing: ' + tool)
    docker = ['docker', '--host', args.docker_host]
    name = 'credential-proxy-bootstrap-' + secrets.token_hex(8)
    root = secrets.token_hex(24)
    process, log, created = None, None, False
    stage = 'prepare'
    try:
        with tempfile.TemporaryDirectory(prefix='credential-proxy-bootstrap-') as directory:
            work = Path(directory)
            os.chmod(work, 0o700)
            try:
                stage = 'build executable'
                binary = str(work / 'agent-vault')
                command(['go', 'build', '-o', binary, '.'], cwd=Path(__file__).resolve().parents[2])
                stage = 'start disposable Vault'
                # Create first so cleanup can identify ownership before start fails.
                command(docker + ['create', '--name', name, '-p', '127.0.0.1::8200',
                                  '--entrypoint', '/bin/vault', VAULT_IMAGE, 'server', '-dev',
                                  '-dev-no-store-token', '-dev-root-token-id=' + root,
                                  '-dev-listen-address=0.0.0.0:8200'])
                created = True
                command(docker + ['start', name])
                address = 'http://' + command(docker + ['port', name, '8200/tcp'])

                def vault(path, body=None, method=None):
                    return request(address + '/v1/' + path, body, {'X-Vault-Token': root}, method)

                deadline = time.monotonic() + 15
                while True:
                    try:
                        vault('sys/health')
                        break
                    except Exception:
                        if time.monotonic() >= deadline:
                            raise RuntimeError('Vault readiness timeout') from None
                        time.sleep(.2)
                stage = 'configure short-lived AppRole'
                vault('sys/auth/approle', {'type': 'approle'})
                vault('sys/policies/acl/bootstrap', {'policy': 'path "secret/data/bootstrap" { capabilities = ["read"] }'})
                vault('auth/approle/role/bootstrap', {'token_policies': ['bootstrap'], 'token_ttl': '20s',
                                                    'token_max_ttl': '20s', 'secret_id_ttl': '10m'})
                role = vault('auth/approle/role/bootstrap/role-id')['data']['role_id']
                secret = vault('auth/approle/role/bootstrap/secret-id', {})['data']['secret_id']
                command(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', str(work / 'key.pem'),
                         '-out', str(work / 'ca.pem'), '-subj', '/CN=fixture.invalid', '-days', '1'])
                (work / 'reviewer').write_text('synthetic-reviewer-not-used-during-bootstrap')
                config = {'apiServer': 'https://127.0.0.1:1', 'caFile': str(work / 'ca.pem'),
                          'reviewerTokenFile': str(work / 'reviewer'), 'issuer': 'fixture', 'audience': 'credential-proxy',
                          'bindings': [{'namespace': 'closed', 'serviceAccount': 'unadmitted',
                                        'serviceAccountUID': 'sentinel', 'agentID': 'nonexistent-agent', 'vaultID': 'nonexistent-vault'}]}
                (work / 'identity.json').write_text(json.dumps(config))
                management, http, pg = free_port(), free_port(), free_port()
                base = 'http://127.0.0.1:' + str(management)
                env = {'PATH': os.environ['PATH'], 'HOME': directory, 'AGENT_VAULT_MASTER_PASSWORD': secrets.token_hex(24),
                       'AGENT_VAULT_CREDENTIAL_PROXY': 'true', 'AGENT_VAULT_WORKLOAD_IDENTITY_FILE': str(work / 'identity.json'),
                       'AGENT_VAULT_DB_BROKER': 'true', 'VAULT_ADDR': address, 'VAULT_ROLE_ID': role,
                       'VAULT_SECRET_ID': secret, 'DO_NOT_TRACK': '1'}
                log = open(work / 'server.log', 'wb')

                def start():
                    nonlocal process
                    process = subprocess.Popen([binary, 'server', '--host', '127.0.0.1', '--port', str(management),
                                                '--mitm-port', str(http), '--postgres-port', str(pg)],
                                               env=env, stdout=log, stderr=log)
                    deadline = time.monotonic() + 20
                    while time.monotonic() < deadline:
                        if process.poll() is not None:
                            raise RuntimeError('server exited during startup')
                        try:
                            for port in (management, http, pg):
                                with socket.create_connection(('127.0.0.1', port), .1):
                                    pass
                            return
                        except OSError:
                            time.sleep(.1)
                    raise RuntimeError('server readiness timeout')

                stage = 'strict cold-store bootstrap'
                start()
                account = request(base + '/v1/auth/register', {'email': 'owner@example.test',
                                  'password': secrets.token_hex(24), 'device_label': 'bootstrap-check'})
                assert account['role'] == 'owner' and account['authenticated'] is True
                owner = {'Authorization': 'Bearer ' + account['token']}
                created_vault = request(base + '/v1/vaults', {'name': 'bootstrap', 'credential_store': {
                    'kind': 'hashicorp', 'config': {'mount': 'secret', 'secret_path': 'bootstrap', 'kv_version': 2}}}, owner)
                assert created_vault['id']
                # Discard the compatibility token; it is never passed to a caller.
                request(base + '/v1/agents', {'name': 'bootstrap-agent', 'role': 'no-access',
                        'vaults': [{'vault_name': 'bootstrap', 'vault_role': 'proxy'}]}, owner)
                exported = request(base + '/v1/agents/bootstrap-agent', headers=owner)
                assert exported['id'] and exported['role'] == 'no-access'
                assert exported['vaults'] == [{'vault_name': 'bootstrap', 'vault_role': 'proxy'}]
                assert 'token' not in exported and 'av_agent_token' not in exported
                print('PASS: strict executable sentinel startup, owner registration, HashiCorp vault, proxy grant and stable ID export', flush=True)
                stage = 'AppRole expiry and controlled restart'
                accessors = vault('auth/token/accessors', method='LIST')['data']['keys']
                live = [vault('auth/token/lookup-accessor', {'accessor': item})['data'] for item in accessors]
                live = [item for item in live if item['path'] == 'auth/approle/login']
                assert len(live) == 1 and 0 < live[0]['ttl'] <= 20
                time.sleep(22)
                remaining = vault('auth/token/accessors', method='LIST')['data']['keys']
                assert live[0]['accessor'] not in remaining and process.poll() is None
                stop(process)
                process = None
                start()
                accessors = vault('auth/token/accessors', method='LIST')['data']['keys']
                after = [vault('auth/token/lookup-accessor', {'accessor': item})['data'] for item in accessors]
                assert any(item['path'] == 'auth/approle/login' and item['ttl'] > 0 for item in after)
                assert request(base + '/v1/agents/bootstrap-agent', headers=owner)['id'] == exported['id']
                print('PASS: login expires without renewal; same-store restart logs in again and preserves owner session/agent ID')
                print('SCOPE: no caller admitted; post-expiry request denial, TokenReview and deployed isolation are not tested')
            finally:
                try:
                    stop(process)
                finally:
                    if log:
                        log.close()
                    if created:
                        command(docker + ['rm', '-f', name])
    except Exception:
        # Exceptions can include credentials in subprocess argv or server bodies.
        print('FAIL: ' + stage + '; sensitive diagnostic output suppressed')
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
