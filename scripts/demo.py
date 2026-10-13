"""Real curl requests against a temporary local API."""
import json
import secrets
import subprocess
import sys
import tempfile
import threading
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from secure_api import create_app
from werkzeug.serving import make_server


def main():
    lines = []
    with tempfile.TemporaryDirectory() as directory:
        app = create_app({'DATABASE': str(Path(directory) / 'demo.sqlite'), 'JWT_SECRET': secrets.token_hex(32)})
        server = make_server('127.0.0.1', 0, app)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        base = f'http://127.0.0.1:{server.server_port}'

        def call(label, path, expected, data=None, token=None):
            args = ['curl', '--silent', '--show-error', '--max-time', '10', '--write-out', '\n%{http_code}', base + path]
            if data is not None:
                args += ['-H', 'Content-Type: application/json', '--data', json.dumps(data)]
            if token:
                args += ['-H', 'Authorization: Bearer ' + token]
            result = subprocess.run(args, capture_output=True, text=True, check=True)
            body, code = result.stdout.rsplit('\n', 1)
            parsed = json.loads(body)
            display = dict(parsed)
            if 'access_token' in display:
                display['access_token'] = '[REDACTED: temporary demo token]'
            lines.append(f'{label}: HTTP {code}\n{json.dumps(display, ensure_ascii=False)}')
            assert int(code) == expected, lines[-1]
            return parsed

        try:
            credentials = {'login': 'demo-student', 'password': 'Demo-password-2026!'}
            call('GET /api/data without token', '/api/data', 401)
            call('POST /auth/register', '/auth/register', 201, credentials)
            call('POST /auth/register duplicate', '/auth/register', 409, credentials)
            call('POST /auth/login wrong password', '/auth/login', 401, {**credentials, 'password': 'Wrong-password-2026!'})
            token = call('POST /auth/login', '/auth/login', 200, credentials)['access_token']
            call('GET /api/data with token', '/api/data', 200, token=token)
        finally:
            server.shutdown()
            thread.join()
    output = Path(__file__).resolve().parents[1] / 'evidence' / 'curl-demo.txt'
    output.parent.mkdir(exist_ok=True)
    output.write_text('\n\n'.join(lines) + '\n')
    print(output.read_text())


if __name__ == '__main__':
    main()
