import sqlite3
from datetime import datetime, timedelta, timezone

import jwt
import pytest
from argon2 import PasswordHasher
from secure_api import create_app


@pytest.fixture()
def app(tmp_path):
    return create_app({'TESTING': True, 'DATABASE': str(tmp_path / 'test.sqlite'), 'JWT_SECRET': 'test-only-key-' + 'x' * 40})


@pytest.fixture()
def client(app):
    return app.test_client()


def register(client, login='student'):
    return client.post('/auth/register', json={'login': login, 'password': 'Demo-password-2026!'})


def token(client, login='student'):
    return client.post('/auth/login', json={'login': login, 'password': 'Demo-password-2026!'}).json['access_token']


def test_registration_and_password_storage(client, app):
    assert register(client).status_code == 201
    assert register(client).status_code == 409
    with sqlite3.connect(app.config['DATABASE']) as connection:
        stored = connection.execute('SELECT password_hash FROM users').fetchone()[0]
    assert stored.startswith('$argon2id$')
    assert PasswordHasher().verify(stored, 'Demo-password-2026!')


def test_login_and_protected_data(client):
    register(client)
    result = client.get('/api/data', headers={'Authorization': 'Bearer ' + token(client)})
    assert result.status_code == 200
    assert result.json['user']['login'] == 'student'
    assert 'password_hash' not in result.get_data(as_text=True)


@pytest.mark.parametrize('login,password', [('student', 'Wrong-password-2026'), ('unknown', 'Demo-password-2026!')])
def test_wrong_credentials(client, login, password):
    register(client)
    assert client.post('/auth/login', json={'login': login, 'password': password}).status_code == 401


@pytest.mark.parametrize('authorization', ['', 'Bearer invalid', 'Basic abc', 'Bearer'])
def test_unauthorized(client, authorization):
    assert client.get('/api/data', headers={'Authorization': authorization}).status_code == 401


@pytest.mark.parametrize('variant', ['expired', 'wrong_key', 'wrong_audience', 'missing_exp', 'none'])
def test_invalid_tokens(client, app, variant):
    register(client)
    now = datetime.now(timezone.utc)
    claims = {'sub': '1', 'iat': now, 'exp': now + timedelta(minutes=5), 'iss': 'infosec-lab-01', 'aud': 'infosec-api'}
    key = app.config['JWT_SECRET']
    algorithm = 'HS256'
    if variant == 'expired':
        claims['exp'] = now - timedelta(seconds=1)
    elif variant == 'wrong_key':
        key = 'another-test-key-' + 'y' * 40
    elif variant == 'wrong_audience':
        claims['aud'] = 'other-service'
    elif variant == 'missing_exp':
        del claims['exp']
    else:
        key, algorithm = None, 'none'
    encoded = jwt.encode(claims, key, algorithm=algorithm)
    assert client.get('/api/data', headers={'Authorization': 'Bearer ' + encoded}).status_code == 401


def test_sql_input_is_data(client):
    register(client)
    payload = "' OR 1=1 --"
    assert client.post('/auth/login', json={'login': payload, 'password': 'Demo-password-2026!'}).status_code == 401
    assert register(client, payload).status_code == 201
    result = client.get('/api/data', headers={'Authorization': 'Bearer ' + token(client, payload)})
    assert result.status_code == 200
    assert result.json['user']['id'] == 2


def test_output_escaping_preserves_database(client, app):
    login = '<script>alert(1)</script>'
    assert register(client, login).json['login'] == '&lt;script&gt;alert(1)&lt;/script&gt;'
    result = client.get('/api/data', headers={'Authorization': 'Bearer ' + token(client, login)})
    assert result.json['user']['login'] == '&lt;script&gt;alert(1)&lt;/script&gt;'
    assert result.mimetype == 'application/json'
    assert result.headers['X-Content-Type-Options'] == 'nosniff'
    with sqlite3.connect(app.config['DATABASE']) as connection:
        assert connection.execute('SELECT login FROM users').fetchone()[0] == login


@pytest.mark.parametrize('data', [None, [], {}, {'login': 1, 'password': 'Demo-password-2026!'}, {'login': 'student', 'password': 'short'}, {'login': ' student', 'password': 'Demo-password-2026!'}])
def test_bad_input(client, data):
    assert client.post('/auth/register', json=data).status_code in (400, 415)


def test_malformed_and_large_requests(client):
    assert client.post('/auth/login', data='{', content_type='application/json').status_code == 400
    assert client.post('/auth/register', data='x' * 20000, content_type='application/json').status_code == 413
    assert client.get('/missing').status_code == 404


def test_secret_required(tmp_path):
    with pytest.raises(ValueError):
        create_app({'DATABASE': str(tmp_path / 'db'), 'JWT_SECRET': ''})
