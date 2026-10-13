"""Small educational API with password hashing and token authentication."""
import os
import sqlite3
from datetime import datetime, timedelta, timezone
from functools import wraps
from pathlib import Path

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import VerificationError
from flask import Flask, g, jsonify, request
from markupsafe import escape
from werkzeug.exceptions import HTTPException


def create_app(config=None):
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_mapping(
        DATABASE=os.environ.get('API_DATABASE', str(Path(app.instance_path) / 'api.sqlite')),
        JWT_SECRET=os.environ.get('JWT_SECRET', ''),
        JWT_TTL_SECONDS=900,
        MAX_CONTENT_LENGTH=16384,
    )
    if config:
        app.config.update(config)
    secret = app.config['JWT_SECRET']
    if not isinstance(secret, str) or len(secret.encode()) < 32:
        raise ValueError('JWT_SECRET must contain at least 32 bytes; generate it with secrets.token_hex(32).')
    Path(app.config['DATABASE']).parent.mkdir(parents=True, exist_ok=True)
    hasher = PasswordHasher()
    dummy_hash = hasher.hash('unused-dummy-password-for-timing')

    def db():
        if 'db' not in g:
            g.db = sqlite3.connect(app.config['DATABASE'])
            g.db.row_factory = sqlite3.Row
        return g.db

    @app.teardown_appcontext
    def close_db(_error):
        connection = g.pop('db', None)
        if connection is not None:
            connection.close()

    with app.app_context():
        db().execute('CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, login TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL)')
        db().commit()

    def credentials():
        if not request.is_json:
            return None, (jsonify(error='JSON content type required'), 415)
        data = request.get_json()
        if not isinstance(data, dict) or set(data) != {'login', 'password'}:
            return None, (jsonify(error='Expected login and password'), 400)
        login, password = data['login'], data['password']
        if not isinstance(login, str) or not 1 <= len(login) <= 80 or login != login.strip() or any(ord(c) < 32 for c in login):
            return None, (jsonify(error='Invalid login'), 400)
        if not isinstance(password, str) or not 12 <= len(password) <= 128:
            return None, (jsonify(error='Password must contain 12 to 128 characters'), 400)
        return data, None

    def authenticated(view):
        @wraps(view)
        def wrapper(*args, **kwargs):
            auth = request.headers.get('Authorization', '').split()
            if len(auth) != 2 or auth[0].lower() != 'bearer':
                return jsonify(error='Bearer token required'), 401
            try:
                claims = jwt.decode(auth[1], secret, algorithms=['HS256'], issuer='infosec-lab-01', audience='infosec-api', options={'require': ['sub', 'iat', 'exp', 'iss', 'aud']})
                user = db().execute('SELECT id, login FROM users WHERE id = ?', (claims['sub'],)).fetchone()
                if user is None:
                    return jsonify(error='Invalid token'), 401
            except jwt.InvalidTokenError:
                return jsonify(error='Invalid or expired token'), 401
            g.user = user
            return view(*args, **kwargs)
        return wrapper

    @app.post('/auth/register')
    def register():
        data, error = credentials()
        if error:
            return error
        password_hash = hasher.hash(data['password'])
        try:
            cursor = db().execute('INSERT INTO users (login, password_hash) VALUES (?, ?)', (data['login'], password_hash))
            db().commit()
        except sqlite3.IntegrityError:
            return jsonify(error='Login already registered'), 409
        return jsonify(id=cursor.lastrowid, login=str(escape(data['login']))), 201

    @app.post('/auth/login')
    def login():
        data, error = credentials()
        if error:
            return error
        user = db().execute('SELECT id, password_hash FROM users WHERE login = ?', (data['login'],)).fetchone()
        try:
            hasher.verify(user['password_hash'] if user else dummy_hash, data['password'])
        except VerificationError:
            return jsonify(error='Invalid credentials'), 401
        if user is None:
            return jsonify(error='Invalid credentials'), 401
        if hasher.check_needs_rehash(user['password_hash']):
            db().execute('UPDATE users SET password_hash = ? WHERE id = ?', (hasher.hash(data['password']), user['id']))
            db().commit()
        now = datetime.now(timezone.utc)
        token = jwt.encode({'sub': str(user['id']), 'iat': now, 'exp': now + timedelta(seconds=app.config['JWT_TTL_SECONDS']), 'iss': 'infosec-lab-01', 'aud': 'infosec-api'}, secret, algorithm='HS256')
        # Bearer is the standard authentication scheme, not a hardcoded secret.
        return jsonify(access_token=token, token_type='Bearer', expires_in=app.config['JWT_TTL_SECONDS'])  # nosec B106

    @app.get('/api/data')
    @authenticated
    def data():
        return jsonify(user={'id': g.user['id'], 'login': str(escape(g.user['login']))}, data=['Учебные данные'])

    @app.after_request
    def headers(response):
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['Cache-Control'] = 'no-store'
        response.headers['Content-Security-Policy'] = "default-src 'none'; frame-ancestors 'none'"
        return response

    @app.errorhandler(HTTPException)
    def http_error(error):
        return jsonify(error=error.name), error.code

    return app
