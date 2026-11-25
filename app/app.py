import os
import time
import json
import base64
import pickle
import hashlib
import secrets
import sqlite3
import threading
import zipfile
import tempfile
from io import BytesIO
from pathlib import Path
from functools import wraps
from collections import defaultdict, deque
from urllib.parse import urlparse

import jwt
import yaml
from lxml import etree
from flask import (
    Flask, request, render_template, render_template_string, redirect,
    url_for, session, make_response, jsonify, g, abort, send_from_directory, Response
)
from werkzeug.utils import secure_filename
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

APP_DIR = os.path.dirname(__file__)
DB_PATH = os.path.join(APP_DIR, 'vaultcorp.db')
UPLOAD_DIR = os.path.join(APP_DIR, 'uploads')
FLAG_DIR = os.environ.get('FLAG_DIR', '/tmp/.vault/missing')

SECRET_EXPORT_SEG = os.environ.get('SECRET_EXPORT_SEG', 'missing')
SECRET_CONFIG_SEG = os.environ.get('SECRET_CONFIG_SEG', 'missing')
SECRET_ADMIN_HOST = os.environ.get('SECRET_ADMIN_HOST', 'missing.internal')
RSA_KID = os.environ.get('RSA_KID', 'k1')
HMAC_SECRET = os.environ.get('HMAC_SECRET', 'change-me')
FLAG_JWT = os.environ.get('FLAG_JWT', 'VenD{unset}')
FLAG_PICKLE = os.environ.get('FLAG_PICKLE', 'VenD{unset}')
FLAG_RACE = os.environ.get('FLAG_RACE', 'VenD{unset}')
FLAG_YAML = os.environ.get('FLAG_YAML', 'VenD{unset}')
FLAG_HOST = os.environ.get('FLAG_HOST', 'VenD{unset}')
FLAG_CAPSTONE = os.environ.get('FLAG_CAPSTONE', 'VenD{unset}')

app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET', 'dev')
app.config['SITE_SECRET'] = HMAC_SECRET
app.config['INTERNAL_NOTE'] = f'FLAG_SSTI_LOCATION={FLAG_DIR}/flag_ssti'

RSA_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
RSA_PUB_PEM = RSA_KEY.public_key().public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
).decode()

_rate = defaultdict(lambda: deque())
_banned = {}
_rate_lock = threading.Lock()

def client_ip():
    return request.headers.get('X-Forwarded-For', request.remote_addr or '0.0.0.0').split(',')[0].strip()

@app.before_request
def rate_limit():
    ip = client_ip()
    now = time.time()
    if ip in _banned and _banned[ip] > now:
        return jsonify({'error': 'temporarily banned', 'retry_after': int(_banned[ip] - now)}), 429
    honeypots = ('/wp-login.php', '/.env', '/admin.php', '/phpmyadmin', '/.git/HEAD')
    if request.path in honeypots or request.path.startswith('/.git/'):
        _banned[ip] = now + 300
        return jsonify({'error': 'banned for 5 min'}), 403
    exempt_prefixes = ('/claim/', '/store/transfer')
    if any(request.path.startswith(p) for p in exempt_prefixes):
        return
    with _rate_lock:
        q = _rate[ip]
        while q and q[0] < now - 1:
            q.popleft()
        if len(q) >= 15:
            return jsonify({'error': 'rate limit (15 req/s)'}), 429
        q.append(now)

def db():
    if 'db' not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(e=None):
    d = g.pop('db', None)
    if d:
        d.close()

def hash_pw(pw):
    return hashlib.sha256(pw.encode()).hexdigest()

def login_required(f):
    @wraps(f)
    def wrapper(*a, **kw):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*a, **kw)
    return wrapper

def current_user():
    if 'user_id' not in session:
        return None
    row = db().execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    return dict(row) if row else None

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/robots.txt')
def robots():
    body = (
        "User-agent: *\n"
        "Disallow: /internal/\n"
        "Disallow: /tools/\n"
        f"Disallow: /partner/{SECRET_CONFIG_SEG}/\n"
        "Disallow: /export/\n"
    )
    return Response(body, mimetype='text/plain')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        u = request.form.get('username', '').strip()
        p = request.form.get('password', '')
        e = request.form.get('email', '').strip()
        if not u or not p:
            return render_template('register.html', error='Username and password required.')
        if len(u) > 80 or any(c in u for c in '<>"'):
            return render_template('register.html', error='Invalid characters in username.')
        try:
            db().execute(
                'INSERT INTO users (username, password, email, bio) VALUES (?, ?, ?, ?)',
                (u, hash_pw(p), e, '')
            )
            db().commit()
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            return render_template('register.html', error='Username taken.')
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        u = request.form.get('username', '')
        p = request.form.get('password', '')
        row = db().execute(
            'SELECT * FROM users WHERE username = ? AND password = ?',
            (u, hash_pw(p))
        ).fetchone()
        if row:
            session['user_id'] = row['id']
            session['username'] = row['username']
            return redirect(url_for('dashboard'))
        return render_template('login.html', error='Invalid credentials.')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    u = current_user()
    return render_template('dashboard.html', user=u)

@app.route('/directory')
@login_required
def directory():
    rows = db().execute('SELECT username, email, bio FROM users').fetchall()
    cards = []
    for r in rows:
        bio_raw = r['bio'] or ''
        try:
            rendered_bio = render_template_string(bio_raw) if bio_raw else ''
        except Exception as ex:
            rendered_bio = f'(template error: {ex})'
        cards.append({'username': r['username'], 'email': r['email'], 'bio': rendered_bio})
    return render_template('directory.html', cards=cards)

@app.route('/profile', methods=['GET'])
@login_required
def profile():
    u = current_user()
    return render_template('profile.html', user=u)

@app.route('/profile/update', methods=['POST'])
@login_required
def profile_update():
    u = current_user()
    email = request.form.get('email', u['email'])
    bio = request.form.get('bio', u['bio'])
    db().execute('UPDATE users SET email = ?, bio = ? WHERE id = ?', (email, bio, u['id']))
    db().commit()
    return redirect(url_for('profile'))

@app.route('/session/save', methods=['POST'])
@login_required
def session_save():
    u = current_user()
    data = {
        'user_id': u['id'],
        'username': u['username'],
        'saved_at': int(time.time()),
        'theme': request.form.get('theme', 'light'),
    }
    blob = base64.b64encode(pickle.dumps(data)).decode()
    resp = make_response(jsonify({'status': 'saved', 'cookie': 'vc_session_blob'}))
    resp.set_cookie('vc_session_blob', blob, httponly=False)
    return resp

@app.route('/session/restore', methods=['GET'])
@login_required
def session_restore():
    blob = request.cookies.get('vc_session_blob', '')
    if not blob:
        return jsonify({'status': 'no saved session'})
    try:
        raw = base64.b64decode(blob)
        data = pickle.loads(raw)
        return jsonify({'status': 'restored', 'data': str(data)[:400]})
    except Exception as ex:
        return jsonify({'status': 'error', 'error': str(ex)}), 400

@app.route('/.well-known/jwks.json')
def jwks():
    pub = RSA_KEY.public_key().public_numbers()
    def b64u(n):
        b = n.to_bytes((n.bit_length() + 7) // 8, 'big')
        return base64.urlsafe_b64encode(b).decode().rstrip('=')
    return jsonify({
        'keys': [{
            'kty': 'RSA',
            'kid': RSA_KID,
            'alg': 'RS256',
            'use': 'sig',
            'n': b64u(pub.n),
            'e': b64u(pub.e),
        }]
    })

@app.route('/api/token', methods=['POST'])
def api_token():
    data = request.get_json(silent=True) or request.form
    u = data.get('username', '')
    p = data.get('password', '')
    row = db().execute(
        'SELECT * FROM users WHERE username = ? AND password = ?',
        (u, hash_pw(p))
    ).fetchone()
    if not row:
        return jsonify({'error': 'invalid'}), 401
    priv_pem = RSA_KEY.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    tok = jwt.encode(
        {'sub': row['id'], 'username': row['username'], 'role': row['role']},
        priv_pem,
        algorithm='RS256',
        headers={'kid': RSA_KID}
    )
    return jsonify({'token': tok, 'alg': 'RS256', 'kid': RSA_KID})

def verify_token():
    import hmac as _hmac, hashlib as _h, base64 as _b
    auth = request.headers.get('Authorization', '')
    if not auth.startswith('Bearer '):
        return None
    tok = auth[7:]
    try:
        parts = tok.split('.')
        if len(parts) != 3:
            return None
        def _pad(s): return s + '=' * (-len(s) % 4)
        header = json.loads(_b.urlsafe_b64decode(_pad(parts[0])))
        payload = json.loads(_b.urlsafe_b64decode(_pad(parts[1])))
        sig_in = (parts[0] + '.' + parts[1]).encode()
        sig = _b.urlsafe_b64decode(_pad(parts[2]))
        alg = header.get('alg', 'RS256')
        if alg == 'HS256':
            expected = _hmac.new(RSA_PUB_PEM.encode(), sig_in, _h.sha256).digest()
            if not _hmac.compare_digest(sig, expected):
                return None
            return payload
        elif alg == 'RS256':
            decoded = jwt.decode(tok, RSA_PUB_PEM, algorithms=['RS256'])
            return decoded
        return None
    except Exception:
        return None

@app.route('/api/me')
def api_me():
    p = verify_token()
    if not p:
        return jsonify({'error': 'auth required'}), 401
    return jsonify(p)

@app.route('/api/admin/vault')
def api_admin_vault():
    p = verify_token()
    if not p:
        return jsonify({'error': 'auth required'}), 401
    if p.get('role') != 'admin':
        return jsonify({'error': 'admin only'}), 403
    return jsonify({'flag': FLAG_JWT})

@app.route('/store')
@login_required
def store():
    u = current_user()
    items = [dict(r) for r in db().execute('SELECT * FROM items').fetchall()]
    users = [dict(r) for r in db().execute('SELECT id, username FROM users WHERE id != ?', (u['id'],)).fetchall()]
    return render_template('store.html', user=u, items=items, users=users, message=session.pop('msg', None))

@app.route('/store/transfer', methods=['POST'])
@login_required
def store_transfer():
    u = current_user()
    try:
        to_id = int(request.form.get('to_user', 0))
        amount = int(request.form.get('amount', 0))
    except ValueError:
        session['msg'] = 'Invalid input.'
        return redirect(url_for('store'))
    if amount <= 0:
        session['msg'] = 'Amount must be positive.'
        return redirect(url_for('store'))
    if to_id == u['id']:
        session['msg'] = 'Cannot transfer to yourself.'
        return redirect(url_for('store'))
    bal = db().execute('SELECT coins FROM users WHERE id = ?', (u['id'],)).fetchone()['coins']
    if bal < amount:
        session['msg'] = 'Insufficient balance.'
        return redirect(url_for('store'))
    time.sleep(0.25)
    db().execute('UPDATE users SET coins = coins - ? WHERE id = ?', (amount, u['id']))
    db().execute('UPDATE users SET coins = coins + ? WHERE id = ?', (amount, to_id))
    db().commit()
    session['msg'] = f'Transferred {amount} to #{to_id}.'
    return redirect(url_for('store'))

@app.route('/claim/daily', methods=['POST'])
@login_required
def claim_daily():
    u = current_user()
    already = db().execute('SELECT 1 FROM claims WHERE user_id=?', (u['id'],)).fetchone()
    if already:
        return jsonify({'error': 'already claimed today'}), 400
    time.sleep(0.15)
    db().execute('INSERT INTO claims (user_id) VALUES (?)', (u['id'],))
    db().execute('UPDATE users SET coins = coins + 500 WHERE id = ?', (u['id'],))
    db().commit()
    return jsonify({'credited': 500})

@app.route('/store/buy', methods=['POST'])
@login_required
def store_buy():
    u = current_user()
    try:
        item_id = int(request.form.get('item_id', 0))
    except ValueError:
        session['msg'] = 'Invalid item.'
        return redirect(url_for('store'))
    item = db().execute('SELECT * FROM items WHERE id = ?', (item_id,)).fetchone()
    if not item:
        session['msg'] = 'Not found.'
        return redirect(url_for('store'))
    fresh = db().execute('SELECT coins FROM users WHERE id = ?', (u['id'],)).fetchone()
    if fresh['coins'] < item['price']:
        session['msg'] = f'Need {item["price"]} coins, you have {fresh["coins"]}.'
        return redirect(url_for('store'))
    db().execute('UPDATE users SET coins = coins - ? WHERE id = ?', (item['price'], u['id']))
    db().commit()
    if item['name'] == 'Legendary Vault Key':
        session['msg'] = f'Purchase complete. FLAG: {FLAG_RACE}'
    else:
        session['msg'] = f'Purchased {item["name"]}.'
    return redirect(url_for('store'))

@app.route('/avatar/upload', methods=['POST'])
@login_required
def avatar_upload():
    u = current_user()
    if 'file' not in request.files:
        return jsonify({'error': 'no file'}), 400
    f = request.files['file']
    name = secure_filename(f.filename or 'avatar')
    if not name.lower().endswith(('.svg', '.png', '.jpg', '.jpeg')):
        return jsonify({'error': 'unsupported type'}), 400
    dest = os.path.join(UPLOAD_DIR, f'u{u["id"]}_{name}')
    f.save(dest)
    if name.lower().endswith('.svg'):
        try:
            parser = etree.XMLParser(resolve_entities=True, load_dtd=True, no_network=True)
            tree = etree.parse(dest, parser)
            root = tree.getroot()
            preview = etree.tostring(root, pretty_print=True).decode(errors='replace')[:2000]
            db().execute('UPDATE users SET avatar = ? WHERE id = ?', (dest, u['id']))
            db().commit()
            return jsonify({'status': 'saved', 'preview': preview})
        except Exception as ex:
            return jsonify({'error': str(ex)}), 400
    db().execute('UPDATE users SET avatar = ? WHERE id = ?', (dest, u['id']))
    db().commit()
    return jsonify({'status': 'saved'})

@app.route(f'/export/<seg>/orders')
def export_orders(seg):
    if seg != SECRET_EXPORT_SEG:
        return jsonify({'error': 'unknown export'}), 404
    p = verify_token()
    if not p:
        return jsonify({'error': 'auth required'}), 401
    username = p.get('username', '')
    try:
        c = db().cursor()
        q = f"SELECT item, note FROM orders WHERE user_id IN (SELECT id FROM users WHERE username = '{username}') UNION SELECT k, v FROM secrets_vault WHERE k IN (SELECT '{username}' as k)"
        c.execute(q)
        return jsonify({'rows': [list(r) for r in c.fetchall()]})
    except Exception as ex:
        return jsonify({'error': str(ex), 'query': q}), 500

@app.route('/internal/')
def internal_index():
    return jsonify({
        'service': 'internal',
        'endpoints': [
            f'/partner/{SECRET_CONFIG_SEG}/import',
            '/internal/bulk/import',
        ],
        'note': 'For partner integrations only. Not for public use.'
    })

@app.route(f'/partner/<seg>/import', methods=['POST'])
def partner_import(seg):
    if seg != SECRET_CONFIG_SEG:
        return jsonify({'error': 'invalid partner key'}), 404
    raw = request.get_data(as_text=True) or ''
    try:
        parsed = yaml.load(raw, Loader=yaml.Loader)
        return jsonify({'parsed': str(parsed)[:500]})
    except Exception as ex:
        return jsonify({'error': str(ex)}), 400

@app.route('/internal/bulk/import', methods=['POST'])
@login_required
def bulk_import():
    if 'archive' not in request.files:
        return jsonify({'error': 'archive field required'}), 400
    f = request.files['archive']
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix='.zip')
    f.save(tmp.name)
    extracted = []
    try:
        with zipfile.ZipFile(tmp.name) as z:
            for info in z.infolist():
                target = os.path.join(UPLOAD_DIR, info.filename)
                os.makedirs(os.path.dirname(target), exist_ok=True)
                with z.open(info) as src, open(target, 'wb') as dst:
                    dst.write(src.read())
                extracted.append(info.filename)
    except Exception as ex:
        os.unlink(tmp.name)
        return jsonify({'error': str(ex)}), 400
    os.unlink(tmp.name)
    return jsonify({'extracted': extracted})

@app.route('/internal/bulk/view')
@login_required
def bulk_view():
    name = request.args.get('name', '')
    try:
        p = os.path.join(UPLOAD_DIR, name)
        with open(p, 'rb') as fh:
            data = fh.read()
        return Response(data, mimetype='text/plain')
    except Exception as ex:
        return jsonify({'error': str(ex)}), 404

@app.route('/admin/vault')
def admin_vault():
    host = request.headers.get('Host', '')
    if host != SECRET_ADMIN_HOST:
        return jsonify({'error': 'not found'}), 404
    return jsonify({'flag': FLAG_HOST, 'note': 'Vault accessed via internal host.'})

@app.route('/api/capstone')
def api_capstone():
    p = verify_token()
    if not p:
        return jsonify({'error': 'auth required'}), 401
    if p.get('role') != 'admin':
        return jsonify({'error': 'admin only'}), 403
    sig = request.headers.get('X-Vault-Sig', '')
    presented_ssti = request.headers.get('X-SSTI-Flag', '')
    presented_yaml = request.headers.get('X-YAML-Flag', '')
    expected = hashlib.sha256((presented_ssti + presented_yaml + HMAC_SECRET).encode()).hexdigest()
    if sig != expected:
        return jsonify({'error': 'invalid vault signature'}), 403
    return jsonify({'flag': FLAG_CAPSTONE})

@app.errorhandler(404)
def nf(_e):
    return jsonify({'error': 'not found'}), 404

@app.errorhandler(500)
def ise(e):
    return jsonify({'error': 'server error', 'type': type(e).__name__}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)
