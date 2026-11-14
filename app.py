"""KeyGuard: a local Flask/SQLite cryptography teaching project."""
import csv
import io
import json
import os
import secrets
import sqlite3
from contextlib import contextmanager
from functools import wraps
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from itsdangerous import BadSignature, URLSafeTimedSerializer
from flask import Flask, abort, flash, g, redirect, render_template, request, send_file, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

LIMIT = 8 * 1024 * 1024
DEMO_USERS = [
    ('north.example', 'North Labs', 'alice@north.example', 'employee'),
    ('north.example', 'North Labs', 'ben@north.example', 'employee'),
    ('south.example', 'South Research', 'cara@south.example', 'employee'),
    ('platform.example', 'Platform Operations', 'admin@platform.example', 'admin'),
]


def create_app(data_dir=None):
    app = Flask(__name__)
    root = Path(data_dir or Path(__file__).parent / 'instance-v2')
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    vault = root / 'keys'
    vault.mkdir(exist_ok=True, mode=0o700)
    secret = root / 'session.secret'
    try:
        with open(os.open(secret, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'wb') as f:
            f.write(secrets.token_bytes(32))
    except FileExistsError:
        pass
    app.config.update(SECRET_KEY=secret.read_bytes(), MAX_CONTENT_LENGTH=LIMIT+65536,
                      SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE='Lax')

    @contextmanager
    def db(write=False):
        c = sqlite3.connect(root / 'simulator.db')
        c.row_factory = sqlite3.Row
        c.execute('PRAGMA foreign_keys=ON')
        try:
            if write:
                c.execute('BEGIN IMMEDIATE')
            yield c
            c.commit()
        except Exception:
            c.rollback()
            raise
        finally:
            c.close()

    with db() as c:
        c.executescript("""
        CREATE TABLE IF NOT EXISTS companies(id INTEGER PRIMARY KEY, domain TEXT NOT NULL UNIQUE, name TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, company_id INTEGER NOT NULL REFERENCES companies(id),
            email TEXT NOT NULL UNIQUE, role TEXT NOT NULL CHECK(role IN ('employee','admin')), password_hash TEXT NOT NULL,
            UNIQUE(id,company_id));
        CREATE TABLE IF NOT EXISTS keys(id INTEGER PRIMARY KEY, company_id INTEGER NOT NULL, user_id INTEGER NOT NULL,
            version INTEGER NOT NULL, handle TEXT NOT NULL UNIQUE, status TEXT NOT NULL CHECK(status IN ('active','compromised','revoked')),
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY(user_id,company_id) REFERENCES users(id,company_id),
            UNIQUE(user_id,version), UNIQUE(id,user_id,company_id));
        CREATE UNIQUE INDEX IF NOT EXISTS one_active_key ON keys(user_id) WHERE status='active';
        CREATE TABLE IF NOT EXISTS files(id TEXT PRIMARY KEY, company_id INTEGER NOT NULL, user_id INTEGER NOT NULL,
            key_id INTEGER NOT NULL, name TEXT NOT NULL, nonce BLOB NOT NULL, ciphertext BLOB NOT NULL, size INTEGER NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(key_id,user_id,company_id) REFERENCES keys(id,user_id,company_id));
        CREATE TABLE IF NOT EXISTS incidents(id INTEGER PRIMARY KEY, key_id INTEGER NOT NULL UNIQUE REFERENCES keys(id),
            status TEXT NOT NULL DEFAULT 'open', created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
        CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY, company_id INTEGER NOT NULL REFERENCES companies(id),
            actor TEXT NOT NULL, event TEXT NOT NULL, detail TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
        """)
    with db(write=True) as c:
        for domain, company, email, role in DEMO_USERS:
            c.execute('INSERT OR IGNORE INTO companies(domain,name) VALUES(?,?)', (domain,company))
            if not c.execute('SELECT 1 FROM users WHERE email=?',(email,)).fetchone():
                cid = c.execute('SELECT id FROM companies WHERE domain=?',(domain,)).fetchone()['id']
                password = 'Admin@123' if role=='admin' else 'Employee@123'
                c.execute('INSERT INTO users(company_id,email,role,password_hash) VALUES(?,?,?,?)',
                          (cid,email,role,generate_password_hash(password)))

    def audit(c, company, event, detail):
        c.execute('INSERT INTO audit(company_id,actor,event,detail) VALUES(?,?,?,?)',
                  (company,g.user['email'],event,detail))

    def new_key(c, user, created):
        version = c.execute('SELECT coalesce(max(version),0)+1 FROM keys WHERE user_id=?',(user['id'],)).fetchone()[0]
        handle = secrets.token_hex(24)
        path = vault / handle
        with open(os.open(path, os.O_WRONLY | os.O_EXCL | os.O_CREAT, 0o600),'wb') as f:
            created.append(path)
            f.write(AESGCM.generate_key(bit_length=256))
        c.execute('INSERT INTO keys(company_id,user_id,version,handle,status) VALUES(?,?,?,?,?)',
                  (user['company_id'],user['id'],version,handle,'active'))
        audit(c,user['company_id'],'KEY_CREATED',f"{user['email']} · version {version}")

    def crypto(k):
        return AESGCM((vault/k['handle']).read_bytes())

    def aad(f):
        return json.dumps([f['company_id'],f['user_id'],f['id'],f['name']],ensure_ascii=False).encode()

    @app.before_request
    def load_identity():
        g.user = None
        if session.get('uid'):
            with db() as c:
                g.user = c.execute('SELECT u.id,u.email,u.role,u.company_id,c.domain FROM users u JOIN companies c ON c.id=u.company_id WHERE u.id=?',
                                   (session['uid'],)).fetchone()
        session.setdefault('csrf',secrets.token_hex(24))
        if request.method == 'POST' and not secrets.compare_digest(session['csrf'],request.form.get('csrf','')):
            abort(400)

    @app.after_request
    def headers(response):
        response.headers.update({'Cache-Control':'no-store','X-Content-Type-Options':'nosniff',
            'Content-Security-Policy':"default-src 'self'; object-src 'none'; frame-ancestors 'none'; form-action 'self'; base-uri 'none'"})
        return response

    def role(required):
        def wrap(fn):
            @wraps(fn)
            def checked(*args,**kwargs):
                if not g.user: return redirect(url_for('login'))
                if g.user['role']!=required: abort(403)
                return fn(*args,**kwargs)
            return checked
        return wrap

    @app.route('/',methods=['GET','POST'])
    def login():
        if request.method=='POST':
            domain = request.form.get('domain','').strip().lower()
            email = request.form.get('email','').strip().lower()
            with db() as c:
                user = c.execute('SELECT u.* FROM users u JOIN companies c ON c.id=u.company_id WHERE u.email=? AND c.domain=?',(email,domain)).fetchone()
            if user and email.rpartition('@')[2]==domain and check_password_hash(user['password_hash'],request.form.get('password','')):
                session.clear()
                session['uid']=user['id']
                return redirect(url_for(user['role']))
            flash('Company domain, email, or password is incorrect.','bad')
        elif g.user:
            return redirect(url_for(g.user['role']))
        return render_template('signin.html')

    @app.post('/logout')
    def logout():
        session.clear()
        return redirect(url_for('login'))

    lab_targets = [(domain, email, email.split('@')[0].title())
                   for domain, _, email, role in DEMO_USERS if role=='employee']
    lab_signer = URLSafeTimedSerializer(app.secret_key, salt='keyguard-lab-target')

    @app.get('/lab')
    def lab():
        targets=[]
        with db() as c:
            for domain,email,name in lab_targets:
                key=c.execute("""SELECT k.id,k.version,k.status FROM keys k JOIN users u ON u.id=k.user_id
                    JOIN companies d ON d.id=k.company_id WHERE u.email=? AND d.domain=? AND u.role='employee'
                    ORDER BY k.version DESC LIMIT 1""",(email,domain)).fetchone()
                token=lab_signer.dumps([email,key['id'],session['csrf']]) if key and key['status']=='active' else ''
                targets.append(dict(name=name,domain=domain,key=key,token=token))
        return render_template('lab.html',targets=targets)

    @app.post('/lab/simulate-theft')
    def simulate_theft():
        try:
            email,kid,csrf=lab_signer.loads(request.form.get('target',''),max_age=3600)
        except BadSignature:
            return {'message':'Select an employee with an active key and reopen the lab if needed.'},409
        target=next((t for t in lab_targets if t[1]==email),None)
        if not target or csrf!=session['csrf']:
            return {'message':'This demo target is no longer available. Refresh the lab.'},409
        domain,_,name=target
        with db(write=True) as c:
            key=c.execute("""SELECT k.* FROM keys k JOIN users u ON u.id=k.user_id
                JOIN companies d ON d.id=k.company_id WHERE k.id=? AND u.email=? AND d.domain=? AND u.role='employee'""",
                          (kid,email,domain)).fetchone()
            if not key or key['status'] not in ('active','compromised'):
                return {'message':f'Assign or recover {name}’s key in Admin, then reopen the lab.'},409
            if key['status']=='active':
                c.execute("UPDATE keys SET status='compromised' WHERE id=?",(key['id'],))
                c.execute('INSERT INTO incidents(key_id) VALUES(?)',(key['id'],))
                c.execute('INSERT INTO audit(company_id,actor,event,detail) VALUES(?,?,?,?)',
                          (key['company_id'],'Incident Lab','COMPROMISE_REPORTED',f"{email} · version {key['version']} · simulated demo theft"))
        return {'message':f"Demo key released. Admin and {name} were notified about workspace key v{key['version']}."}

    @app.get('/incident-notice')
    def incident_notice():
        if not g.user: abort(403)
        return {'message':notice()}

    def notice():
        identity=g.user
        with db() as c:
            if identity['role']=='admin':
                count=c.execute("SELECT count(*) FROM incidents WHERE status='open'").fetchone()[0]
                return f'{count} open key incident(s). Review the affected keys and revoke or rotate them.' if count else ''
            incident=c.execute("""SELECT i.status,k.version,k.status key_status FROM incidents i JOIN keys k ON k.id=i.key_id
                                    WHERE k.company_id=? AND k.user_id=? ORDER BY i.id DESC LIMIT 1""",
                               (identity['company_id'],identity['id'])).fetchone()
            if not incident: return ''
            if incident['status']=='recovered':
                return f"Recovery complete: files affected by key v{incident['version']} were recovered with a replacement key."
            state='was reported compromised' if incident['key_status']=='compromised' else 'was revoked'
            return f"Your key v{incident['version']} {state}. Affected files are blocked until Admin rotates the key and recovers them."


    @app.get('/employee')
    @role('employee')
    def employee():
        with db() as c:
            identity=(g.user['company_id'],g.user['id'])
            files=c.execute('''SELECT f.id,f.name,f.size,f.nonce,f.created_at,k.version,k.status
                FROM files f JOIN keys k ON k.id=f.key_id WHERE f.company_id=? AND f.user_id=? ORDER BY f.created_at DESC''',identity).fetchall()
            active=c.execute("SELECT version FROM keys WHERE company_id=? AND user_id=? AND status='active'",identity).fetchone()
        return render_template('employee.html',files=files,active=active,incident_notice=notice())

    @app.post('/employee/encrypt')
    @role('employee')
    def encrypt():
        upload=request.files.get('file')
        if not upload or not upload.filename:
            flash('Choose a file.','bad')
            return redirect(url_for('employee'))
        data=upload.read(LIMIT+1)
        if len(data)>LIMIT: abort(413)
        f=dict(id=secrets.token_hex(16),name=secure_filename(upload.filename) or 'file.bin',
               company_id=g.user['company_id'],user_id=g.user['id'])
        with db(write=True) as c:
            k=c.execute("SELECT * FROM keys WHERE company_id=? AND user_id=? AND status='active'",(f['company_id'],f['user_id'])).fetchone()
            if not k:
                flash('No active key is assigned to you. Ask the platform admin.','bad')
                return redirect(url_for('employee'))
            nonce=secrets.token_bytes(12)
            try:
                cipher=crypto(k).encrypt(nonce,data,aad(f))
            except (OSError,ValueError):
                flash('Your assigned key is unavailable. Contact the platform admin.','bad')
                return redirect(url_for('employee'))
            c.execute('INSERT INTO files(id,company_id,user_id,key_id,name,nonce,ciphertext,size) VALUES(?,?,?,?,?,?,?,?)',
                      (f['id'],f['company_id'],f['user_id'],k['id'],f['name'],nonce,cipher,len(data)))
            audit(c,f['company_id'],'FILE_ENCRYPTED',f"{f['name']} · version {k['version']}")
        flash('File encrypted with your assigned key.','ok')
        return redirect(url_for('employee'))

    @app.post('/employee/files/<fid>/<operation>')
    @role('employee')
    def file_action(fid,operation):
        with db(write=True) as c:
            f=c.execute('''SELECT f.*, k.handle,k.status,k.version FROM files f JOIN keys k ON k.id=f.key_id
                WHERE f.id=? AND f.company_id=? AND f.user_id=?''',(fid,g.user['company_id'],g.user['id'])).fetchone()
            if not f or operation not in ('verify','download'): abort(404)
            if f['status']!='active':
                flash('This key is blocked. An admin must recover the file first.','bad')
                return redirect(url_for('employee'))
            try:
                data=crypto(f).decrypt(f['nonce'],f['ciphertext'],aad(f))
            except (InvalidTag,OSError,ValueError):
                audit(c,f['company_id'],'FILE_AUTH_FAILED',f['name'])
                flash('Authentication failed. No plaintext was released.','bad')
                return redirect(url_for('employee'))
            audit(c,f['company_id'],'FILE_VERIFIED' if operation=='verify' else 'FILE_DOWNLOADED',f['name'])
        if operation=='verify':
            flash('Authentication passed: ciphertext and file context verified.','ok')
            return redirect(url_for('employee'))
        return send_file(io.BytesIO(data),as_attachment=True,download_name=f['name'],mimetype='application/octet-stream')

    @app.get('/admin')
    @role('admin')
    def admin():
        with db() as c:
            companies=c.execute("""SELECT c.domain,c.name,count(k.id) total,
                count(CASE WHEN k.status='active' THEN 1 END) active,
                count(CASE WHEN k.status='compromised' THEN 1 END) compromised,
                count(CASE WHEN k.status='revoked' THEN 1 END) revoked
                FROM companies c LEFT JOIN keys k ON k.company_id=c.id
                WHERE EXISTS(SELECT 1 FROM users u WHERE u.company_id=c.id AND u.role='employee')
                GROUP BY c.id ORDER BY c.domain""").fetchall()
            employees=c.execute("""SELECT u.id,u.email,c.domain,k.id key_id,k.version,k.status FROM users u
                JOIN companies c ON c.id=u.company_id LEFT JOIN keys k ON k.user_id=u.id AND
                k.version=(SELECT max(version) FROM keys WHERE user_id=u.id)
                WHERE u.role='employee' ORDER BY c.domain,u.email""").fetchall()
            incidents=c.execute("""SELECT i.id,i.status,i.created_at,k.version,u.email,c.domain FROM incidents i
                JOIN keys k ON k.id=i.key_id JOIN users u ON u.id=k.user_id JOIN companies c ON c.id=k.company_id
                ORDER BY i.id DESC""").fetchall()
            events=c.execute('SELECT a.created_at,c.domain,a.actor,a.event,a.detail FROM audit a JOIN companies c ON c.id=a.company_id ORDER BY a.id DESC LIMIT 100').fetchall()
        return render_template('admin.html',companies=companies,employees=employees,incidents=incidents,events=events,incident_notice=notice())

    @app.post('/admin/audit.csv')
    @role('admin')
    def audit_export():
        output=io.StringIO()
        writer=csv.writer(output)
        writer.writerow(['Time (UTC)','Company','Actor','Event','Detail'])
        with db() as c:
            for row in c.execute('SELECT a.created_at,c.domain,a.actor,a.event,a.detail FROM audit a JOIN companies c ON c.id=a.company_id ORDER BY a.id'):
                writer.writerow([("'" + value if value.startswith(('=','+','-','@',chr(9),chr(13))) else value) for value in row])
        return send_file(io.BytesIO(output.getvalue().encode('utf-8-sig')),as_attachment=True,download_name='keyguard-audit.csv',mimetype='text/csv')

    @app.post('/admin/employees/<int:uid>/<operation>')
    @role('admin')
    def lifecycle(uid,operation):
        created=[]
        try:
            with db(write=True) as c:
                u=c.execute("SELECT id,email,company_id FROM users WHERE id=? AND role='employee'",(uid,)).fetchone()
                if not u: abort(404)
                k=c.execute('SELECT * FROM keys WHERE user_id=? AND company_id=? ORDER BY version DESC LIMIT 1',(uid,u['company_id'])).fetchone()
                if operation=='assign' and not k:
                    new_key(c,u,created)
                    message='Assigned a unique employee key.'
                elif operation=='revoke' and k and k['status']=='compromised':
                    c.execute("UPDATE keys SET status='revoked' WHERE id=?",(k['id'],))
                    audit(c,u['company_id'],'KEY_REVOKED',u['email'])
                    message='Key revoked. Rotate and recover to restore file access.'
                elif operation=='recover' and k and k['status']=='revoked':
                    files=c.execute('SELECT id FROM files WHERE key_id=? AND company_id=? AND user_id=?',(k['id'],u['company_id'],uid)).fetchall()
                    new_key(c,u,created)
                    new=c.execute("SELECT * FROM keys WHERE user_id=? AND status='active'",(uid,)).fetchone()
                    for entry in files:
                        f=c.execute('SELECT * FROM files WHERE id=?',(entry['id'],)).fetchone()
                        plain=crypto(k).decrypt(f['nonce'],f['ciphertext'],aad(f))
                        nonce=secrets.token_bytes(12)
                        engine=crypto(new)
                        ciphertext=engine.encrypt(nonce,plain,aad(f))
                        if engine.decrypt(nonce,ciphertext,aad(f))!=plain: raise InvalidTag
                        c.execute('UPDATE files SET key_id=?,nonce=?,ciphertext=? WHERE id=?',(new['id'],nonce,ciphertext,f['id']))
                        audit(c,u['company_id'],'FILE_RECOVERED',f"{f['name']} · version {k['version']} → {new['version']}")
                    c.execute("UPDATE incidents SET status='recovered' WHERE key_id=?",(k['id'],))
                    audit(c,u['company_id'],'RECOVERY_COMPLETE',f"{u['email']} · {len(files)} files")
                    message=f"Rotated to version {new['version']}; {len(files)} files verified and recovered."
                else:
                    abort(409)
        except Exception as exc:
            for path in created: path.unlink(missing_ok=True)
            if not isinstance(exc,(InvalidTag,OSError,ValueError)): raise
            with db(write=True) as c:
                audit(c,u['company_id'],'LIFECYCLE_FAILED',f"{u['email']} · {operation} · key unavailable or authentication failed")
            flash('Operation failed. No key or file changes were committed.','bad')
            return redirect(url_for('admin'))
        flash(message,'ok')
        return redirect(url_for('admin'))

    @app.errorhandler(400)
    @app.errorhandler(403)
    @app.errorhandler(404)
    @app.errorhandler(409)
    @app.errorhandler(413)
    def error(exc):
        return render_template('error.html',code=exc.code),exc.code

    return app


if __name__=='__main__':
    create_app().run(host='127.0.0.1',port=int(os.environ.get('KEYGUARD_PORT','5050')),debug=False)
