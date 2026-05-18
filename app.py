from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session, abort
from flask_compress import Compress
from werkzeug.security import generate_password_hash, check_password_hash
import os
import re
import secrets
import sqlite3
from datetime import datetime, date

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
# Compression gzip des réponses HTML/JSON
app.config['COMPRESS_MIMETYPES'] = ['text/html','text/css','application/json','application/javascript']
app.config['COMPRESS_LEVEL'] = 6
app.config['COMPRESS_MIN_SIZE'] = 500
Compress(app)

DATABASE_URL = os.environ.get('DATABASE_URL', '')
DB_PATH = os.path.join(os.path.dirname(__file__), 'gafarou.db')
USE_PG = bool(DATABASE_URL)

_pg_pool = None   # pool de connexions PostgreSQL (initialisé une fois par worker)

if USE_PG:
    import psycopg2
    import psycopg2.extras
    from psycopg2 import pool as _pg_pool_lib


# ───────────── SÉCURITÉ ─────────────

def clean(val, max_len=300):
    """Nettoie et tronque les entrées utilisateur."""
    return str(val).strip()[:max_len] if val else ''


@app.before_request
def csrf_protect():
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(32)
    if request.method == 'POST' and not request.path.startswith('/api/'):
        token = request.form.get('csrf_token', '')
        stored = session.get('csrf_token', '')
        if not token or not stored or not secrets.compare_digest(token, stored):
            abort(403)


# Endpoints publics (pas de login requis)
_PUBLIC_ENDPOINTS = frozenset({
    'login', 'logout', 'pwa_manifest', 'service_worker', 'offline_page', 'ping', 'static'
})


@app.before_request
def require_login():
    ep = request.endpoint
    if ep is None or ep in _PUBLIC_ENDPOINTS:
        return
    if 'user_id' not in session:
        return redirect(url_for('login', next=request.path))


@app.after_request
def set_security_headers(resp):
    resp.headers['X-Frame-Options'] = 'SAMEORIGIN'
    resp.headers['X-Content-Type-Options'] = 'nosniff'
    resp.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    resp.headers['X-XSS-Protection'] = '1; mode=block'
    # Cache agressif pour les fichiers statiques (logo, sw.js, manifest)
    if request.path.startswith('/static/') and request.path != '/static/sw.js':
        resp.headers['Cache-Control'] = 'public, max-age=31536000, immutable'
    return resp


@app.context_processor
def inject_globals():
    alertes = []
    # Éviter une requête DB inutile sur les appels AJAX/API/static
    skip = (request.path.startswith(('/api/', '/static/', '/ping', '/sw.js', '/manifest.json', '/offline', '/login', '/logout'))
           or 'user_id' not in session)
    if not skip:
        try:
            conn = get_db()
            rows = conn.execute("""
                SELECT v.id, v.numero, v.date_vente,
                       c.nom || ' ' || COALESCE(c.prenom,'') AS client_nom,
                       c.telephone,
                       (v.montant_total - v.montant_paye) AS reste,
                       (CURRENT_DATE - v.date_vente::date)::integer AS jours
                FROM ventes v
                JOIN clients c ON c.id = v.client_id
                WHERE v.statut = 'en_cours'
                ORDER BY reste DESC
                LIMIT 20
            """ if USE_PG else """
                SELECT v.id, v.numero, v.date_vente,
                       c.nom || ' ' || COALESCE(c.prenom,'') AS client_nom,
                       c.telephone,
                       (v.montant_total - v.montant_paye) AS reste,
                       CAST(julianday('now') - julianday(v.date_vente) AS INTEGER) AS jours
                FROM ventes v
                JOIN clients c ON c.id = v.client_id
                WHERE v.statut = 'en_cours'
                ORDER BY reste DESC
                LIMIT 20
            """).fetchall()
            conn.close()
            for r in rows:
                niveau = 'danger' if r['jours'] >= 30 else ('warning' if r['jours'] >= 7 else 'info')
                alertes.append({
                    'id': r['id'],
                    'numero': r['numero'],
                    'client': r['client_nom'].strip(),
                    'telephone': r['telephone'] or '',
                    'reste': r['reste'],
                    'jours': r['jours'],
                    'niveau': niveau,
                })
        except Exception:
            pass
    return {
        'csrf_token': session.get('csrf_token', ''),
        'alertes': alertes,
        'nb_alertes': len(alertes),
        'current_username': session.get('username', ''),
    }


@app.errorhandler(403)
def forbidden(_):
    return ('<h2 style="font-family:sans-serif;color:#b71c1c;">'
            '403 — Accès refusé (token invalide)</h2>'
            '<a href="/">← Retour</a>'), 403

# ───────────────────────────────── BASE DE DONNÉES ─────────────────────────────────

# ── Wrappers SQLite ──
class _SqliteCur:
    def __init__(self, cur):
        self._cur = cur
        self._rowid = cur.lastrowid

    def fetchone(self):
        r = self._cur.fetchone()
        return dict(r) if r else None

    def fetchall(self):
        return [dict(r) for r in self._cur.fetchall()]

    @property
    def lastrowid(self):
        return self._rowid


class _SqliteConn:
    def __init__(self, conn):
        self._c = conn

    def execute(self, sql, params=None):
        # SQLite ne supporte pas RETURNING — on le retire
        sql = re.sub(r'\s*RETURNING\s+id\s*$', '', sql.strip(), flags=re.IGNORECASE)
        cur = self._c.execute(sql, params if params is not None else ())
        return _SqliteCur(cur)

    def commit(self):
        self._c.commit()

    def close(self):
        self._c.close()


# ── Wrappers PostgreSQL ──
class _PgCur:
    def __init__(self, cur):
        self._cur = cur

    def fetchone(self):
        return self._cur.fetchone()

    def fetchall(self):
        return self._cur.fetchall()

    @property
    def lastrowid(self):
        row = self._cur.fetchone()
        return row['id'] if row else None


class _PgConn:
    def __init__(self, conn):
        self._c = conn

    def execute(self, sql, params=None):
        cur = self._c.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute(sql.replace('?', '%s'), params if params is not None else ())
        return _PgCur(cur)

    def commit(self):
        self._c.commit()

    def close(self):
        # Remettre la connexion dans le pool au lieu de la fermer
        global _pg_pool
        if _pg_pool:
            try:
                self._c.rollback()   # annule toute transaction pendante avant retour au pool
            except Exception:
                pass
            _pg_pool.putconn(self._c)
        else:
            self._c.close()


def _get_pg_pool():
    """Retourne le pool PostgreSQL, l'initialise si nécessaire (lazy)."""
    global _pg_pool
    if _pg_pool is None:
        _pg_pool = _pg_pool_lib.SimpleConnectionPool(1, 8, DATABASE_URL)
    return _pg_pool


def get_db():
    if USE_PG:
        conn = _get_pg_pool().getconn()
        return _PgConn(conn)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA cache_size = -8000")
    return _SqliteConn(conn)


def init_db():
    if USE_PG:
        conn = psycopg2.connect(DATABASE_URL)
        conn.autocommit = True
        cur = conn.cursor()
        ddl = [
            """CREATE TABLE IF NOT EXISTS clients (
                id               SERIAL PRIMARY KEY,
                nom              TEXT NOT NULL,
                prenom           TEXT DEFAULT '',
                telephone        TEXT DEFAULT '',
                adresse          TEXT DEFAULT '',
                date_inscription DATE DEFAULT CURRENT_DATE
            )""",
            """CREATE TABLE IF NOT EXISTS produits (
                id            SERIAL PRIMARY KEY,
                nom           TEXT NOT NULL,
                categorie     TEXT DEFAULT '',
                prix_unitaire DOUBLE PRECISION NOT NULL DEFAULT 0,
                description   TEXT DEFAULT '',
                actif         SMALLINT DEFAULT 1
            )""",
            """CREATE TABLE IF NOT EXISTS ventes (
                id            SERIAL PRIMARY KEY,
                numero        TEXT UNIQUE NOT NULL,
                client_id     INTEGER NOT NULL REFERENCES clients(id),
                date_vente    DATE NOT NULL,
                montant_total DOUBLE PRECISION NOT NULL DEFAULT 0,
                montant_paye  DOUBLE PRECISION NOT NULL DEFAULT 0,
                statut        TEXT DEFAULT 'en_cours',
                notes         TEXT DEFAULT '',
                date_creation TIMESTAMPTZ DEFAULT NOW()
            )""",
            """CREATE TABLE IF NOT EXISTS vente_items (
                id            SERIAL PRIMARY KEY,
                vente_id      INTEGER NOT NULL REFERENCES ventes(id),
                produit_id    INTEGER,
                produit_nom   TEXT NOT NULL,
                quantite      INTEGER NOT NULL DEFAULT 1,
                prix_unitaire DOUBLE PRECISION NOT NULL DEFAULT 0
            )""",
            """CREATE TABLE IF NOT EXISTS paiements (
                id             SERIAL PRIMARY KEY,
                vente_id       INTEGER NOT NULL REFERENCES ventes(id),
                date_paiement  DATE NOT NULL,
                montant        DOUBLE PRECISION NOT NULL,
                notes          TEXT DEFAULT ''
            )""",
            """CREATE TABLE IF NOT EXISTS parametres (
                id                  INTEGER PRIMARY KEY,
                nom_boutique        TEXT DEFAULT 'Ma Boutique',
                adresse_boutique    TEXT DEFAULT '',
                telephone_boutique  TEXT DEFAULT '',
                devise              TEXT DEFAULT 'FCFA',
                proprietaire        TEXT DEFAULT ''
            )""",
            """INSERT INTO parametres (id, nom_boutique, devise)
               VALUES (1, 'ART Gestion Crédit', 'FCFA')
               ON CONFLICT DO NOTHING""",
            # Index pour accélérer les requêtes fréquentes
            "CREATE INDEX IF NOT EXISTS idx_ventes_statut ON ventes(statut)",
            "CREATE INDEX IF NOT EXISTS idx_ventes_client ON ventes(client_id)",
            "CREATE INDEX IF NOT EXISTS idx_ventes_creation ON ventes(date_creation DESC)",
            "CREATE INDEX IF NOT EXISTS idx_items_vente ON vente_items(vente_id)",
            "CREATE INDEX IF NOT EXISTS idx_paiements_vente ON paiements(vente_id)",
            "CREATE INDEX IF NOT EXISTS idx_clients_nom ON clients(nom)",
            """CREATE TABLE IF NOT EXISTS users (
                id       SERIAL PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL
            )""",
        ]
        for stmt in ddl:
            cur.execute(stmt)
        cur.close()
        conn.close()
    else:
        # SQLite — création locale
        conn = sqlite3.connect(DB_PATH)
        conn.executescript('''
            CREATE TABLE IF NOT EXISTS clients (
                id               INTEGER PRIMARY KEY AUTOINCREMENT,
                nom              TEXT NOT NULL,
                prenom           TEXT DEFAULT '',
                telephone        TEXT DEFAULT '',
                adresse          TEXT DEFAULT '',
                date_inscription TEXT DEFAULT (date('now'))
            );
            CREATE TABLE IF NOT EXISTS produits (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                nom           TEXT NOT NULL,
                categorie     TEXT DEFAULT '',
                prix_unitaire REAL NOT NULL DEFAULT 0,
                description   TEXT DEFAULT '',
                actif         INTEGER DEFAULT 1
            );
            CREATE TABLE IF NOT EXISTS ventes (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                numero        TEXT UNIQUE NOT NULL,
                client_id     INTEGER NOT NULL,
                date_vente    TEXT NOT NULL,
                montant_total REAL NOT NULL DEFAULT 0,
                montant_paye  REAL NOT NULL DEFAULT 0,
                statut        TEXT DEFAULT 'en_cours',
                notes         TEXT DEFAULT '',
                date_creation TEXT DEFAULT (datetime('now')),
                FOREIGN KEY (client_id) REFERENCES clients(id)
            );
            CREATE TABLE IF NOT EXISTS vente_items (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                vente_id      INTEGER NOT NULL,
                produit_id    INTEGER,
                produit_nom   TEXT NOT NULL,
                quantite      INTEGER NOT NULL DEFAULT 1,
                prix_unitaire REAL NOT NULL DEFAULT 0,
                FOREIGN KEY (vente_id) REFERENCES ventes(id)
            );
            CREATE TABLE IF NOT EXISTS paiements (
                id             INTEGER PRIMARY KEY AUTOINCREMENT,
                vente_id       INTEGER NOT NULL,
                date_paiement  TEXT NOT NULL,
                montant        REAL NOT NULL,
                notes          TEXT DEFAULT '',
                FOREIGN KEY (vente_id) REFERENCES ventes(id)
            );
            CREATE TABLE IF NOT EXISTS parametres (
                id                  INTEGER PRIMARY KEY CHECK (id = 1),
                nom_boutique        TEXT DEFAULT 'Ma Boutique',
                adresse_boutique    TEXT DEFAULT '',
                telephone_boutique  TEXT DEFAULT '',
                devise              TEXT DEFAULT 'FCFA',
                proprietaire        TEXT DEFAULT ''
            );
            INSERT OR IGNORE INTO parametres (id, nom_boutique, devise)
            VALUES (1, 'ART Gestion Crédit', 'FCFA');
            CREATE INDEX IF NOT EXISTS idx_ventes_statut ON ventes(statut);
            CREATE INDEX IF NOT EXISTS idx_ventes_client ON ventes(client_id);
            CREATE INDEX IF NOT EXISTS idx_ventes_creation ON ventes(date_creation);
            CREATE INDEX IF NOT EXISTS idx_items_vente ON vente_items(vente_id);
            CREATE INDEX IF NOT EXISTS idx_paiements_vente ON paiements(vente_id);
            CREATE INDEX IF NOT EXISTS idx_clients_nom ON clients(nom);
            CREATE TABLE IF NOT EXISTS users (
                id       INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL
            );
        ''')
        conn.commit()
        conn.close()


def seed_admin():
    """Crée l'utilisateur admin par défaut si aucun utilisateur n'existe."""
    try:
        conn = get_db()
        n = conn.execute('SELECT COUNT(*) AS n FROM users').fetchone()['n']
        if n == 0:
            pw = generate_password_hash('admin')
            conn.execute('INSERT INTO users (username, password) VALUES (?,?)', ('admin', pw))
            conn.commit()
        conn.close()
    except Exception as e:
        print(f'[seed_admin] Erreur: {e}')


def get_params():
    conn = get_db()
    p = conn.execute('SELECT * FROM parametres WHERE id = 1').fetchone()
    conn.close()
    return p


def gen_numero():
    now = datetime.now()
    conn = get_db()
    count = conn.execute('SELECT COUNT(*) AS n FROM ventes').fetchone()['n'] + 1
    conn.close()
    return f"CR{now.strftime('%Y%m')}{count:04d}"


# ───────────────────────────────── FILTRES JINJA ─────────────────────────────────

@app.template_filter('fmt_date')
def fmt_date(d):
    if not d:
        return ''
    try:
        return datetime.strptime(str(d)[:10], '%Y-%m-%d').strftime('%d/%m/%Y')
    except Exception:
        return str(d)


@app.template_filter('fmt_money')
def fmt_money(amount):
    if amount is None:
        return '0'
    return f"{float(amount):,.0f}".replace(',', ' ')


# ───────────────────────────────── AUTHENTIFICATION ─────────────────────────────────

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    error = None
    if request.method == 'POST':
        username = clean(request.form.get('username', ''), 100)
        password = request.form.get('password', '')
        conn = get_db()
        user = conn.execute('SELECT * FROM users WHERE username=?', (username,)).fetchone()
        conn.close()
        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            next_url = request.form.get('next') or request.args.get('next') or url_for('dashboard')
            # Sécurité : ne rediriger que vers des chemins relatifs
            if next_url.startswith('/') and not next_url.startswith('//'):
                return redirect(next_url)
            return redirect(url_for('dashboard'))
        error = 'Nom d\'utilisateur ou mot de passe incorrect.'
    params = get_params()
    next_url = request.args.get('next', '')
    return render_template('login.html', params=params, error=error, next_url=next_url)


@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('username', None)
    flash('Vous avez été déconnecté.', 'info')
    return redirect(url_for('login'))


# ───────────────────────────────── DASHBOARD ─────────────────────────────────

@app.route('/')
def dashboard():
    conn = get_db()
    stats = {
        'credits_en_cours': conn.execute(
            "SELECT COUNT(*) AS n FROM ventes WHERE statut='en_cours'").fetchone()['n'],
        'montant_total_du': conn.execute(
            "SELECT COALESCE(SUM(montant_total - montant_paye),0) AS n FROM ventes WHERE statut='en_cours'"
        ).fetchone()['n'],
        'credits_soldes_mois': conn.execute(
            "SELECT COUNT(*) AS n FROM ventes WHERE statut='solde' "
            "AND to_char(date_creation, 'YYYY-MM') = to_char(NOW(), 'YYYY-MM')"
            if USE_PG else
            "SELECT COUNT(*) AS n FROM ventes WHERE statut='solde' "
            "AND strftime('%Y-%m', date_creation)=strftime('%Y-%m','now')"
        ).fetchone()['n'],
        'total_clients': conn.execute("SELECT COUNT(*) AS n FROM clients").fetchone()['n'],
    }
    recent = conn.execute('''
        SELECT v.*, c.nom||' '||c.prenom AS client_nom, c.telephone
        FROM ventes v JOIN clients c ON v.client_id=c.id
        ORDER BY v.date_creation DESC LIMIT 8
    ''').fetchall()
    top_debiteurs = conn.execute('''
        SELECT c.id, c.nom||' '||c.prenom AS client_nom, c.telephone,
               COUNT(v.id) AS nb_credits,
               SUM(v.montant_total - v.montant_paye) AS total_du
        FROM clients c JOIN ventes v ON c.id=v.client_id
        WHERE v.statut='en_cours'
        GROUP BY c.id ORDER BY total_du DESC LIMIT 6
    ''').fetchall()
    params = get_params()
    conn.close()
    return render_template('dashboard.html', stats=stats, recent=recent,
                           top_debiteurs=top_debiteurs, params=params)


# ───────────────────────────────── CLIENTS ─────────────────────────────────

@app.route('/clients')
def clients():
    conn = get_db()
    q = request.args.get('q', '').strip()
    if q:
        rows = conn.execute('''
            SELECT c.*,
                   COUNT(v.id) AS nb_credits,
                   COALESCE(SUM(CASE WHEN v.statut='en_cours'
                       THEN v.montant_total - v.montant_paye ELSE 0 END), 0) AS total_du
            FROM clients c LEFT JOIN ventes v ON c.id=v.client_id
            WHERE c.nom LIKE ? OR c.prenom LIKE ? OR c.telephone LIKE ?
            GROUP BY c.id ORDER BY c.nom
        ''', (f'%{q}%', f'%{q}%', f'%{q}%')).fetchall()
    else:
        rows = conn.execute('''
            SELECT c.*,
                   COUNT(v.id) AS nb_credits,
                   COALESCE(SUM(CASE WHEN v.statut='en_cours'
                       THEN v.montant_total - v.montant_paye ELSE 0 END), 0) AS total_du
            FROM clients c LEFT JOIN ventes v ON c.id=v.client_id
            GROUP BY c.id ORDER BY c.nom
        ''').fetchall()
    params = get_params()
    conn.close()
    return render_template('clients.html', clients=rows, search=q, params=params)


@app.route('/clients/ajouter', methods=['GET', 'POST'])
def ajouter_client():
    if request.method == 'POST':
        nom = clean(request.form.get('nom', ''), 100)
        prenom = clean(request.form.get('prenom', ''), 100)
        telephone = clean(request.form.get('telephone', ''), 30)
        adresse = clean(request.form.get('adresse', ''), 250)
        if not nom:
            flash('Le nom est obligatoire.', 'danger')
            return render_template('client_form.html', client=None, params=get_params())
        conn = get_db()
        conn.execute('INSERT INTO clients (nom,prenom,telephone,adresse) VALUES (?,?,?,?)',
                     (nom, prenom, telephone, adresse))
        conn.commit()
        conn.close()
        flash(f'Client {nom} {prenom} ajouté avec succès!', 'success')
        return redirect(url_for('clients'))
    return render_template('client_form.html', client=None, params=get_params())


@app.route('/clients/<int:cid>/modifier', methods=['GET', 'POST'])
def modifier_client(cid):
    conn = get_db()
    client = conn.execute('SELECT * FROM clients WHERE id=?', (cid,)).fetchone()
    if not client:
        conn.close()
        flash('Client introuvable.', 'danger')
        return redirect(url_for('clients'))
    if request.method == 'POST':
        nom = clean(request.form.get('nom', ''), 100)
        prenom = clean(request.form.get('prenom', ''), 100)
        telephone = clean(request.form.get('telephone', ''), 30)
        adresse = clean(request.form.get('adresse', ''), 250)
        if not nom:
            flash('Le nom est obligatoire.', 'danger')
            return render_template('client_form.html', client=client, params=get_params())
        conn.execute('UPDATE clients SET nom=?,prenom=?,telephone=?,adresse=? WHERE id=?',
                     (nom, prenom, telephone, adresse, cid))
        conn.commit()
        conn.close()
        flash('Client modifié avec succès!', 'success')
        return redirect(url_for('detail_client', cid=cid))
    params = get_params()
    conn.close()
    return render_template('client_form.html', client=client, params=params)


@app.route('/clients/<int:cid>')
def detail_client(cid):
    conn = get_db()
    client = conn.execute('SELECT * FROM clients WHERE id=?', (cid,)).fetchone()
    if not client:
        conn.close()
        flash('Client introuvable.', 'danger')
        return redirect(url_for('clients'))
    ventes_list = conn.execute(
        'SELECT * FROM ventes WHERE client_id=? ORDER BY date_creation DESC', (cid,)).fetchall()
    stats = {
        'total': len(ventes_list),
        'en_cours': sum(1 for v in ventes_list if v['statut'] == 'en_cours'),
        'soldes':   sum(1 for v in ventes_list if v['statut'] == 'solde'),
        'total_du': sum((v['montant_total'] - v['montant_paye'])
                        for v in ventes_list if v['statut'] == 'en_cours'),
        'total_achats': sum(v['montant_total'] for v in ventes_list),
    }
    params = get_params()
    conn.close()
    return render_template('detail_client.html', client=client, ventes=ventes_list,
                           stats=stats, params=params)


# ───────────────────────────────── PRODUITS ─────────────────────────────────

@app.route('/produits')
def produits():
    conn = get_db()
    q = request.args.get('q', '').strip()
    if q:
        rows = conn.execute(
            "SELECT * FROM produits WHERE actif=1 AND (nom LIKE ? OR categorie LIKE ?) ORDER BY categorie,nom",
            (f'%{q}%', f'%{q}%')).fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM produits WHERE actif=1 ORDER BY categorie,nom").fetchall()
    params = get_params()
    conn.close()
    return render_template('produits.html', produits=rows, search=q, params=params)


@app.route('/produits/ajouter', methods=['GET', 'POST'])
def ajouter_produit():
    if request.method == 'POST':
        nom = clean(request.form.get('nom', ''), 150)
        categorie = clean(request.form.get('categorie', ''), 80)
        prix = clean(request.form.get('prix_unitaire', '0'), 20)
        description = clean(request.form.get('description', ''), 300)
        if not nom:
            flash('Le nom du produit est obligatoire.', 'danger')
            return render_template('produit_form.html', produit=None, params=get_params())
        try:
            prix = float(prix)
        except ValueError:
            prix = 0.0
        conn = get_db()
        conn.execute('INSERT INTO produits (nom,categorie,prix_unitaire,description) VALUES (?,?,?,?)',
                     (nom, categorie, prix, description))
        conn.commit()
        conn.close()
        flash(f'Produit "{nom}" ajouté!', 'success')
        return redirect(url_for('produits'))
    return render_template('produit_form.html', produit=None, params=get_params())


@app.route('/produits/<int:pid>/modifier', methods=['GET', 'POST'])
def modifier_produit(pid):
    conn = get_db()
    produit = conn.execute('SELECT * FROM produits WHERE id=?', (pid,)).fetchone()
    if not produit:
        conn.close()
        flash('Produit introuvable.', 'danger')
        return redirect(url_for('produits'))
    if request.method == 'POST':
        nom = request.form.get('nom', '').strip()
        categorie = request.form.get('categorie', '').strip()
        prix = request.form.get('prix_unitaire', '0').strip()
        description = request.form.get('description', '').strip()
        try:
            prix = float(prix)
        except ValueError:
            prix = 0.0
        conn.execute('UPDATE produits SET nom=?,categorie=?,prix_unitaire=?,description=? WHERE id=?',
                     (nom, categorie, prix, description, pid))
        conn.commit()
        conn.close()
        flash('Produit modifié!', 'success')
        return redirect(url_for('produits'))
    params = get_params()
    conn.close()
    return render_template('produit_form.html', produit=produit, params=params)


@app.route('/produits/<int:pid>/supprimer', methods=['POST'])
def supprimer_produit(pid):
    conn = get_db()
    conn.execute('UPDATE produits SET actif=0 WHERE id=?', (pid,))
    conn.commit()
    conn.close()
    flash('Produit archivé.', 'info')
    return redirect(url_for('produits'))


# ───────────────────────────────── VENTES / CRÉDITS ─────────────────────────────────

@app.route('/ventes')
def ventes():
    conn = get_db()
    statut = request.args.get('statut', 'en_cours')
    q = request.args.get('q', '').strip()
    sql = '''
        SELECT v.*, c.nom||' '||c.prenom AS client_nom, c.telephone
        FROM ventes v JOIN clients c ON v.client_id=c.id WHERE 1=1
    '''
    params_q = []
    if statut and statut != 'tous':
        sql += ' AND v.statut=?'
        params_q.append(statut)
    if q:
        sql += ' AND (c.nom LIKE ? OR c.prenom LIKE ? OR v.numero LIKE ?)'
        params_q += [f'%{q}%', f'%{q}%', f'%{q}%']
    sql += ' ORDER BY v.date_creation DESC'
    rows = conn.execute(sql, params_q).fetchall()
    total_du = sum(v['montant_total'] - v['montant_paye']
                   for v in rows if v['statut'] == 'en_cours')
    params = get_params()
    conn.close()
    return render_template('ventes.html', ventes=rows, statut=statut,
                           search=q, total_du=total_du, params=params)


@app.route('/ventes/nouvelle', methods=['GET', 'POST'])
def nouvelle_vente():
    conn = get_db()
    if request.method == 'POST':
        client_id = request.form.get('client_id', '').strip()
        date_vente = request.form.get('date_vente', date.today().isoformat()).strip()
        notes = request.form.get('notes', '').strip()
        montant_paye_initial = request.form.get('montant_paye_initial', '0').strip()
        try:
            montant_paye_initial = float(montant_paye_initial)
        except ValueError:
            montant_paye_initial = 0.0

        if not client_id:
            flash('Veuillez sélectionner un client.', 'danger')
            clients_list = conn.execute('SELECT * FROM clients ORDER BY nom').fetchall()
            produits_list = conn.execute('SELECT * FROM produits WHERE actif=1 ORDER BY nom').fetchall()
            conn.close()
            return render_template('nouvelle_vente.html', clients=clients_list,
                                   produits=produits_list, params=get_params(),
                                   today=date.today().isoformat())

        # Récupérer les lignes de produits
        produit_noms = request.form.getlist('produit_nom[]')
        produit_ids  = request.form.getlist('produit_id[]')
        quantites    = request.form.getlist('quantite[]')
        prix_list    = request.form.getlist('prix_unitaire[]')

        items = []
        montant_total = 0.0
        for i in range(len(produit_noms)):
            nom_p = produit_noms[i].strip() if i < len(produit_noms) else ''
            if not nom_p:
                continue
            try:
                qty = int(quantites[i]) if i < len(quantites) and quantites[i] else 1
            except ValueError:
                qty = 1
            try:
                prix = float(prix_list[i]) if i < len(prix_list) and prix_list[i] else 0.0
            except ValueError:
                prix = 0.0
            pid = produit_ids[i] if i < len(produit_ids) and produit_ids[i] else None
            try:
                pid = int(pid) if pid else None
            except ValueError:
                pid = None
            montant_total += qty * prix
            items.append((pid, nom_p, qty, prix))

        if not items or montant_total == 0:
            flash('Veuillez ajouter au moins un produit avec un prix.', 'danger')
            clients_list = conn.execute('SELECT * FROM clients ORDER BY nom').fetchall()
            produits_list = conn.execute('SELECT * FROM produits WHERE actif=1 ORDER BY nom').fetchall()
            conn.close()
            return render_template('nouvelle_vente.html', clients=clients_list,
                                   produits=produits_list, params=get_params(),
                                   today=date.today().isoformat())

        montant_paye_initial = min(montant_paye_initial, montant_total)
        statut = 'solde' if montant_paye_initial >= montant_total else 'en_cours'
        numero = gen_numero()

        cur = conn.execute('''
            INSERT INTO ventes (numero, client_id, date_vente, montant_total, montant_paye, statut, notes)
            VALUES (?,?,?,?,?,?,?) RETURNING id
        ''', (numero, int(client_id), date_vente, montant_total, montant_paye_initial, statut, notes))
        vente_id = cur.lastrowid

        for pid, nom_p, qty, prix in items:
            conn.execute('''
                INSERT INTO vente_items (vente_id,produit_id,produit_nom,quantite,prix_unitaire)
                VALUES (?,?,?,?,?)
            ''', (vente_id, pid, nom_p, qty, prix))

        if montant_paye_initial > 0:
            conn.execute('''
                INSERT INTO paiements (vente_id, date_paiement, montant, notes)
                VALUES (?,?,?,?)
            ''', (vente_id, date_vente, montant_paye_initial, 'Versement initial'))

        conn.commit()
        conn.close()
        flash(f'Crédit N°{numero} enregistré avec succès!', 'success')
        if statut == 'solde':
            return redirect(url_for('recu', vid=vente_id))
        return redirect(url_for('detail_vente', vid=vente_id))

    clients_list = conn.execute('SELECT * FROM clients ORDER BY nom').fetchall()
    produits_list = conn.execute('SELECT * FROM produits WHERE actif=1 ORDER BY nom').fetchall()
    params = get_params()
    conn.close()
    return render_template('nouvelle_vente.html', clients=clients_list,
                           produits=produits_list, params=params,
                           today=date.today().isoformat())


@app.route('/ventes/<int:vid>')
def detail_vente(vid):
    conn = get_db()
    vente = conn.execute('''
        SELECT v.*, c.nom AS client_nom, c.prenom AS client_prenom,
               c.telephone AS client_telephone, c.adresse AS client_adresse,
               c.id AS client_id
        FROM ventes v JOIN clients c ON v.client_id=c.id WHERE v.id=?
    ''', (vid,)).fetchone()
    if not vente:
        conn.close()
        flash('Crédit introuvable.', 'danger')
        return redirect(url_for('ventes'))
    items = conn.execute('SELECT * FROM vente_items WHERE vente_id=?', (vid,)).fetchall()
    paiements = conn.execute(
        'SELECT * FROM paiements WHERE vente_id=? ORDER BY date_paiement', (vid,)).fetchall()
    params = get_params()
    conn.close()
    reste = vente['montant_total'] - vente['montant_paye']
    return render_template('detail_vente.html', vente=vente, items=items,
                           paiements=paiements, reste=reste, params=params,
                           today=date.today().isoformat())


@app.route('/ventes/<int:vid>/paiement', methods=['POST'])
def ajouter_paiement(vid):
    conn = get_db()
    vente = conn.execute('SELECT * FROM ventes WHERE id=?', (vid,)).fetchone()
    if not vente:
        conn.close()
        flash('Crédit introuvable.', 'danger')
        return redirect(url_for('ventes'))

    try:
        montant = float(request.form.get('montant', '0').strip())
    except ValueError:
        montant = 0.0
    date_paiement = request.form.get('date_paiement', date.today().isoformat()).strip()
    notes = request.form.get('notes', '').strip()

    reste = vente['montant_total'] - vente['montant_paye']
    p = get_params()
    if montant <= 0 or montant > reste + 0.01:
        flash(f'Montant invalide. Reste à payer : {reste:,.0f} {p["devise"]}', 'danger')
        conn.close()
        return redirect(url_for('detail_vente', vid=vid))

    montant = min(montant, reste)
    new_paye = vente['montant_paye'] + montant
    new_statut = 'solde' if new_paye >= vente['montant_total'] - 0.01 else 'en_cours'

    conn.execute('INSERT INTO paiements (vente_id,date_paiement,montant,notes) VALUES (?,?,?,?)',
                 (vid, date_paiement, montant, notes))
    conn.execute('UPDATE ventes SET montant_paye=?,statut=? WHERE id=?',
                 (new_paye, new_statut, vid))
    conn.commit()
    conn.close()

    if new_statut == 'solde':
        flash(f'Paiement enregistré. Crédit entièrement SOLDÉ! Reçu généré.', 'success')
        return redirect(url_for('recu', vid=vid))
    flash(f'Paiement de {montant:,.0f} {p["devise"]} enregistré!', 'success')
    return redirect(url_for('detail_vente', vid=vid))


# ───────────────────────────────── REÇU ─────────────────────────────────

@app.route('/ventes/<int:vid>/recu')
def recu(vid):
    conn = get_db()
    vente = conn.execute('''
        SELECT v.*, c.nom AS client_nom, c.prenom AS client_prenom,
               c.telephone AS client_telephone, c.adresse AS client_adresse,
               c.id AS client_id
        FROM ventes v JOIN clients c ON v.client_id=c.id WHERE v.id=?
    ''', (vid,)).fetchone()
    if not vente:
        conn.close()
        flash('Crédit introuvable.', 'danger')
        return redirect(url_for('ventes'))
    items = conn.execute('SELECT * FROM vente_items WHERE vente_id=?', (vid,)).fetchall()
    paiements = conn.execute(
        'SELECT * FROM paiements WHERE vente_id=? ORDER BY date_paiement', (vid,)).fetchall()
    params = get_params()
    conn.close()
    reste = vente['montant_total'] - vente['montant_paye']
    now_str = datetime.now().strftime('%d/%m/%Y à %H:%M')
    return render_template('recu.html', vente=vente, items=items,
                           paiements=paiements, reste=reste,
                           params=params, now_str=now_str)


# ───────────────────────────────── PARAMÈTRES ─────────────────────────────────

@app.route('/parametres', methods=['GET', 'POST'])
def parametres():
    conn = get_db()
    if request.method == 'POST':
        nom_boutique       = request.form.get('nom_boutique', '').strip()
        adresse_boutique   = request.form.get('adresse_boutique', '').strip()
        telephone_boutique = request.form.get('telephone_boutique', '').strip()
        devise             = request.form.get('devise', 'FCFA').strip()
        proprietaire       = request.form.get('proprietaire', '').strip()
        conn.execute('''
            UPDATE parametres
            SET nom_boutique=?, adresse_boutique=?, telephone_boutique=?,
                devise=?, proprietaire=?
            WHERE id=1
        ''', (nom_boutique, adresse_boutique, telephone_boutique, devise, proprietaire))
        conn.commit()
        conn.close()
        flash('Paramètres sauvegardés avec succès!', 'success')
        return redirect(url_for('parametres'))
    params = get_params()
    conn.close()
    return render_template('parametres.html', params=params)


@app.route('/parametres/mot-de-passe', methods=['POST'])
def changer_mot_de_passe():
    user_id = session.get('user_id')
    ancien = request.form.get('ancien_mdp', '')
    nouveau = request.form.get('nouveau_mdp', '').strip()
    confirm = request.form.get('confirm_mdp', '').strip()
    if len(nouveau) < 4:
        flash('Le nouveau mot de passe doit contenir au moins 4 caractères.', 'danger')
        return redirect(url_for('parametres'))
    if nouveau != confirm:
        flash('Les nouveaux mots de passe ne correspondent pas.', 'danger')
        return redirect(url_for('parametres'))
    conn = get_db()
    user = conn.execute('SELECT * FROM users WHERE id=?', (user_id,)).fetchone()
    if not user or not check_password_hash(user['password'], ancien):
        conn.close()
        flash('Ancien mot de passe incorrect.', 'danger')
        return redirect(url_for('parametres'))
    conn.execute('UPDATE users SET password=? WHERE id=?',
                 (generate_password_hash(nouveau), user_id))
    conn.commit()
    conn.close()
    flash('Mot de passe modifié avec succès !', 'success')
    return redirect(url_for('parametres'))


# ───────────────────────────────── API JSON ─────────────────────────────────

@app.route('/api/produit/<int:pid>')
def api_produit(pid):
    conn = get_db()
    p = conn.execute('SELECT * FROM produits WHERE id=? AND actif=1', (pid,)).fetchone()
    conn.close()
    if p:
        return jsonify({'nom': p['nom'], 'prix_unitaire': p['prix_unitaire'],
                        'categorie': p['categorie']})
    return jsonify({}), 404


@app.route('/api/clients')
def api_clients():
    q = request.args.get('q', '').strip()
    conn = get_db()
    if q:
        rows = conn.execute(
            "SELECT id, nom, prenom, telephone FROM clients "
            "WHERE nom LIKE ? OR prenom LIKE ? OR telephone LIKE ? ORDER BY nom LIMIT 10",
            (f'%{q}%', f'%{q}%', f'%{q}%')).fetchall()
    else:
        rows = conn.execute(
            "SELECT id, nom, prenom, telephone FROM clients ORDER BY nom LIMIT 50").fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])


@app.route('/api/clients/creer', methods=['POST'])
def api_creer_client():
    nom       = clean(request.form.get('nom', ''), 100)
    prenom    = clean(request.form.get('prenom', ''), 100)
    telephone = clean(request.form.get('telephone', ''), 30)
    adresse   = clean(request.form.get('adresse', ''), 250)
    if not nom:
        return jsonify({'error': 'Le nom est obligatoire'}), 400
    conn = get_db()
    # Éviter les doublons évidents
    exist = conn.execute(
        'SELECT id FROM clients WHERE nom=? AND prenom=?', (nom, prenom)).fetchone()
    if exist:
        conn.close()
        return jsonify({'error': f'Client « {nom} {prenom} » existe déjà', 'id': exist['id'],
                        'nom': nom, 'prenom': prenom, 'telephone': telephone,
                        'exists': True}), 409
    cur = conn.execute(
        'INSERT INTO clients (nom,prenom,telephone,adresse) VALUES (?,?,?,?) RETURNING id',
        (nom, prenom, telephone, adresse))
    cid = cur.lastrowid
    conn.commit()
    conn.close()
    return jsonify({'id': cid, 'nom': nom, 'prenom': prenom, 'telephone': telephone}), 201


@app.route('/api/produits/creer', methods=['POST'])
def api_creer_produit():
    nom         = clean(request.form.get('nom', ''), 150)
    categorie   = clean(request.form.get('categorie', ''), 80)
    prix_str    = clean(request.form.get('prix_unitaire', '0'), 20)
    description = clean(request.form.get('description', ''), 300)
    if not nom:
        return jsonify({'error': 'Le nom du produit est obligatoire'}), 400
    try:
        prix = float(prix_str)
    except ValueError:
        prix = 0.0
    conn = get_db()
    cur = conn.execute(
        'INSERT INTO produits (nom,categorie,prix_unitaire,description) VALUES (?,?,?,?) RETURNING id',
        (nom, categorie, prix, description))
    pid = cur.lastrowid
    conn.commit()
    conn.close()
    return jsonify({'id': pid, 'nom': nom, 'categorie': categorie,
                    'prix_unitaire': prix, 'description': description}), 201


@app.route('/ping')
def ping():
    return '', 204


# ───────────────────────────────── PWA ─────────────────────────────────

@app.route('/manifest.json')
def pwa_manifest():
    from flask import send_from_directory
    resp = send_from_directory('static', 'manifest.json')
    resp.headers['Content-Type'] = 'application/manifest+json'
    return resp


@app.route('/sw.js')
def service_worker():
    from flask import send_from_directory
    resp = send_from_directory('static', 'sw.js')
    resp.headers['Content-Type'] = 'application/javascript'
    resp.headers['Service-Worker-Allowed'] = '/'
    resp.headers['Cache-Control'] = 'no-cache'
    return resp


@app.route('/offline')
def offline_page():
    from flask import send_from_directory
    return send_from_directory('static', 'offline.html')


# ───────────────────────────────── MAIN ─────────────────────────────────

# Initialise les tables au démarrage (gunicorn ou python direct)
if DATABASE_URL:
    init_db()
    seed_admin()
else:
    # SQLite — init locale au premier lancement
    init_db()
    seed_admin()

if __name__ == '__main__':
    print("\n" + "="*55)
    print("  ART Gestion Crédit — Système de Gestion des Crédits")
    print("  Ouvrez votre navigateur : http://127.0.0.1:5000")
    print("="*55 + "\n")
    app.run(debug=False, port=5000, host='127.0.0.1')
