import sqlite3
import hashlib
import os
import secrets

DB_PATH = os.path.join(os.path.dirname(__file__), 'vaultcorp.db')
FLAG_SQLI2 = os.environ.get('FLAG_SQLI2', 'VenD{unset}')
FLAG_CAPSTONE = os.environ.get('FLAG_CAPSTONE', 'VenD{unset}')

def hash_pw(pw):
    return hashlib.sha256(pw.encode()).hexdigest()

def init():
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.executescript('''
    CREATE TABLE users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      email TEXT,
      role TEXT DEFAULT 'user',
      bio TEXT,
      coins INTEGER DEFAULT 100,
      avatar TEXT
    );
    CREATE TABLE orders (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER,
      item TEXT,
      note TEXT
    );
    CREATE TABLE items (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT,
      price INTEGER,
      description TEXT
    );
    CREATE TABLE secrets_vault (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      k TEXT,
      v TEXT
    );
    CREATE TABLE claims (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER
    );
    ''')

    seed = [
        ('admin', hash_pw('r3alLy-h4rd-p4ss-' + secrets.token_hex(4)), 'admin@vaultcorp.local', 'admin', 'System administrator.', 999999),
        ('arturo.vega', hash_pw('arturo2026'), 'arturo.vega@vaultcorp.local', 'user', 'Senior accountant.', 250),
        ('priya.kapoor', hash_pw('priya_rules'), 'priya.kapoor@vaultcorp.local', 'user', 'HR.', 180),
    ]
    c.executemany(
        'INSERT INTO users (username, password, email, role, bio, coins) VALUES (?, ?, ?, ?, ?, ?)',
        seed
    )

    c.execute(
        "INSERT INTO orders (user_id, item, note) VALUES (?, ?, ?)",
        (1, 'Vault export archive', 'Confidential. See secrets_vault for details.')
    )

    c.executemany(
        "INSERT INTO items (name, price, description) VALUES (?, ?, ?)",
        [
            ('Mug', 50, 'Enamel VaultCorp mug'),
            ('Hoodie', 500, 'Charcoal hoodie, size M'),
            ('Legendary Vault Key', 2000, 'Unlocks the vault. Flag on purchase.'),
        ]
    )

    c.executemany(
        "INSERT INTO secrets_vault (k, v) VALUES (?, ?)",
        [
            ('db_flag', FLAG_SQLI2),
            ('note', 'Rotate every quarter.'),
        ]
    )

    conn.commit()
    conn.close()
    print(f'[+] db initialized at {DB_PATH}')

if __name__ == '__main__':
    init()
