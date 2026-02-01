import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).parent / "sample.db"


def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_conn()
    cur = conn.cursor()
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT,
            email TEXT,
            role TEXT
        );
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS products (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            description TEXT,
            price REAL
        );
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS orders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            product_id INTEGER,
            quantity INTEGER,
            status TEXT
        );
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS reviews (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            product_id INTEGER,
            user_id INTEGER,
            comment TEXT
        );
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS request_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            method TEXT,
            path TEXT,
            query TEXT,
            body TEXT,
            ip TEXT
        );
        """
    )
    # Backfill column for existing DBs
    try:
        cur.execute("ALTER TABLE request_logs ADD COLUMN ip TEXT")
    except Exception:
        pass
    conn.commit()

    cur.execute("SELECT COUNT(*) as c FROM users")
    if cur.fetchone()["c"] == 0:
        # Hardcoded admin credentials (intentional vulnerability)
        users = [
            ("admin", "admin123", "admin@example.com", "admin"),
            ("alice", "password1", "alice@example.com", "user"),
            ("bob", "password2", "bob@example.com", "user"),
            ("carol", "password3", "carol@example.com", "user"),
            ("dave", "password4", "dave@example.com", "user"),
        ]
        cur.executemany(
            "INSERT INTO users (username, password, email, role) VALUES (?, ?, ?, ?)",
            users,
        )

    cur.execute("SELECT COUNT(*) as c FROM products")
    if cur.fetchone()["c"] == 0:
        products = [
            ("Matrix Mouse", "Wireless mouse", 39.99),
            ("Red Keycap Set", "Mechanical keyboard caps", 59.99),
            ("Blue Team Hoodie", "Team gear", 69.99),
            ("Cyan Cable", "USB-C cable", 9.99),
            ("Security Badge", "Metal badge", 14.99),
            ("War Room Lamp", "Desk lamp", 89.99),
            ("Threat Map Poster", "Wall art", 19.99),
            ("SOC Notebook", "Grid paper", 7.99),
            ("Signal Radio", "Decorative radio", 129.99),
            ("Access Card", "RFID card", 4.99),
        ]
        cur.executemany(
            "INSERT INTO products (name, description, price) VALUES (?, ?, ?)",
            products,
        )

    cur.execute("SELECT COUNT(*) as c FROM orders")
    if cur.fetchone()["c"] == 0:
        orders = [
            (2, 1, 1, "shipped"),
            (3, 2, 2, "processing"),
            (4, 3, 1, "processing"),
            (5, 4, 3, "delivered"),
            (2, 5, 1, "processing"),
        ]
        cur.executemany(
            "INSERT INTO orders (user_id, product_id, quantity, status) VALUES (?, ?, ?, ?)",
            orders,
        )

    cur.execute("SELECT COUNT(*) as c FROM reviews")
    if cur.fetchone()["c"] == 0:
        reviews = [
            (1, 2, "Great mouse for late-night ops."),
            (2, 3, "Keycaps feel solid."),
            (3, 4, "Hoodie is warm."),
        ]
        cur.executemany(
            "INSERT INTO reviews (product_id, user_id, comment) VALUES (?, ?, ?)",
            reviews,
        )

    conn.commit()
    conn.close()
