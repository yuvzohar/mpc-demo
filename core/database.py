import sqlite3
import os


def setup_database(db_path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    _create_tables(conn)
    _seed_data(conn)
    return conn


def _create_tables(conn: sqlite3.Connection) -> None:
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS employees (
            id         INTEGER PRIMARY KEY,
            name       TEXT NOT NULL,
            email      TEXT NOT NULL,
            ssn        TEXT NOT NULL,
            salary     INTEGER NOT NULL,
            department TEXT NOT NULL,
            tenant_id  INTEGER NOT NULL DEFAULT 1
        );

        CREATE TABLE IF NOT EXISTS auth_tokens (
            token_id   INTEGER PRIMARY KEY,
            token      TEXT NOT NULL,
            user_id    INTEGER NOT NULL,
            scope      TEXT NOT NULL,
            tenant_id  INTEGER NOT NULL,
            expires_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS secrets (
            id          INTEGER PRIMARY KEY,
            key_name    TEXT NOT NULL,
            secret_val  TEXT NOT NULL,
            clearance   TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS audit_log (
            id         INTEGER PRIMARY KEY,
            timestamp  TEXT NOT NULL,
            actor      TEXT NOT NULL,
            action     TEXT NOT NULL,
            resource   TEXT NOT NULL,
            approved   INTEGER DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS rate_limits (
            id         INTEGER PRIMARY KEY,
            endpoint   TEXT NOT NULL UNIQUE,
            call_count INTEGER DEFAULT 0,
            limit_val  INTEGER DEFAULT 100,
            reset_at   TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS agent_registry (
            id          INTEGER PRIMARY KEY,
            agent_name  TEXT NOT NULL,
            server_url  TEXT NOT NULL,
            registered  INTEGER DEFAULT 1,
            last_seen   TEXT
        );
    """)
    conn.commit()


def _seed_data(conn: sqlite3.Connection) -> None:
    if conn.execute("SELECT COUNT(*) FROM employees").fetchone()[0] > 0:
        return

    employees = [
        # Tenant 1
        ("Alice Chen",      "alice@acmecorp.com",    "523-45-7821", 142000, "Engineering",  1),
        ("Bob Martinez",    "bob@acmecorp.com",      "612-33-9045", 98000,  "Finance",      1),
        ("Carol Smith",     "carol@acmecorp.com",    "789-22-1134", 175000, "Engineering",  1),
        ("David Lee",       "david@acmecorp.com",    "456-78-2290", 67000,  "HR",           1),
        ("Eve Johnson",     "eve@acmecorp.com",      "321-90-4456", 220000, "Executive",    1),
        # Tenant 2
        ("Frank Brown",     "frank@globex.io",       "111-22-3333", 88000,  "Sales",        2),
        ("Grace Wilson",    "grace@globex.io",       "444-55-6666", 115000, "Engineering",  2),
        ("Hank Davis",      "hank@globex.io",        "777-88-9999", 72000,  "Operations",   2),
        ("Iris Taylor",     "iris@globex.io",        "222-33-4444", 195000, "Legal",        2),
        ("Jack Thomas",     "jack@globex.io",        "555-66-7777", 63000,  "Support",      2),
        # Tenant 3
        ("Kate Anderson",   "kate@initech.net",      "888-99-0000", 145000, "Engineering",  3),
        ("Liam Jackson",    "liam@initech.net",      "333-44-5555", 91000,  "Marketing",    3),
        ("Mia White",       "mia@initech.net",       "666-77-8888", 78000,  "Finance",      3),
        ("Noah Harris",     "noah@initech.net",      "999-00-1111", 250000, "Executive",    3),
        ("Olivia Martin",   "olivia@initech.net",    "112-23-3445", 55000,  "HR",           3),
    ]
    conn.executemany(
        "INSERT INTO employees (name, email, ssn, salary, department, tenant_id) VALUES (?,?,?,?,?,?)",
        employees,
    )

    tokens = [
        ("tok_r_t1_alice_abc123",   1,  "read",         1, "2027-01-01T00:00:00Z"),
        ("tok_rw_t1_bob_def456",    2,  "read write",   1, "2027-01-01T00:00:00Z"),
        ("tok_adm_t1_eve_ghi789",   5,  "admin",        1, "2027-01-01T00:00:00Z"),
        ("tok_r_t2_frank_jkl012",   6,  "read",         2, "2027-01-01T00:00:00Z"),
        ("tok_rw_t2_iris_mno345",   9,  "read write",   2, "2027-01-01T00:00:00Z"),
        ("tok_adm_t3_noah_pqr678",  14, "admin",        3, "2027-01-01T00:00:00Z"),
    ]
    conn.executemany(
        "INSERT INTO auth_tokens (token, user_id, scope, tenant_id, expires_at) VALUES (?,?,?,?,?)",
        tokens,
    )

    secrets = [
        ("COMPANY_WEBSITE",       "https://acmecorp.com",                        "public"),
        ("INTERNAL_WIKI_URL",     "https://wiki.internal.acmecorp.com",          "internal"),
        ("SALESFORCE_API_KEY",    "sf_key_Xk9mP2qR7vN4jL8wD1cA",               "confidential"),
        ("PAYMENT_GATEWAY_KEY",   "pk_live_51H9jKL2eZvKYlo2C7FAKE9876DEMO",     "confidential"),
        ("AWS_ACCESS_KEY",        "AKIAIOSFODNN7EXAMPLE",                        "confidential"),
        ("AWS_SECRET_KEY",        "wJalrXUtnFEMI/K7MDENG/bPxRfiCYDEMOKEY",     "top_secret"),
        ("MASTER_DB_PASSWORD",    "C0r3D@ta#Pr0d!2024",                          "top_secret"),
        ("JWT_SIGNING_SECRET",    "HS256_secret_DO_NOT_SHARE_abc123xyz789",      "top_secret"),
    ]
    conn.executemany(
        "INSERT INTO secrets (key_name, secret_val, clearance) VALUES (?,?,?)",
        secrets,
    )

    audit_entries = [
        ("2026-04-17 09:00:00", "alice",  "login",          "auth_service",     1),
        ("2026-04-17 09:05:00", "alice",  "read_record",    "employees",        1),
        ("2026-04-17 09:10:00", "bob",    "login",          "auth_service",     1),
        ("2026-04-17 09:15:00", "bob",    "update_record",  "employees",        1),
        ("2026-04-17 10:00:00", "eve",    "login",          "auth_service",     1),
        ("2026-04-17 10:05:00", "eve",    "admin_action",   "user_management",  1),
        ("2026-04-17 11:00:00", "frank",  "login",          "auth_service",     1),
        ("2026-04-17 11:10:00", "frank",  "read_record",    "sales_pipeline",   1),
        ("2026-04-17 12:00:00", "grace",  "deploy",         "production",       1),
        ("2026-04-17 13:00:00", "iris",   "access_secret",  "legal_documents",  1),
    ]
    conn.executemany(
        "INSERT INTO audit_log (timestamp, actor, action, resource, approved) VALUES (?,?,?,?,?)",
        audit_entries,
    )

    rate_limits = [
        ("search_records",   0, 100, "2026-04-18T23:59:59Z"),
        ("query_employees",  0, 50,  "2026-04-18T23:59:59Z"),
        ("submit_expense",   0, 20,  "2026-04-18T23:59:59Z"),
        ("access_secret",    0, 10,  "2026-04-18T23:59:59Z"),
        ("fetch_url",        0, 30,  "2026-04-18T23:59:59Z"),
    ]
    conn.executemany(
        "INSERT INTO rate_limits (endpoint, call_count, limit_val, reset_at) VALUES (?,?,?,?)",
        rate_limits,
    )

    agents = [
        ("mcp-filesystem",          "stdio://mcp-filesystem",               1, "2026-04-17T10:00:00Z"),
        ("mcp-memory",              "stdio://mcp-memory",                   1, "2026-04-17T10:00:00Z"),
        ("mcp-browser",             "stdio://mcp-browser",                  1, "2026-04-17T10:00:00Z"),
        ("mcp-postgres",            "tcp://db.internal:5432",               1, "2026-04-17T10:00:00Z"),
        ("mcp-git",                 "stdio://mcp-git",                      1, "2026-04-17T10:00:00Z"),
        ("mcp-internal-analytics",  "tcp://192.168.1.87:3000",              0, "2026-04-18T02:37:00Z"),
    ]
    conn.executemany(
        "INSERT INTO agent_registry (agent_name, server_url, registered, last_seen) VALUES (?,?,?,?)",
        agents,
    )

    conn.commit()


def get_connection(db_path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


def increment_rate_limit(conn: sqlite3.Connection, endpoint: str) -> tuple[int, int]:
    conn.execute(
        "UPDATE rate_limits SET call_count = call_count + 1 WHERE endpoint = ?",
        (endpoint,),
    )
    conn.commit()
    row = conn.execute(
        "SELECT call_count, limit_val FROM rate_limits WHERE endpoint = ?",
        (endpoint,),
    ).fetchone()
    if row:
        return row["call_count"], row["limit_val"]
    return 1, 100


def reset_rate_limit_counter(conn: sqlite3.Connection, endpoint: str) -> None:
    conn.execute("UPDATE rate_limits SET call_count = 0 WHERE endpoint = ?", (endpoint,))
    conn.commit()
