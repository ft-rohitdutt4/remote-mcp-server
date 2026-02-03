from fastmcp import FastMCP
import os
import aiosqlite
import sqlite3
import tempfile
from typing import Optional
import json
import secrets
import hashlib
from datetime import datetime

# ---------------------------------------------------------------------------
# FastMCP Cloud uses an ephemeral filesystem. tempdir is the only writable
# location, but it resets on each cold start.  For a production deployment
# you would swap this out for an external database (Postgres, etc.).
# ---------------------------------------------------------------------------
TEMP_DIR = tempfile.gettempdir()
DB_PATH = os.path.join(TEMP_DIR, "expenses.db")

print(f"Database path: {DB_PATH}")

mcp = FastMCP("ExpenseTracker")

# ---------------------------------------------------------------------------
# DB init — single source of truth.  Users now live in the same DB so we
# never need to write to the repo directory (which is read-only on Cloud).
# ---------------------------------------------------------------------------
def init_db():
    """Initialize database tables (expenses + users)."""
    try:
        with sqlite3.connect(DB_PATH) as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("""
                CREATE TABLE IF NOT EXISTS expenses (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id     TEXT    NOT NULL,
                    date        TEXT    NOT NULL,
                    amount      REAL    NOT NULL,
                    category    TEXT    NOT NULL,
                    subcategory TEXT    DEFAULT '',
                    note        TEXT    DEFAULT ''
                )
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_user_date
                ON expenses(user_id, date)
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    user_id          TEXT   PRIMARY KEY,
                    api_key          TEXT   NOT NULL UNIQUE,
                    email            TEXT   NOT NULL UNIQUE,
                    name             TEXT   NOT NULL,
                    password_hash    TEXT   NOT NULL,
                    salt             TEXT   NOT NULL,
                    registered_at    TEXT   NOT NULL,
                    api_key_regen_at TEXT
                )
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_users_email
                ON users(email)
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_users_apikey
                ON users(api_key)
            """)
            conn.commit()
        print("✓ Database initialized (expenses + users)")
    except Exception as e:
        print(f"✗ Database initialization error: {e}")
        raise

init_db()

# ---------------------------------------------------------------------------
# Auth helpers
# ---------------------------------------------------------------------------
def _hash_password(password: str, salt: str) -> str:
    """PBKDF2-SHA256 with 260k iterations — safe for public-facing use."""
    return hashlib.pbkdf2_hmac(
        "sha256",
        password.encode(),
        salt.encode(),
        iterations=260_000,
    ).hex()


async def _authenticate(api_key: str) -> str:
    """Return the user_id for the given API key, or raise."""
    if not api_key:
        raise ValueError("API key is required")
    async with aiosqlite.connect(DB_PATH) as db:
        cur = await db.execute(
            "SELECT user_id FROM users WHERE api_key = ?", (api_key,)
        )
        row = await cur.fetchone()
    if row is None:
        raise ValueError("Invalid API key")
    return row[0]


# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------
@mcp.tool()
async def register_user(email: str, name: str, password: str):
    """Register a new user account and receive your API key.

    This is a PUBLIC tool — anyone can register.

    Args:
        email:    Your email address (must be unique).
        name:     Your display name.
        password: A secure password (stored as a salted PBKDF2 hash).

    Returns:
        Your unique API key.  Save it — you need it for every other tool.
    """
    # basic email sanity check
    if "@" not in email or "." not in email.split("@")[-1]:
        return {"status": "error", "message": "Invalid email format."}

    try:
        async with aiosqlite.connect(DB_PATH) as db:
            # duplicate-email check
            cur = await db.execute(
                "SELECT 1 FROM users WHERE LOWER(email) = LOWER(?)", (email,)
            )
            if await cur.fetchone():
                return {
                    "status": "error",
                    "message": "This email is already registered. "
                               "Use regenerate_api_key if you lost your key.",
                }

            user_id   = f"user_{secrets.token_hex(8)}"
            api_key   = secrets.token_urlsafe(32)
            salt      = secrets.token_hex(16)
            pw_hash   = _hash_password(password, salt)
            now       = datetime.now().isoformat()

            await db.execute(
                """INSERT INTO users
                   (user_id, api_key, email, name, password_hash, salt, registered_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (user_id, api_key, email.lower(), name, pw_hash, salt, now),
            )
            await db.commit()

        return {
            "status": "success",
            "message": "Registration successful! Save your API key.",
            "api_key": api_key,
            "user_id": user_id,
            "name":    name,
            "email":   email.lower(),
            "instructions": "Use this API key with all expense tracker tools. Keep it secret!",
        }
    except Exception as e:
        return {"status": "error", "message": f"Registration error: {e}"}


@mcp.tool()
async def regenerate_api_key(email: str, password: str):
    """Regenerate your API key (requires email + password).

    Args:
        email:    Your registered email.
        password: Your account password.

    Returns:
        A new API key.  The old one stops working immediately.
    """
    try:
        async with aiosqlite.connect(DB_PATH) as db:
            cur = await db.execute(
                "SELECT user_id, password_hash, salt FROM users WHERE LOWER(email) = LOWER(?)",
                (email,),
            )
            row = await cur.fetchone()

            if row is None:
                return {"status": "error", "message": "Email not found."}

            user_id, stored_hash, salt = row
            if _hash_password(password, salt) != stored_hash:
                return {"status": "error", "message": "Incorrect password."}

            new_key = secrets.token_urlsafe(32)
            await db.execute(
                "UPDATE users SET api_key = ?, api_key_regen_at = ? WHERE user_id = ?",
                (new_key, datetime.now().isoformat(), user_id),
            )
            await db.commit()

        return {
            "status":  "success",
            "message": "New API key generated.",
            "api_key": new_key,
            "user_id": user_id,
            "warning": "Your old API key will no longer work.",
        }
    except Exception as e:
        return {"status": "error", "message": f"Error: {e}"}


@mcp.tool()
async def add_expense(
    date: str,
    amount: float,
    category: str,
    api_key: str,
    subcategory: str = "",
    note: str = "",
):
    """Add a new expense entry (private to your account).

    Args:
        date:        YYYY-MM-DD.
        amount:      Expense amount (e.g. 45.50).
        category:    e.g. "Food & Dining".
        api_key:     Your personal API key.
        subcategory: Optional sub-category.
        note:        Optional note.
    """
    user_id = await _authenticate(api_key)
    try:
        async with aiosqlite.connect(DB_PATH) as db:
            cur = await db.execute(
                "INSERT INTO expenses(user_id, date, amount, category, subcategory, note) "
                "VALUES (?,?,?,?,?,?)",
                (user_id, date, amount, category, subcategory, note),
            )
            await db.commit()
            return {"status": "success", "id": cur.lastrowid, "message": "Expense added."}
    except Exception as e:
        return {"status": "error", "message": f"Database error: {e}"}


@mcp.tool()
async def list_expenses(start_date: str, end_date: str, api_key: str):
    """List your expenses within a date range.

    Args:
        start_date: YYYY-MM-DD.
        end_date:   YYYY-MM-DD.
        api_key:    Your personal API key.
    """
    user_id = await _authenticate(api_key)
    try:
        async with aiosqlite.connect(DB_PATH) as db:
            cur = await db.execute(
                "SELECT id, date, amount, category, subcategory, note "
                "FROM expenses WHERE user_id = ? AND date BETWEEN ? AND ? "
                "ORDER BY date DESC, id DESC",
                (user_id, start_date, end_date),
            )
            cols     = [d[0] for d in cur.description]
            expenses = [dict(zip(cols, row)) for row in await cur.fetchall()]
        return {"count": len(expenses), "expenses": expenses}
    except Exception as e:
        return {"status": "error", "message": f"Error: {e}"}


@mcp.tool()
async def summarize(
    start_date: str,
    end_date: str,
    api_key: str,
    category: Optional[str] = None,
):
    """Summarize your expenses by category (optionally filtered).

    Args:
        start_date: YYYY-MM-DD.
        end_date:   YYYY-MM-DD.
        api_key:    Your personal API key.
        category:   Optional single-category filter.
    """
    user_id = await _authenticate(api_key)
    try:
        query  = ("SELECT category, SUM(amount) AS total_amount, COUNT(*) AS count "
                  "FROM expenses WHERE user_id = ? AND date BETWEEN ? AND ?")
        params = [user_id, start_date, end_date]
        if category:
            query  += " AND category = ?"
            params.append(category)
        query += " GROUP BY category ORDER BY total_amount DESC"

        async with aiosqlite.connect(DB_PATH) as db:
            cur     = await db.execute(query, params)
            cols    = [d[0] for d in cur.description]
            summary = [dict(zip(cols, row)) for row in await cur.fetchall()]

        return {
            "total_amount": sum(item["total_amount"] for item in summary),
            "summary":      summary,
        }
    except Exception as e:
        return {"status": "error", "message": f"Error: {e}"}


@mcp.tool()
async def delete_expense(expense_id: int, api_key: str):
    """Delete one of your own expenses.

    Args:
        expense_id: The ID returned when the expense was added.
        api_key:    Your personal API key.
    """
    user_id = await _authenticate(api_key)
    try:
        async with aiosqlite.connect(DB_PATH) as db:
            cur = await db.execute(
                "SELECT 1 FROM expenses WHERE id = ? AND user_id = ?",
                (expense_id, user_id),
            )
            if not await cur.fetchone():
                return {"status": "error", "message": "Expense not found or not yours."}
            await db.execute(
                "DELETE FROM expenses WHERE id = ? AND user_id = ?",
                (expense_id, user_id),
            )
            await db.commit()
        return {"status": "success", "message": f"Expense {expense_id} deleted."}
    except Exception as e:
        return {"status": "error", "message": f"Error: {e}"}


# ---------------------------------------------------------------------------
# Resources
# ---------------------------------------------------------------------------
CATEGORIES = [
    "Food & Dining",
    "Transportation",
    "Shopping",
    "Entertainment",
    "Bills & Utilities",
    "Healthcare",
    "Travel",
    "Education",
    "Business",
    "Other",
]

@mcp.resource("expense:///categories", mime_type="application/json")
def categories():
    """Get the list of available expense categories."""
    return json.dumps({"categories": CATEGORIES}, indent=2)


# ---------------------------------------------------------------------------
# Local dev entry-point (ignored by FastMCP Cloud)
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    print("\n" + "=" * 60)
    print(" Expense Tracker MCP Server  (local dev)")
    print("=" * 60)
    print(f" DB  : {DB_PATH}")
    print(" Run : http://0.0.0.0:8000")
    print("=" * 60 + "\n")
    mcp.run(transport="http", host="0.0.0.0", port=8000)