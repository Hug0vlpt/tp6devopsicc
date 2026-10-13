"""MiniShop : application FastAPI VOLONTAIREMENT VULNÉRABLE (support du TP Cours 7).

Ne jamais déployer ce code tel quel. Votre mission : le rendre conforme.
Documentation interactive : http://localhost:5000/docs
"""
import logging
import os
import secrets
import sqlite3
import subprocess
import traceback
import requests
import uvicorn
import yaml
import ast
from fastapi import Body, FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, PlainTextResponse
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware
from sqlalchemy import Float, String, create_engine, select
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column
from pydantic import BaseModel, constr
from ipaddress import IPv4Address
from pathlib import Path
from urllib.parse import urlparse
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError

SECRET_KEY = os.environ["SECRET_KEY"]
DB_PATH = os.environ.get("DB_PATH", "shop.db")
UPLOAD_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "uploads")

ph = PasswordHasher()
# default password when the user doesn't exist
DUMMY_HASH = ph.hash("dummy-password")

logging.basicConfig(level=logging.DEBUG)
log = logging.getLogger("minishop")

app = FastAPI(title="MiniShop", debug=True)
app.add_middleware(
    SessionMiddleware,
    secret_key=SECRET_KEY,
    https_only=True,
    same_site="lax",
)

class Base(DeclarativeBase):
    pass

class LoginData(BaseModel):
    username: constr(min_length=1, max_length=64)
    password: constr(min_length=1, max_length=128)

class Product(Base):
    __tablename__ = "products"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String)
    price: Mapped[float] = mapped_column(Float)

class CalcData(BaseModel):
    expr: constr(min_length=1, max_length=100)

class Profile(BaseModel):
    name: str
    age: int

engine = create_engine(f"sqlite:///{DB_PATH}")

def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = db()
    conn.executescript(
        """
        DROP TABLE IF EXISTS users;
        DROP TABLE IF EXISTS products;
        DROP TABLE IF EXISTS invoices;
        CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT UNIQUE,
                            password TEXT, is_admin INTEGER DEFAULT 0);
        CREATE TABLE products (id INTEGER PRIMARY KEY, name TEXT, price REAL);
        CREATE TABLE invoices (id INTEGER PRIMARY KEY, owner_id INTEGER,
                               label TEXT, amount REAL);
        """
    )
    conn.execute("INSERT INTO users (username, password, is_admin) VALUES (?, ?, 1)",
                 ("admin", ph.hash("admin123")))
    conn.execute("INSERT INTO users (username, password) VALUES (?, ?)", ("alice", ph.hash("alice123")))
    conn.execute("INSERT INTO users (username, password) VALUES (?, ?)", ("bob", ph.hash("bob123")))
    conn.executemany("INSERT INTO products (name, price) VALUES (?, ?)",
                     [("apple", 1.2), ("banana", 0.8), ("cherry", 3.5)])
    conn.executemany("INSERT INTO invoices (owner_id, label, amount) VALUES (?, ?, ?)",
                     [(2, "Facture Alice", 42.0), (3, "Facture Bob", 99.0)])
    conn.commit()
    conn.close()


@app.exception_handler(Exception)
async def handle_error(request: Request, exc: Exception):
    return HTMLResponse("<pre>" + traceback.format_exc() + "</pre>", status_code=500)


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/login")
def login(request: Request, data: LoginData):
    row = db().execute(
        "SELECT id, username, password FROM users WHERE username = ?",
        (data.username,),
    ).fetchone()

    # it always run a verification, so time doesn't reveal which usernames exist
    stored_hash = row["password"] if row else DUMMY_HASH
    try:
        ph.verify(stored_hash, data.password)
        valid = row is not None
    except (VerifyMismatchError, InvalidHashError):
        valid = False

    if not valid:
        log.warning("failed login attempt user=%r", data.username)
        return JSONResponse({"error": "bad credentials"}, status_code=401)

    request.session["user_id"] = row["id"]
    request.session["token"] = secrets.token_urlsafe(32)
    log.info("login success user=%r, password=%r", row["username"], row["password"])
    return {"status": "logged in", "user": row["username"]}


@app.get("/search")
def search(q: str = ""):
    with Session(engine) as session:
        stmt = select(Product).where(Product.name.ilike(f"%{q}%"))
        products = session.scalars(stmt).all()
        return [{"id": p.id, "name": p.name, "price": p.price} for p in products]


@app.get("/ping")
def ping(host: IPv4Address = IPv4Address("127.0.0.1")):
    try:
        out = subprocess.run(
            ["ping", "-c", "1", "-W", "2", str(host)],
            capture_output=True, text=True, timeout=5,
        )
    except subprocess.TimeoutExpired:
        return JSONResponse({"error": "timeout"}, status_code=504)
    return PlainTextResponse(out.stdout)


@app.get("/hello")
def hello(name: str = ""):
    templates = Jinja2Templates(directory="templates")
    return templates.TemplateResponse(
    "hello.html", {"request": request, "name": name})


@app.get("/files/{name:path}")
def get_file(name: str):
    BASE = Path(UPLOAD_DIR).resolve()
    p = (BASE / name).resolve()
    if not p.is_relative_to(BASE) or not p.is_file():
        raise HTTPException(status_code=404)
    return FileResponse(p)


@app.post("/calc")
def calc(data: CalcData):
    try:
        val = ast.literal_eval(data.expr)
    except (ValueError, SyntaxError, TypeError, MemoryError, RecursionError):
        return JSONResponse({"error": "invalid expression"}, status_code=400)
    return {"result": str(val)}


@app.post("/import-yaml")
async def import_yaml(request: Request):
    try:
        cfg = yaml.safe_load(await request.body())
    except yaml.YAMLError:
        return JSONResponse({"error": "invalid yaml"}, status_code=400)
    return {"keys": list(cfg.keys()) if isinstance(cfg, dict) else str(type(cfg))}


@app.post("/import-profile")
def import_profile(profile: Profile):
    return {"profile": profile.dict()}


@app.get("/fetch")
def fetch(url: str):
    ALLOWED = {"api.partenaire.com"}
    u = urlparse(url)
    if u.scheme != "https" or u.hostname not in ALLOWED:
        raise HTTPException(status_code=400)
    r = requests.get(url, timeout=5, allow_redirects=False)
    return PlainTextResponse(r.text[:500])


@app.get("/invoices/{invoice_id}")
def invoice(invoice_id: int, request: Request):
    if "user_id" not in request.session:
        return JSONResponse({"error": "login required"}, status_code=401)
    row = db().execute("SELECT * FROM invoices WHERE id = ?", (invoice_id,)).fetchone()
    if not row:
        return JSONResponse({"error": "not found"}, status_code=404)
    return dict(row)


@app.get("/admin/users")
def admin_users(request: Request):
    if "user_id" not in request.session:
        return JSONResponse({"error": "login required"}, status_code=401)
    rows = db().execute("SELECT id, username, is_admin FROM users").fetchall()
    return [dict(r) for r in rows]


@app.delete("/users/{user_id}")
def delete_user(user_id: int, request: Request):
    if "user_id" not in request.session:
        return JSONResponse({"error": "login required"}, status_code=401)
    conn = db()
    conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit()
    return {"deleted": user_id}


@app.get("/boom")
def boom():
    return 1 / 0


if __name__ == "__main__":
    init_db()
    uvicorn.run("app:app", host="0.0.0.0", port=5000, reload=True)
