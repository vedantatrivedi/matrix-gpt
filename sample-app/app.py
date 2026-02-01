import base64
import hashlib
import hmac
import importlib
import json
import sys
import traceback
from datetime import datetime
from pathlib import Path
from typing import Optional

import httpx
from fastapi import Body, FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from starlette.exceptions import HTTPException as StarletteHTTPException

from database import get_conn, init_db

# INTERNAL_API_KEY=dev-internal-key-123 (intentional comment leak)

APP_DIR = Path(__file__).parent
UPLOADS_DIR = APP_DIR / "uploads"
UPLOADS_DIR.mkdir(exist_ok=True)

JWT_SECRET = "dev-secret"

app = FastAPI()
BLOCKED_IPS: set[str] = set()
RATE_LIMITS: dict[str, dict] = {}


@app.on_event("startup")
def on_startup():
    init_db()


@app.middleware("http")
async def defense_and_log(request: Request, call_next):
    ts = datetime.utcnow().isoformat()
    ip = request.client.host if request.client else "unknown"

    if ip in BLOCKED_IPS:
        return JSONResponse(status_code=403, content={"error": "blocked"})

    limiter = RATE_LIMITS.get(ip)
    if limiter:
        now = datetime.utcnow().timestamp()
        window = limiter.get("window", 60)
        limit = limiter.get("limit", 30)
        timestamps = [t for t in limiter.get("hits", []) if now - t <= window]
        if len(timestamps) >= limit:
            limiter["hits"] = timestamps
            return JSONResponse(status_code=429, content={"error": "rate_limited"})
        timestamps.append(now)
        limiter["hits"] = timestamps

    body_bytes = await request.body()
    body_text = body_bytes.decode("utf-8", errors="ignore")
    body_text = body_text[:1000]
    print(f"[{ts}] {request.method} {request.url.path}")
    conn = get_conn()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO request_logs (timestamp, method, path, query, body, ip) VALUES (?, ?, ?, ?, ?, ?)",
        (ts, request.method, request.url.path, request.url.query, body_text, ip),
    )
    conn.commit()
    conn.close()
    return await call_next(request)


@app.exception_handler(Exception)
async def handle_exception(request: Request, exc: Exception):
    tb = traceback.format_exc()
    return JSONResponse(
        status_code=500,
        content={"error": str(exc), "trace": tb},
    )


@app.exception_handler(StarletteHTTPException)
async def handle_http_exception(request: Request, exc: StarletteHTTPException):
    tb = traceback.format_exc()
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": exc.detail, "trace": tb},
    )


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(data: str) -> bytes:
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)


def jwt_encode(payload: dict, alg: str = "HS256") -> str:
    header = {"alg": alg, "typ": "JWT"}
    header_b64 = _b64url_encode(json.dumps(header).encode("utf-8"))
    payload_b64 = _b64url_encode(json.dumps(payload).encode("utf-8"))
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    if alg == "none":
        signature = ""
    else:
        sig = hmac.new(JWT_SECRET.encode("utf-8"), signing_input, hashlib.sha256).digest()
        signature = _b64url_encode(sig)
    return f"{header_b64}.{payload_b64}.{signature}"


def jwt_verify(token: str) -> Optional[dict]:
    try:
        header_b64, payload_b64, signature = token.split(".")
        header = json.loads(_b64url_decode(header_b64))
        payload = json.loads(_b64url_decode(payload_b64))
        alg = header.get("alg")
        if alg == "none":
            # Vulnerability: accept unsigned tokens
            return payload
        if alg != "HS256":
            return None
        signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
        expected = hmac.new(JWT_SECRET.encode("utf-8"), signing_input, hashlib.sha256).digest()
        if _b64url_encode(expected) == signature:
            return payload
        return None
    except Exception:
        return None


def get_current_user(request: Request) -> Optional[dict]:
    auth = request.headers.get("authorization") or ""
    if not auth.startswith("Bearer "):
        return None
    token = auth.replace("Bearer ", "", 1)
    return jwt_verify(token)


def is_internal_request(request: Request) -> bool:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        ip = forwarded.split(",")[0].strip()
        return ip in ("127.0.0.1", "localhost", "::1")
    return False


class ReloadRequest(BaseModel):
    filename: str
    content: str


app.mount("/uploads", StaticFiles(directory=str(UPLOADS_DIR)), name="uploads")


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/")
def index():
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT id, name, description, price FROM products")
    products = cur.fetchall()
    cur.execute(
        "SELECT r.product_id, r.comment, u.username FROM reviews r JOIN users u ON r.user_id = u.id"
    )
    reviews = cur.fetchall()
    conn.close()

    product_html = "".join(
        [
            f"<li><strong>{p['name']}</strong> - ${p['price']}<br>{p['description']}</li>"
            for p in products
        ]
    )
    review_html = "".join(
        [
            f"<li>Product {r['product_id']} by {r['username']}: {r['comment']}</li>"
            for r in reviews
        ]
    )
    html = f"""
    <html>
      <head><title>Sample Shop</title></head>
      <body>
        <h1>Sample Shop</h1>
        <h2>Products</h2>
        <ul>{product_html}</ul>
        <h2>Reviews</h2>
        <ul>{review_html}</ul>
      </body>
    </html>
    """
    return HTMLResponse(html)


@app.get("/reviews/{product_id}")
def reviews_page(product_id: int):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute(
        "SELECT r.comment, u.username FROM reviews r JOIN users u ON r.user_id = u.id WHERE r.product_id = ?",
        (product_id,),
    )
    rows = cur.fetchall()
    conn.close()
    review_html = "".join(
        [f"<li>{r['username']}: {r['comment']}</li>" for r in rows]
    )
    html = f"""
    <html>
      <head><title>Reviews</title></head>
      <body>
        <h1>Reviews for product {product_id}</h1>
        <ul>{review_html}</ul>
      </body>
    </html>
    """
    return HTMLResponse(html)


@app.get("/api/products")
def products(search: Optional[str] = None):
    conn = get_conn()
    cur = conn.cursor()
    if search:
        # Vulnerable SQL injection
        query = f"SELECT id, name, price FROM products WHERE name = '{search}'"
        cur.execute(query)
    else:
        cur.execute("SELECT id, name, price FROM products")
    rows = cur.fetchall()
    conn.close()
    return {"products": [dict(r) for r in rows]}


@app.get("/api/products/{product_id}")
def product_detail(product_id: int):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT id, name, description, price FROM products WHERE id = ?", (product_id,))
    row = cur.fetchone()
    conn.close()
    if not row:
        raise HTTPException(status_code=404, detail="Product not found")
    return dict(row)


@app.post("/api/reviews")
def create_review(product_id: int = Form(...), user_id: int = Form(...), comment: str = Form(...)):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO reviews (product_id, user_id, comment) VALUES (?, ?, ?)",
        (product_id, user_id, comment),
    )
    conn.commit()
    conn.close()
    return {"status": "ok"}


@app.get("/api/reviews/{product_id}")
def reviews_api(product_id: int):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute(
        "SELECT r.id, r.comment, u.username FROM reviews r JOIN users u ON r.user_id = u.id WHERE r.product_id = ?",
        (product_id,),
    )
    rows = cur.fetchall()
    conn.close()
    return {"reviews": [dict(r) for r in rows]}


@app.post("/api/auth/login")
def login(username: str = Form(...), password: str = Form(...)):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute(
        "SELECT id, username, role FROM users WHERE username = ? AND password = ?",
        (username, password),
    )
    row = cur.fetchone()
    conn.close()
    if not row:
        return JSONResponse(status_code=401, content={"error": "invalid credentials"})
    token = jwt_encode({"sub": row["id"], "username": row["username"], "role": row["role"]})
    return {"token": token}


@app.get("/api/orders/{order_id}")
def get_order(order_id: int, request: Request):
    user = get_current_user(request)
    if not user:
        return JSONResponse(status_code=401, content={"error": "unauthorized"})
    conn = get_conn()
    cur = conn.cursor()
    # Vulnerability: no ownership check (IDOR)
    cur.execute(
        "SELECT id, user_id, product_id, quantity, status FROM orders WHERE id = ?",
        (order_id,),
    )
    row = cur.fetchone()
    conn.close()
    if not row:
        raise HTTPException(status_code=404, detail="Order not found")
    return dict(row)


@app.post("/api/orders")
def create_order(
    request: Request,
    product_id: int = Form(...),
    quantity: int = Form(1),
):
    user = get_current_user(request)
    if not user:
        return JSONResponse(status_code=401, content={"error": "unauthorized"})
    conn = get_conn()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO orders (user_id, product_id, quantity, status) VALUES (?, ?, ?, ?)",
        (user["sub"], product_id, quantity, "processing"),
    )
    conn.commit()
    conn.close()
    # Vulnerability: no CSRF protection
    return {"status": "created"}


@app.post("/api/users/avatar")
def upload_avatar(file: UploadFile = File(...)):
    # Vulnerability: unrestricted file upload
    filename = file.filename
    dest = UPLOADS_DIR / filename
    with dest.open("wb") as f:
        f.write(file.file.read())
    return {"status": "ok", "url": f"/uploads/{filename}"}


@app.post("/api/image-proxy")
async def image_proxy(request: Request, url: Optional[str] = Form(None)):
    # Vulnerability: SSRF, no allowlist
    if url is None:
        data = await request.json()
        url = data.get("url") if isinstance(data, dict) else None
    if not url:
        raise HTTPException(status_code=400, detail="url required")
    resp = httpx.get(url, timeout=5.0, headers={"X-Forwarded-For": "127.0.0.1"})
    return {"content": resp.text}


@app.get("/api/admin/users")
def admin_users(request: Request):
    user = get_current_user(request)
    if not is_internal_request(request):
        if not user or user.get("role") != "admin":
            return JSONResponse(status_code=403, content={"error": "forbidden"})
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT id, username, password, email, role FROM users")
    rows = cur.fetchall()
    conn.close()
    return {"users": [dict(r) for r in rows]}


@app.get("/api/admin/orders")
def admin_orders(request: Request):
    user = get_current_user(request)
    if not is_internal_request(request):
        if not user or user.get("role") != "admin":
            return JSONResponse(status_code=403, content={"error": "forbidden"})
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT id, user_id, product_id, quantity, status FROM orders")
    rows = cur.fetchall()
    conn.close()
    return {"orders": [dict(r) for r in rows]}


@app.get("/internal/logs")
def internal_logs(since: Optional[str] = None):
    conn = get_conn()
    cur = conn.cursor()
    if since:
        cur.execute(
            "SELECT timestamp, method, path, query, body, ip FROM request_logs WHERE timestamp > ? ORDER BY id ASC",
            (since,),
        )
    else:
        cur.execute(
            "SELECT timestamp, method, path, query, body, ip FROM request_logs ORDER BY id DESC LIMIT 200"
        )
    rows = cur.fetchall()
    conn.close()
    return {"logs": [dict(r) for r in rows]}


class DefenseAction(BaseModel):
    ip: str
    action: str
    limit: Optional[int] = None
    window: Optional[int] = None


@app.post("/internal/defense")
def internal_defense(payload: DefenseAction = Body(...)):
    ip = payload.ip
    action = payload.action.lower()
    if action == "block":
        BLOCKED_IPS.add(ip)
        return {"status": "blocked", "ip": ip}
    if action == "unblock":
        BLOCKED_IPS.discard(ip)
        return {"status": "unblocked", "ip": ip}
    if action == "limit":
        limit = payload.limit or 30
        window = payload.window or 60
        RATE_LIMITS[ip] = {"limit": limit, "window": window, "hits": []}
        return {"status": "limited", "ip": ip, "limit": limit, "window": window}
    if action == "clear":
        RATE_LIMITS.pop(ip, None)
        return {"status": "cleared", "ip": ip}
    raise HTTPException(status_code=400, detail="invalid action")


@app.get("/internal/source")
def internal_source(filename: str):
    target = APP_DIR / filename
    if not target.exists():
        raise HTTPException(status_code=404, detail="file not found")
    return {"filename": filename, "content": target.read_text()}


@app.post("/internal/reload")
def internal_reload(payload: ReloadRequest = Body(...)):
    # Intended to be private (Railway private networking / localhost)
    target = APP_DIR / payload.filename
    if not target.exists():
        raise HTTPException(status_code=404, detail="file not found")
    target.write_text(payload.content)
    importlib.invalidate_caches()
    module_name = "app"
    if module_name in sys.modules:
        new_mod = importlib.reload(sys.modules[module_name])
        if hasattr(new_mod, "app"):
            app.router.routes = new_mod.app.router.routes
    print(f"RELOADED: {payload.filename}")
    return {"status": "reloaded"}
