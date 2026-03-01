from __future__ import annotations

import os
import sqlite3
import subprocess
from pathlib import Path

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
UPLOAD_DIR = BASE_DIR / "uploads"
DB_PATH = DATA_DIR / "vuln_target.db"

DATA_DIR.mkdir(parents=True, exist_ok=True)
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

app = FastAPI(title="Vulnerable Test Target", version="0.1.0")
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")


def db_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    with db_conn() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                username TEXT,
                email TEXT,
                role TEXT,
                api_key TEXT
            );

            CREATE TABLE IF NOT EXISTS orders (
                id INTEGER PRIMARY KEY,
                user_id INTEGER,
                item TEXT,
                amount REAL,
                status TEXT
            );
            """
        )
        count = conn.execute("SELECT COUNT(*) AS c FROM users").fetchone()["c"]
        if count == 0:
            conn.executemany(
                "INSERT INTO users(id, username, email, role, api_key) VALUES (?, ?, ?, ?, ?)",
                [
                    (1, "alice", "alice@example.com", "user", "ak_alice_dev_123"),
                    (2, "bob", "bob@example.com", "user", "ak_bob_dev_456"),
                    (3, "admin", "admin@example.com", "admin", "ak_admin_root_999"),
                ],
            )
            conn.executemany(
                "INSERT INTO orders(id, user_id, item, amount, status) VALUES (?, ?, ?, ?, ?)",
                [
                    (101, 1, "book", 12.5, "paid"),
                    (102, 2, "laptop", 899.0, "paid"),
                    (103, 1, "camera", 320.0, "shipping"),
                ],
            )

    (DATA_DIR / "internal_notes.txt").write_text(
        "internal secret notes\nroot_token=dev-root-token\n",
        encoding="utf-8",
    )


@app.on_event("startup")
def on_startup() -> None:
    init_db()


@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    vuln_routes = [
        {
            "name": "SQL Injection",
            "path": "POST /vuln/sqli",
            "desc": "Unsafe SQL query with string concatenation",
        },
        {
            "name": "Command Injection",
            "path": "POST /vuln/cmd",
            "desc": "User command executed via shell=True",
        },
        {
            "name": "Path Traversal",
            "path": "POST /vuln/traversal",
            "desc": "Arbitrary file read through unsanitized join",
        },
        {
            "name": "Unrestricted File Upload",
            "path": "/vuln/upload (POST)",
            "desc": "File type/extension/content validation absent",
        },
        {
            "name": "Unrestricted File Download",
            "path": "POST /vuln/download",
            "desc": "Any local path can be downloaded",
        },
        {
            "name": "IDOR",
            "path": "POST /vuln/idor/orders/102",
            "desc": "Order ownership not checked",
        },
        {
            "name": "Unauthenticated API Access",
            "path": "POST /api/admin/metrics",
            "desc": "Sensitive admin API accessible without session",
        },
    ]
    cards = []
    for item in vuln_routes:
        cards.append(
            "<article class='card'>"
            f"<h2>{item['name']}</h2>"
            f"<p>{item['desc']}</p>"
            f"<code>{item['path']}</code>"
            "</article>"
        )
    html = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>Vuln Target Lab</title>
  <link rel="stylesheet" href="/static/style.css" />
</head>
<body>
  <main class="container">
    <header>
      <h1>Vuln Target Lab</h1>
      <p>Testing target with 7 intentionally vulnerable paths.</p>
    </header>
    <section class="grid">{''.join(cards)}</section>
    <section class="panel">
      <h3>Quick Links</h3>
      <ul>
        <li><code>POST /vuln/sqli body={{"user_id":"1"}}</code></li>
        <li><code>POST /vuln/sqli body={{"user_id":"1 OR 1=1"}}</code></li>
        <li><code>POST /vuln/cmd body={{"cmd":"whoami"}}</code></li>
        <li><code>POST /vuln/traversal body={{"file":"../../data/internal_notes.txt"}}</code></li>
        <li><code>POST /vuln/download body={{"path":"./data/internal_notes.txt"}}</code></li>
        <li><code>POST /vuln/idor/orders/102 body={{"user_id":1}}</code></li>
        <li><code>POST /api/admin/metrics</code></li>
      </ul>
    </section>
    <section class="panel">
      <h3>Upload Test</h3>
      <p>POST raw body to <code>/vuln/upload?filename=your_file.txt</code></p>
      <textarea id="uploadData" rows="4" style="width:100%;">test upload content</textarea>
      <div style="margin-top:8px; display:flex; gap:8px; flex-wrap:wrap;">
        <input id="uploadName" type="text" value="notes.txt" />
        <button type="button" onclick="doUpload()">Upload Raw Text</button>
      </div>
      <pre id="uploadResult" style="white-space:pre-wrap;"></pre>
    </section>
  </main>
  <script>
    async function doUpload() {{
      const name = document.getElementById('uploadName').value || 'notes.txt';
      const data = document.getElementById('uploadData').value || '';
      const r = await fetch('/vuln/upload?filename=' + encodeURIComponent(name), {{
        method: 'POST',
        body: data
      }});
      document.getElementById('uploadResult').textContent = await r.text();
    }}
  </script>
</body>
</html>"""
    return HTMLResponse(html)


# 1) SQL Injection
@app.post("/vuln/sqli")
def vuln_sqli(body: SqliBody):
    user_id = body.user_id
    query = f"SELECT id, username, email, role, api_key FROM users WHERE id = {user_id}"  # nosec
    with db_conn() as conn:
        rows = conn.execute(query).fetchall()
    return {
        "query": query,
        "rows": [dict(r) for r in rows],
    }


# 2) Command Injection
@app.post("/vuln/cmd")
def vuln_cmd(body: CmdBody):
    cmd = body.cmd
    try:
        output = subprocess.check_output(cmd, shell=True, text=True, stderr=subprocess.STDOUT, timeout=5)  # nosec
    except Exception as e:
        output = f"error: {e}"
    return PlainTextResponse(output)


# 3) Path Traversal
@app.post("/vuln/traversal")
def vuln_traversal(body: TraversalBody):
    file = body.file
    target = UPLOAD_DIR / file
    try:
        content = target.read_text(encoding="utf-8", errors="ignore")
    except Exception as e:
        raise HTTPException(status_code=404, detail=f"read failed: {e}")
    return PlainTextResponse(content)


# 4) Unrestricted File Upload
@app.post("/vuln/upload")
async def vuln_upload(request: Request, filename: str = Query("upload.bin"), note: str = Query("")):
    save_path = UPLOAD_DIR / filename
    data = await request.body()
    save_path.write_bytes(data)
    return {
        "saved": str(save_path),
        "note": note,
        "size": len(data),
        "download_hint": f"/vuln/download?path={save_path}",
    }


# 5) Unrestricted File Download
@app.post("/vuln/download")
def vuln_download(body: DownloadBody):
    path = body.path
    target = Path(path)
    try:
        content = target.read_bytes()
    except Exception as e:
        raise HTTPException(status_code=404, detail=f"download failed: {e}")
    return PlainTextResponse(content.decode("utf-8", errors="ignore"))


# 6) IDOR
@app.post("/vuln/idor/orders/{order_id}")
def vuln_idor(order_id: int, body: IdorBody):
    user_id = body.user_id
    with db_conn() as conn:
        row = conn.execute(
            "SELECT id, user_id, item, amount, status FROM orders WHERE id = ?",
            (order_id,),
        ).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="order not found")

    # Intentionally vulnerable: no ownership check between user_id and row.user_id
    return {
        "request_user_id": user_id,
        "order": dict(row),
        "warning": "IDOR vulnerable: ownership not validated",
    }


# 7) Unauthenticated API Access
@app.post("/api/admin/metrics")
def unauth_admin_metrics():
    with db_conn() as conn:
        users = conn.execute("SELECT id, username, email, role, api_key FROM users").fetchall()
        orders = conn.execute("SELECT id, user_id, item, amount, status FROM orders").fetchall()

    return JSONResponse(
        {
            "service": "vuln-target",
            "env": "development",
            "db_path": str(DB_PATH),
            "users": [dict(u) for u in users],
            "orders": [dict(o) for o in orders],
            "secret_note_path": str(DATA_DIR / "internal_notes.txt"),
            "note": "No authentication required (intentionally vulnerable)",
        }
    )


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("app:app", host="0.0.0.0", port=8081, reload=False)
class SqliBody(BaseModel):
    user_id: str = "1"


class CmdBody(BaseModel):
    cmd: str = "whoami"


class TraversalBody(BaseModel):
    file: str = "sample.txt"


class DownloadBody(BaseModel):
    path: str = "./uploads/sample.txt"


class IdorBody(BaseModel):
    user_id: int
