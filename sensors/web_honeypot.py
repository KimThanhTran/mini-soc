"""A decoy admin site. Every request is reported; posted credentials are captured and always refused.

Pages are static text: nothing the visitor sends is ever echoed back, so the decoy cannot be used for XSS or injection.
"""
import asyncio
import os
from contextlib import asynccontextmanager
from urllib.parse import parse_qs

from fastapi import FastAPI, Request, Response

from ship import Shipper

shipper = Shipper("honeypot_web", os.environ.get("SENSOR_HOST", "web-honeypot"))
TRUST_XFF = os.environ.get("TRUST_XFF") == "1"  # lab only: lets the simulator pretend to be several addresses
BAIT = {"/", "/admin", "/login", "/wp-login.php", "/phpmyadmin/", "/administrator"}
PAGE = """<!doctype html><title>Acme Router Admin</title><h1>Acme Router Admin</h1>
<form method="post" action="/login"><input name="username"><input name="password" type="password"><button>Sign in</button></form>
<p>{note}</p>"""


@asynccontextmanager
async def lifespan(_app):
    task = asyncio.create_task(shipper.run())
    yield
    task.cancel()


app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)


def client_ip(request: Request) -> str:
    if TRUST_XFF and (xff := request.headers.get("x-forwarded-for")):
        return xff.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


@app.api_route("/{path:path}", methods=["GET", "POST", "HEAD", "PUT", "DELETE", "OPTIONS"])
async def trap(request: Request) -> Response:
    path = request.url.path
    body = (await request.body())[:4096]  # bound what is read and kept
    creds = {k: v[0] for k, v in parse_qs(body.decode(errors="replace")).items()}
    if request.method == "POST" and path in BAIT:
        status, text, kind = 401, PAGE.format(note="Invalid credentials."), "text/html"
    elif path in BAIT:
        status, text, kind = 200, PAGE.format(note=""), "text/html"
    else:
        status, text, kind = 404, "Not Found", "text/plain"
    data = {"src_ip": client_ip(request), "method": request.method, "status": status,
            "path": request.scope.get("raw_path", path.encode()).decode(errors="replace") + (f"?{request.url.query}" if request.url.query else ""),
            "user_agent": request.headers.get("user-agent", "")[:300]}
    if request.method == "POST" and path in BAIT and ("username" in creds or "password" in creds):
        data |= {"username": creds.get("username", "")[:128], "password": creds.get("password", "")[:64]}
    shipper.emit(data)
    return Response(text, status_code=status, media_type=kind)
