import json
import os
import time
import uuid
from collections import deque
from datetime import datetime, timezone
from pathlib import Path

import jwt
import redis
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response

app = FastAPI()

EMAIL = "25f1001383@ds.study.iitm.ac.in"
ALLOWED_ORIGIN = "https://dash-vw2tce.example.com"

# ---------- Q8 state ----------
START = time.monotonic()
REQUEST_COUNT = 0
LOGS = deque(maxlen=1000)


@app.middleware("http")
async def cors_and_headers(request: Request, call_next):
    global REQUEST_COUNT
    REQUEST_COUNT += 1
    request_id = str(uuid.uuid4())
    start = time.perf_counter()

    origin = request.headers.get("origin")
    allowed = origin == ALLOWED_ORIGIN
    public = request.url.path == "/analytics"  # Q7 is open to all origins

    if request.method == "OPTIONS":
        if public:
            response = Response(status_code=200)
            response.headers["Access-Control-Allow-Origin"] = "*"
            response.headers["Access-Control-Allow-Methods"] = "POST, OPTIONS"
            requested = request.headers.get("access-control-request-headers")
            response.headers["Access-Control-Allow-Headers"] = requested or "Content-Type, X-API-Key"
            response.headers["Access-Control-Max-Age"] = "600"
        elif origin is None or allowed:
            response = Response(status_code=200)
            if allowed:
                response.headers["Access-Control-Allow-Origin"] = ALLOWED_ORIGIN
                response.headers["Access-Control-Allow-Methods"] = "GET, OPTIONS"
                requested = request.headers.get("access-control-request-headers")
                response.headers["Access-Control-Allow-Headers"] = requested or "*"
                response.headers["Access-Control-Max-Age"] = "600"
        else:
            response = Response(status_code=403)
    else:
        response = await call_next(request)
        if public:
            response.headers["Access-Control-Allow-Origin"] = "*"
        elif allowed:
            response.headers["Access-Control-Allow-Origin"] = ALLOWED_ORIGIN
            response.headers["Access-Control-Expose-Headers"] = "X-Request-ID, X-Process-Time"

    elapsed = time.perf_counter() - start
    response.headers["Vary"] = "Origin"
    response.headers["X-Request-ID"] = request_id
    response.headers["X-Process-Time"] = f"{elapsed:.6f}"

    entry = {
        "level": "INFO",
        "ts": datetime.now(timezone.utc).isoformat(),
        "path": request.url.path,
        "request_id": request_id,
        "method": request.method,
        "status": response.status_code,
        "duration_ms": round(elapsed * 1000, 3),
    }
    LOGS.append(entry)
    print(json.dumps(entry), flush=True)
    return response


@app.get("/")
async def root():
    return {"status": "ok"}


# ---------- Q3 ----------
@app.get("/stats")
async def stats(values: str = ""):
    try:
        nums = [int(v) for v in values.split(",") if v.strip() != ""]
    except ValueError:
        return JSONResponse({"error": "values must be comma-separated integers"}, status_code=400)
    if not nums:
        return JSONResponse({"error": "no values given"}, status_code=400)
    return {
        "email": EMAIL,
        "count": len(nums),
        "sum": sum(nums),
        "min": min(nums),
        "max": max(nums),
        "mean": sum(nums) / len(nums),
    }


# ---------- Q4 ----------
ISSUER = "https://idp.exam.local"
AUDIENCE = "tds-k8lmgsvw.apps.exam.local"
PUBLIC_KEY = (Path(__file__).parent / "public_key.pem").read_text()


@app.post("/verify")
async def verify(request: Request):
    try:
        body = await request.json()
        token = body["token"]
        claims = jwt.decode(
            token,
            PUBLIC_KEY,
            algorithms=["RS256"],
            audience=AUDIENCE,
            issuer=ISSUER,
            options={"require": ["exp", "iss", "aud"]},
        )
    except Exception:
        return JSONResponse({"valid": False}, status_code=401)
    return {
        "valid": True,
        "email": claims.get("email"),
        "sub": claims.get("sub"),
        "aud": claims.get("aud"),
    }


# ---------- Q6 ----------
rds = redis.Redis.from_url(os.getenv("REDIS_URL", "redis://localhost:6379"), decode_responses=True)


@app.post("/hit/{key}")
def hit(key: str):
    return {"key": key, "count": rds.incr(f"hits:{key}")}


@app.get("/count/{key}")
def count(key: str):
    value = rds.get(f"hits:{key}")
    return {"key": key, "count": int(value) if value else 0}


# ---------- Q6 + Q8 health ----------
@app.get("/healthz")
def healthz():
    uptime = round(time.monotonic() - START, 3)
    try:
        rds.ping()
        return {"status": "ok", "redis": "up", "uptime_s": uptime}
    except Exception:
        return JSONResponse({"status": "error", "redis": "down", "uptime_s": uptime}, status_code=503)


# ---------- Q7 ----------
@app.post("/analytics")
async def analytics(request: Request):
    expected = os.getenv("ANALYTICS_API_KEY", "")
    given = request.headers.get("x-api-key")
    if not expected or given != expected:
        return JSONResponse({"error": "unauthorized"}, status_code=401)

    try:
        body = await request.json()
        events = body["events"]
        users = set()
        totals = {}
        revenue = 0.0
        for e in events:
            user = e["user"]
            amount = float(e["amount"])
            users.add(user)
            if amount > 0:
                revenue += amount
                totals[user] = totals.get(user, 0.0) + amount
    except Exception:
        return JSONResponse({"error": "bad request body"}, status_code=400)

    top_user = max(totals, key=totals.get) if totals else None
    return {
        "email": EMAIL,
        "total_events": len(events),
        "unique_users": len(users),
        "revenue": round(revenue, 6),
        "top_user": top_user,
    }


# ---------- Q8 ----------
@app.get("/work")
def work(n: int = 1):
    if n < 0 or n > 1_000_000:
        return JSONResponse({"error": "n must be between 0 and 1000000"}, status_code=400)
    acc = 0
    for i in range(n):
        acc += i * i
    return {"email": EMAIL, "done": n}


@app.get("/metrics")
def metrics():
    text = (
        "# HELP http_requests_total Total HTTP requests handled.\n"
        "# TYPE http_requests_total counter\n"
        f"http_requests_total {REQUEST_COUNT}\n"
    )
    return Response(text, media_type="text/plain; version=0.0.4; charset=utf-8")


@app.get("/logs/tail")
def logs_tail(limit: int = 10):
    if limit <= 0:
        return []
    return list(LOGS)[-min(limit, 1000):]
