import time
import uuid

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response

ALLOWED_ORIGIN = "https://dash-vw2tce.example.com"
EMAIL = "25f1001383@ds.study.iitm.ac.in"

app = FastAPI()


@app.middleware("http")
async def cors_and_headers(request: Request, call_next):
    start = time.perf_counter()
    origin = request.headers.get("origin")
    allowed = origin == ALLOWED_ORIGIN

    if request.method == "OPTIONS":
        if origin is None or allowed:
            response = Response(status_code=200)
            if allowed:
                response.headers["Access-Control-Allow-Origin"] = ALLOWED_ORIGIN
                response.headers["Access-Control-Allow-Methods"] = "GET, OPTIONS"
                requested = request.headers.get("access-control-request-headers")
                response.headers["Access-Control-Allow-Headers"] = requested or "*"
                response.headers["Access-Control-Max-Age"] = "600"
        else:
            # any other origin: rejected, and no Access-Control-Allow-Origin header
            response = Response(status_code=403)
    else:
        response = await call_next(request)
        if allowed:
            response.headers["Access-Control-Allow-Origin"] = ALLOWED_ORIGIN
            response.headers["Access-Control-Expose-Headers"] = "X-Request-ID, X-Process-Time"

    response.headers["Vary"] = "Origin"
    response.headers["X-Request-ID"] = str(uuid.uuid4())
    response.headers["X-Process-Time"] = f"{time.perf_counter() - start:.6f}"
    return response


@app.get("/")
async def root():
    return {"status": "ok"}


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


# ---------- Q4: token verification ----------
from pathlib import Path

import jwt

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
