"""
CORS-Aware Metrics API
FastAPI service that computes descriptive statistics with strict per-origin CORS policy.
Also provides JWT verification endpoint.
"""

import time
import uuid
import jwt
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel

# ─── Configuration ───────────────────────────────────────────────────────────
ALLOWED_ORIGIN = "https://dash-1drh4p.example.com"
EMAIL = "24f1000851@ds.study.iitm.ac.in"

# JWT verification config
JWT_ISSUER = "https://idp.exam.local"
JWT_AUDIENCE = "tds-38am6fmx.apps.exam.local"
JWT_PUBLIC_KEY = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2okOHspNjgA+2rTLbeuY
cxiP/hG8C6Sb9iwg3yiLAA4HCnpITcbWCSelbvbYGuc3EbNy4xFyf5Cbj5DHJMID
EkryOgyd2giIIIBOUBj8S63uGcnRpOBh9NFatfNwheKuzsPuVNldu6A9cNteNpXc
WyJjG2axVfmq7i6SuKr1JoWYG7xTTAvKPujSl4OtsQfO3h5NepzdfXpr28oNnzfW
ed+zclR6BcmNNo/WVfJ4xyCLSf0BCOgdTgW6PdaChd1l9VDetJZVEgC5tkyvXsfI
SI6iyrYbKR0NEBSqq4XkadEjsCs4F1RncsS4LlgniT7GlkL9Mce3b0wGLs9/7ZIX
dQIDAQAB
-----END PUBLIC KEY-----"""


class TokenRequest(BaseModel):
    token: str

app = FastAPI(title="CORS-Aware Metrics API")


# ─── Middleware: X-Request-ID & X-Process-Time ───────────────────────────────
@app.middleware("http")
async def add_custom_headers(request: Request, call_next):
    request_id = str(uuid.uuid4())
    start_time = time.perf_counter()

    response = await call_next(request)

    process_time = time.perf_counter() - start_time
    response.headers["X-Request-ID"] = request_id
    response.headers["X-Process-Time"] = f"{process_time:.6f}"

    return response


# ─── Manual CORS handling ────────────────────────────────────────────────────
# We handle CORS manually instead of using CORSMiddleware to ensure
# that non-allowed origins get NO Access-Control-Allow-Origin header at all.

@app.middleware("http")
async def cors_middleware(request: Request, call_next):
    origin = request.headers.get("origin")

    # Handle preflight OPTIONS requests
    if request.method == "OPTIONS":
        if origin == ALLOWED_ORIGIN:
            return Response(
                status_code=200,
                headers={
                    "Access-Control-Allow-Origin": ALLOWED_ORIGIN,
                    "Access-Control-Allow-Methods": "GET, OPTIONS",
                    "Access-Control-Allow-Headers": "*",
                    "Access-Control-Max-Age": "600",
                },
            )
        else:
            # Reject preflight from non-allowed origins: no ACAO header
            return Response(status_code=200)

    # Handle normal requests
    response = await call_next(request)

    if origin == ALLOWED_ORIGIN:
        response.headers["Access-Control-Allow-Origin"] = ALLOWED_ORIGIN

    return response


# ─── Stats Endpoint ──────────────────────────────────────────────────────────
@app.get("/stats")
async def stats(values: str):
    nums = [int(v.strip()) for v in values.split(",") if v.strip()]
    count = len(nums)
    total = sum(nums)
    minimum = min(nums)
    maximum = max(nums)
    mean = total / count

    return {
        "email": EMAIL,
        "count": count,
        "sum": total,
        "min": minimum,
        "max": maximum,
        "mean": round(mean, 10),
    }


# ─── JWT Verify Endpoint ─────────────────────────────────────────────────────
@app.post("/verify")
async def verify(body: TokenRequest):
    try:
        payload = jwt.decode(
            body.token,
            JWT_PUBLIC_KEY,
            algorithms=["RS256"],
            issuer=JWT_ISSUER,
            audience=JWT_AUDIENCE,
            options={"require": ["exp", "iss", "aud", "sub", "email"]},
        )
        return JSONResponse(
            status_code=200,
            content={
                "valid": True,
                "email": payload.get("email"),
                "sub": payload.get("sub"),
                "aud": payload.get("aud"),
            },
        )
    except Exception:
        return JSONResponse(
            status_code=401,
            content={"valid": False},
        )


# ─── Health Check ────────────────────────────────────────────────────────────
@app.get("/")
async def root():
    return {"status": "ok", "service": "CORS-Aware Metrics API"}
