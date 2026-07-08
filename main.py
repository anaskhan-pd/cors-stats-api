"""
CORS-Aware Metrics API
FastAPI service that computes descriptive statistics with strict per-origin CORS policy.
"""

import time
import uuid
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse

# ─── Configuration ───────────────────────────────────────────────────────────
ALLOWED_ORIGIN = "https://dash-1drh4p.example.com"
EMAIL = "24f1000851@ds.study.iitm.ac.in"

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


# ─── Health Check ────────────────────────────────────────────────────────────
@app.get("/")
async def root():
    return {"status": "ok", "service": "CORS-Aware Metrics API"}
