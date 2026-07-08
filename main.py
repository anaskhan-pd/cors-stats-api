"""
CORS-Aware Metrics API
FastAPI service that computes descriptive statistics with strict per-origin CORS policy.
Also provides JWT verification endpoint.
"""

import os
import time
import uuid
from pathlib import Path
from typing import List, Optional

import jwt
import yaml
from dotenv import dotenv_values
from fastapi import FastAPI, Query, Request, Response
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
                    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
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


# ─── 12-Factor Config Precedence ─────────────────────────────────────────────

BASE_DIR = Path(__file__).resolve().parent

DEFAULTS = {
    "port": 8000,
    "workers": 1,
    "debug": False,
    "log_level": "info",
    "api_key": "default-secret-000",
}

# Key mapping from APP_* env var names to config keys
ENV_KEY_MAP = {
    "APP_PORT": "port",
    "APP_WORKERS": "workers",
    "APP_DEBUG": "debug",
    "APP_LOG_LEVEL": "log_level",
    "APP_API_KEY": "api_key",
}

# Alias: NUM_WORKERS -> workers (in .env layer)
ENV_ALIASES = {
    "NUM_WORKERS": "workers",
}

CONFIG_KEYS = {"port", "workers", "debug", "log_level", "api_key"}


def coerce_bool(value) -> bool:
    """Convert a value to boolean."""
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in ("true", "1", "yes", "on")


def coerce_int(value) -> int:
    """Convert a value to integer."""
    return int(value)


def coerce_value(key: str, value):
    """Apply type coercion based on key name."""
    if key == "port" or key == "workers":
        return coerce_int(value)
    elif key == "debug":
        return coerce_bool(value)
    else:
        return str(value)


def load_yaml_config() -> dict:
    """Load config.development.yaml (layer 2)."""
    yaml_path = BASE_DIR / "config.development.yaml"
    if yaml_path.exists():
        with open(yaml_path) as f:
            data = yaml.safe_load(f) or {}
        return {k: v for k, v in data.items() if k in CONFIG_KEYS}
    return {}


def load_dotenv_config() -> dict:
    """Load .env file (layer 3) with APP_* prefix mapping and aliases."""
    env_path = BASE_DIR / ".env"
    result = {}
    if env_path.exists():
        env_vals = dotenv_values(env_path)
        for env_key, val in env_vals.items():
            if env_key in ENV_KEY_MAP:
                result[ENV_KEY_MAP[env_key]] = val
            elif env_key in ENV_ALIASES:
                result[ENV_ALIASES[env_key]] = val
    return result


def load_os_env_config() -> dict:
    """Load OS environment variables with APP_* prefix (layer 4)."""
    result = {}
    for env_key, config_key in ENV_KEY_MAP.items():
        val = os.environ.get(env_key)
        if val is not None:
            result[config_key] = val
    return result


@app.get("/effective-config")
async def effective_config(request: Request, set: Optional[List[str]] = Query(None)):
    # Layer 1: defaults
    config = dict(DEFAULTS)

    # Layer 2: config.development.yaml
    yaml_config = load_yaml_config()
    config.update(yaml_config)

    # Layer 3: .env file
    dotenv_config = load_dotenv_config()
    config.update(dotenv_config)

    # Layer 4: OS env vars (APP_* prefix)
    os_env_config = load_os_env_config()
    config.update(os_env_config)

    # Layer 5 (highest): CLI overrides from ?set=key=value
    if set:
        for param in set:
            if "=" in param:
                key, value = param.split("=", 1)
                key = key.strip()
                if key in CONFIG_KEYS:
                    config[key] = value

    # Apply type coercion
    for key in CONFIG_KEYS:
        if key in config:
            config[key] = coerce_value(key, config[key])

    # Mask api_key
    config["api_key"] = "****"

    return config


# ─── Health Check ────────────────────────────────────────────────────────────
@app.get("/")
async def root():
    return {"status": "ok", "service": "CORS-Aware Metrics API"}
