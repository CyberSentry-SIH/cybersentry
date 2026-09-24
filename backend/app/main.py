from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from backend.app.core.config import settings
from backend.app.seed import seed_database
from backend.app.api import auth, evidence, analysis, campaigns, graph, cases, reports, admin, health, geo, extension, analyze

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Initialize and seed database on startup
    seed_database()
    yield

app = FastAPI(
    title="CyberSentry V1 API",
    description="AI-Powered Email Forensic and Campaign Intelligence Platform (PS 26106)",
    version=settings.APP_VERSION,
    docs_url=None if settings.ENVIRONMENT == "production" else "/docs",
    redoc_url=None if settings.ENVIRONMENT == "production" else "/redoc",
    lifespan=lifespan
)

# CORS configuration
# Defensive: CORS_ORIGINS is always normalized to a list by the Settings
# validator now, but if it somehow weren't, fail CLOSED (empty list) rather
# than falling back to "*" -- especially since allow_credentials=True below
# turns a wildcard into "any origin, with cookies" once Starlette echoes
# the request's actual Origin header back.
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS if isinstance(settings.CORS_ORIGINS, list) else [],
    allow_origin_regex=r"https://.*\.onrender\.com",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def security_headers_middleware(request: Request, call_next):
    """
    Security headers hardening. None of these were previously set, so every
    response relied entirely on the browser's own defaults:
      - X-Content-Type-Options: stops the browser from guessing a
        response's MIME type differently than what we declared (a common
        way an "innocent" upload gets executed as script/HTML).
      - X-Frame-Options / frame-ancestors: stops this app being embedded in
        an <iframe> on another site for clickjacking.
      - Referrer-Policy: stops full URLs (which can contain evidence IDs,
        tokens in query strings, etc.) leaking to third-party Referer
        headers when a page links out.
      - HSTS: once served over HTTPS, tells browsers to only ever use
        HTTPS for this host going forward. Harmless to send even in local
        HTTP dev -- browsers only honor it once they see it over a real
        HTTPS connection.
    """
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
    return response


@app.middleware("http")
async def csrf_protection_middleware(request: Request, call_next):
    """
    CSRF protection for cookie-authenticated requests.

    This app supports two auth modes: an Authorization: Bearer header, or
    an HttpOnly session cookie (see deps.get_current_user). Bearer tokens
    are already CSRF-immune -- a malicious page on another site cannot make
    the victim's browser attach a custom Authorization header. Cookies are
    the opposite: browsers attach them automatically to any request to
    this domain, including ones triggered by a form or script on a
    completely different site the victim happens to have open. SameSite=Lax
    (our default) already blocks this for most cases, but defense-in-depth
    is cheap here: we also require a custom header on every state-changing
    request. A plain cross-site <form> POST (the classic CSRF vector)
    cannot set custom headers, so this blocks it even if a browser or proxy
    ever treated the cookie's SameSite attribute more loosely than expected.
    Requests already authenticating via Bearer token are exempt, since
    they were never vulnerable to this in the first place.
    """
    if request.method in ("POST", "PUT", "PATCH", "DELETE"):
        auth_header = request.headers.get("authorization", "")
        using_bearer = auth_header.lower().startswith("bearer ")
        has_session_cookie = "access_token" in request.cookies
        if has_session_cookie and not using_bearer:
            if request.headers.get("x-requested-with") != "CyberSentryClient":
                return JSONResponse(
                    status_code=403,
                    content={"detail": "CSRF protection: missing required client header for cookie-authenticated state-changing request."}
                )
    return await call_next(request)

# Include API Routers
api_v1_prefix = "/api/v1"
app.include_router(health.router, prefix=api_v1_prefix)
app.include_router(auth.router, prefix=api_v1_prefix)
app.include_router(evidence.router, prefix=api_v1_prefix)
app.include_router(analysis.router, prefix=api_v1_prefix)
app.include_router(geo.router, prefix=api_v1_prefix)
app.include_router(campaigns.router, prefix=api_v1_prefix)
app.include_router(graph.router, prefix=api_v1_prefix)
app.include_router(cases.router, prefix=api_v1_prefix)
app.include_router(reports.router, prefix=api_v1_prefix)
app.include_router(admin.router, prefix=api_v1_prefix)
app.include_router(extension.router, prefix=api_v1_prefix)
app.include_router(analyze.router, prefix=api_v1_prefix)

@app.get("/")
def root():
    return {
        "platform": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "status": "OPERATIONAL",
        "docs": "/docs",
        "api_v1": "/api/v1"
    }
