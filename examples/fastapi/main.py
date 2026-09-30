"""A FastAPI application consuming FCaptcha, separate from the detection server."""
import os
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated
from urllib.parse import urlsplit

import httpx
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import FileResponse
from pydantic import BaseModel, ConfigDict, Field, ValidationError

STATIC = Path(__file__).parent / "static"


@dataclass(frozen=True)
class Settings:
    origin: str
    captcha_origin: str
    verify_secret: str
    site_key: str = "fastapi-demo"

    def __post_init__(self):
        for value in (self.origin, self.captcha_origin):
            url = urlsplit(value)
            if (url.scheme not in {"http", "https"} or not url.hostname
                    or url.username or url.password or url.path or url.query or url.fragment):
                raise ValueError("Use an http(s) origin without a path or credentials")
        if not self.verify_secret:
            raise ValueError("A server-only verification secret is required")


class Submission(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True, strict=True)
    message: str = Field(min_length=1, max_length=2000)
    token: str = Field(min_length=1, max_length=8192)


def create_app(settings: Settings, *, transport=None) -> FastAPI:
    @asynccontextmanager
    async def lifespan(app):
        # One connection pool per worker, closed on shutdown. No automatic token retries.
        async with httpx.AsyncClient(
            base_url=settings.captcha_origin, timeout=5.0,
            follow_redirects=False, trust_env=False, transport=transport,
        ) as client:
            app.state.verifier = client
            yield

    app = FastAPI(title="FCaptcha + FastAPI example", lifespan=lifespan)

    @app.middleware("http")
    async def response_headers(request, call_next):
        response = await call_next(request)
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        return response

    @app.get("/", include_in_schema=False)
    async def index():
        return FileResponse(STATIC / "index.html")

    @app.get("/app.js", include_in_schema=False)
    async def javascript():
        return FileResponse(STATIC / "app.js", media_type="text/javascript")

    @app.get("/config", include_in_schema=False)
    async def config():
        return {"captchaOrigin": settings.captcha_origin, "siteKey": settings.site_key}

    async def verified_submission(request: Request) -> Submission:
        # Browser cross-origin check, not authentication. The demo uses same-origin JSON.
        if request.headers.get("origin") != settings.origin:
            raise HTTPException(403, "origin_not_allowed")
        if request.headers.get("content-type", "").split(";", 1)[0].strip() != "application/json":
            raise HTTPException(415, "json_required")
        raw = bytearray()
        async for chunk in request.stream():
            raw.extend(chunk)
            if len(raw) > 16 * 1024:
                raise HTTPException(413, "body_too_large")
        try:
            submission = Submission.model_validate_json(bytes(raw))
        except ValidationError:
            # Do not echo tokens or message content in validation errors.
            raise HTTPException(422, "invalid_input") from None

        try:
            response = await request.app.state.verifier.post(
                "/siteverify",
                data={"secret": settings.verify_secret, "response": submission.token},
            )
            response.raise_for_status()
            result = response.json()
            if not isinstance(result, dict) or not isinstance(result.get("success"), bool):
                raise ValueError("Invalid verifier response")
        except (httpx.HTTPError, ValueError):
            raise HTTPException(503, "verification_unavailable") from None

        if (result["success"] is not True
                or result.get("hostname") != urlsplit(settings.origin).hostname
                or result.get("action") != "contact"):
            raise HTTPException(403, "captcha_rejected")
        return submission

    @app.post("/contact")
    async def contact(submission: Annotated[Submission, Depends(verified_submission)]):
        # Perform the protected operation here, after verification. No email/database in this demo.
        return {"accepted": True, "demoOnly": True}

    return app


def app_factory():
    return create_app(Settings(
        origin=os.environ["APP_ORIGIN"],
        captcha_origin=os.environ["FCAPTCHA_ORIGIN"],
        verify_secret=os.environ["FCAPTCHA_VERIFY_SECRET"],
    ))
