"""Startup configuration that must fail closed in network-facing servers."""

import os

INSECURE_DEFAULT_SECRET = "dev-secret-change-in-production"


def _enabled(value: str) -> bool:
    return str(value or "").strip().lower() in ("1", "true", "yes", "on")


def signing_secret_from_env(env=None) -> str:
    env = os.environ if env is None else env
    secret = str(env.get("FCAPTCHA_SECRET", "")).strip()
    if secret and secret != INSECURE_DEFAULT_SECRET:
        return secret
    if _enabled(env.get("FCAPTCHA_INSECURE_DEV_MODE", "")):
        print("WARNING: FCAPTCHA_INSECURE_DEV_MODE enabled; tokens use a public signing key. Never expose this server to a network.", flush=True)
        return INSECURE_DEFAULT_SECRET
    raise RuntimeError(
        "FCAPTCHA_SECRET is required and must not be the public development key. "
        "For local-only development, explicitly set FCAPTCHA_INSECURE_DEV_MODE=1."
    )
