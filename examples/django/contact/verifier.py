import httpx
from django.conf import settings


class VerificationUnavailable(Exception):
    pass


def verify_token(token: str) -> bool:
    if not settings.FCAPTCHA_VERIFY_SECRET:
        raise VerificationUnavailable("FCAPTCHA_VERIFY_SECRET is not configured")

    try:
        with httpx.Client(
            base_url=settings.FCAPTCHA_ORIGIN,
            timeout=5.0,
            follow_redirects=False,
            trust_env=False,
        ) as client:
            response = client.post(
                "/turnstile/v0/siteverify",
                data={"secret": settings.FCAPTCHA_VERIFY_SECRET, "response": token},
            )
            response.raise_for_status()
            result = response.json()
    except (httpx.HTTPError, ValueError) as exc:
        raise VerificationUnavailable("FCaptcha verification unavailable") from exc

    if not isinstance(result, dict) or not isinstance(result.get("success"), bool):
        raise VerificationUnavailable("FCaptcha returned an invalid response")

    return (
        result["success"] is True
        and result.get("hostname") == settings.FCAPTCHA_EXPECTED_HOSTNAME
        and result.get("action") == "contact"
    )
