const captchaOrigin = process.env.FCAPTCHA_ORIGIN || "http://127.0.0.1:3000";

function reply(status, body) {
  return Response.json(body, { status, headers: { "Cache-Control": "no-store" } });
}

export async function POST(request) {
  const origin = new URL(request.url).origin;
  if (request.headers.get("origin") !== origin) return reply(403, { error: "origin_not_allowed" });

  let form;
  try {
    form = await request.formData();
  } catch {
    return reply(400, { error: "invalid_form" });
  }
  const message = form.get("message");
  const token = form.get("fcaptcha_token");
  if (typeof message !== "string" || !message.trim() || message.length > 2000 ||
      typeof token !== "string" || !token.trim() || token.length > 8192) {
    return reply(400, { error: "invalid_input" });
  }

  const secret = process.env.FCAPTCHA_VERIFY_SECRET;
  if (!secret) return reply(503, { error: "verification_unavailable" });

  let result;
  try {
    const response = await fetch(new URL("/turnstile/v0/siteverify", captchaOrigin), {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ secret, response: token }),
      signal: AbortSignal.timeout(5000),
      redirect: "error",
    });
    if (!response.ok) throw new Error("Verification unavailable");
    result = await response.json();
    if (!result || typeof result.success !== "boolean") throw new Error("Invalid verification response");
  } catch {
    return reply(503, { error: "verification_unavailable" });
  }

  if (result?.success !== true || result.hostname !== new URL(origin).hostname || result.action !== "") {
    return reply(403, { error: "captcha_rejected" });
  }
  // The demo deliberately has no protected side effect after verification.
  return reply(200, { accepted: true, demoOnly: true });
}
