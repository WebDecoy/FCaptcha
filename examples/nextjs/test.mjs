import { after, test } from "node:test";
import assert from "node:assert/strict";
import { createHmac, randomBytes } from "node:crypto";
import { once } from "node:events";
import { createRequire } from "node:module";

for (const key of Object.keys(process.env)) {
  if (key.startsWith("FCAPTCHA_") || ["REDIS_URL", "TRUSTED_PROXIES"].includes(key)) delete process.env[key];
}
process.env.FCAPTCHA_SECRET = randomBytes(32).toString("hex");
process.env.FCAPTCHA_VERIFY_SECRET = randomBytes(32).toString("hex");
process.env.FCAPTCHA_LEGACY_UNAUTH_VERIFY = "false";
process.env.TRUSTED_PROXIES = "none";
process.env.REDIS_URL = "";

const require = createRequire(import.meta.url);
const { app } = require("../../server-node/server.js");
const captcha = app.listen(0, "127.0.0.1");
await once(captcha, "listening");
process.env.FCAPTCHA_ORIGIN = `http://127.0.0.1:${captcha.address().port}`;
const { POST } = await import("./app/api/contact/route.js");
after(() => {
  captcha.closeAllConnections();
  captcha.close();
});

function token(overrides = {}) {
  const data = {
    site_key: "nextjs-example",
    jti: randomBytes(16).toString("hex"),
    timestamp: Math.floor(Date.now() / 1000),
    score: 0.05,
    ip_hash: "",
    hostname: "127.0.0.1",
    action: "",
    cdata: "",
    ...overrides,
  };
  const payload = JSON.stringify(data, Object.keys(data).sort());
  data.sig = createHmac("sha256", process.env.FCAPTCHA_SECRET).update(payload).digest("hex");
  return Buffer.from(JSON.stringify(data)).toString("base64url");
}

function submit(value) {
  return POST(new Request("http://127.0.0.1:3001/api/contact", {
    method: "POST",
    headers: { Origin: "http://127.0.0.1:3001" },
    body: new URLSearchParams(value),
  }));
}

test("accepts a valid token once and rejects a replay", async () => {
  const form = { message: "sample", fcaptcha_token: token() };
  const first = await submit(form);
  assert.equal(first.status, 200);
  assert.deepEqual(await first.json(), { accepted: true, demoOnly: true });
  assert.equal((await submit(form)).status, 403);
});

test("rejects a missing token before verification", async () => {
  assert.equal((await submit({ message: "sample" })).status, 400);
});

test("rejects a token minted for another hostname", async () => {
  assert.equal((await submit({ message: "sample", fcaptcha_token: token({ hostname: "other.example" }) })).status, 403);
});
