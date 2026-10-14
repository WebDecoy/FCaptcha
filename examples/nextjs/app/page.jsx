"use client";

import Script from "next/script";
import { useEffect, useRef, useState } from "react";

const captchaOrigin = process.env.NEXT_PUBLIC_FCAPTCHA_ORIGIN || "http://127.0.0.1:3000";
const siteKey = process.env.NEXT_PUBLIC_FCAPTCHA_SITE_KEY || "nextjs-example";

export default function ContactPage() {
  const containerRef = useRef(null);
  const widgetIdRef = useRef(null);
  const [scriptReady, setScriptReady] = useState(false);
  const [busy, setBusy] = useState(false);
  const [status, setStatus] = useState("");

  // The widget owns its DOM and listeners, so mount and destroy it with this component.
  useEffect(() => {
    if (!scriptReady || !containerRef.current) return;
    window.FCaptcha.configure({ serverUrl: captchaOrigin });
    const widgetId = window.FCaptcha.render(containerRef.current, { siteKey });
    widgetIdRef.current = widgetId;
    return () => {
      window.FCaptcha.destroy(widgetId);
      widgetIdRef.current = null;
    };
  }, [scriptReady]);

  async function submit(event) {
    event.preventDefault();
    if (busy) return;
    setBusy(true);
    setStatus("");
    try {
      const response = await fetch("/api/contact", {
        method: "POST",
        body: new FormData(event.currentTarget),
      });
      setStatus(response.ok
        ? "Verified. This demo did not send or store your message."
        : response.status >= 500
          ? "Verification is unavailable. Check the local FCaptcha server."
          : "Verification failed. Please try again.");
    } catch {
      setStatus("Verification is unavailable. Check the local FCaptcha server.");
    } finally {
      if (widgetIdRef.current) window.FCaptcha.reset(widgetIdRef.current);
      setBusy(false);
    }
  }

  return (
    <main style={{ maxWidth: 520, margin: "4rem auto", fontFamily: "system-ui", padding: "0 1rem" }}>
      <h1>FCaptcha with Next.js</h1>
      <p>Try a server-verified form. Messages are neither sent nor stored.</p>
      <form onSubmit={submit}>
        <label htmlFor="message">Sample message</label>
        <textarea id="message" name="message" required maxLength={2000} style={{ display: "block", width: "100%", minHeight: 100, margin: "0.5rem 0 1rem" }} />
        <div ref={containerRef} />
        <button type="submit" disabled={!scriptReady || busy} style={{ marginTop: "1rem" }}>
          {busy ? "Verifying…" : "Submit"}
        </button>
      </form>
      <p role="status" aria-live="polite">{status}</p>
      <Script
        src={`${captchaOrigin}/fcaptcha.js`}
        onReady={() => setScriptReady(true)}
        onError={() => setStatus("Could not load the local FCaptcha widget.")}
      />
    </main>
  );
}
