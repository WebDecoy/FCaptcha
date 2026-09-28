"use client";
import { useRef, useState } from 'react';
import { submitContact } from '../../shared/browser.js';
export default function Page() {
  const pending = useRef(false);
  const [busy, setBusy] = useState(false); const [status, setStatus] = useState('');
  async function submit(event) {
    event.preventDefault();
    if (pending.current) return;
    const message = String(new FormData(event.currentTarget).get('message') || '');
    pending.current = true; setBusy(true); setStatus('');
    try { setStatus(await submitContact(message)); }
    catch (error) { setStatus(error.message || 'Unable to submit.'); }
    finally { pending.current = false; setBusy(false); }
  }
  return <main style={{maxWidth:'42rem',margin:'4rem auto',fontFamily:'system-ui',padding:'1rem'}}>
    <h1>Your Next.js form, server-verified.</h1><p>Local demo. Messages are neither sent nor stored.</p>
    <form onSubmit={submit}><label htmlFor="message">Test message</label>
      <textarea id="message" name="message" required maxLength={2000} style={{display:'block',width:'100%',minHeight:'8rem',margin:'1rem 0'}} />
      <button disabled={busy}>{busy ? 'Verifying…' : 'Verify and submit'}</button>
    </form><p role="status" aria-live="polite">{status}</p>
  </main>;
}
