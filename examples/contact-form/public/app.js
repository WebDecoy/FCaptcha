const $ = id => document.getElementById(id);
const copy = {
  ja: {
    eyebrow: 'セルフホスト · サーバー側検証', title: '画像パズルなしのお問い合わせフォーム。',
    intro: 'メッセージを入力して、FCaptchaで保護された送信を試せます。',
    label: 'テストメッセージ', placeholder: 'テスト用の文章を入力してください',
    submit: '検証して送信', loading: '準備中…', checking: '検証しています…',
    note: 'ローカルのデモです。メッセージは保存・送信されません。個人情報を入力しないでください。',
    success: 'サーバー側の検証に成功しました。デモのためメッセージは送信していません。',
    rejected: '検証を通過できませんでした。少し待ってから、もう一度お試しください。',
    unavailable: '検証サーバーに接続できません。ローカルサーバーを確認してください。'
  },
  en: {
    eyebrow: 'SELF-HOSTED · SERVER-VERIFIED', title: 'A contact form without image puzzles.',
    intro: 'Write a test message and try a submission protected by FCaptcha.',
    label: 'Test message', placeholder: 'Write a sample message',
    submit: 'Verify and submit', loading: 'Loading…', checking: 'Verifying…',
    note: 'Local demo. Messages are neither stored nor sent. Do not enter personal information.',
    success: 'Server verification passed. No message was sent because this is a demo.',
    rejected: 'Verification did not pass. Wait a moment and try again.',
    unavailable: 'Verification service unavailable. Check your local servers.'
  }
};
let lang = 'ja', ready = false, busy = false, statusKey = '';
function render() {
  const c = copy[lang];
  document.documentElement.lang = lang;
  for (const id of ['eyebrow', 'title', 'intro', 'note']) $(id).textContent = c[id];
  $('message-label').textContent = c.label;
  $('message').placeholder = c.placeholder;
  $('submit').textContent = busy ? c.checking : ready ? c.submit : c.loading;
  $('submit').disabled = !ready || busy;
  $('language').textContent = lang === 'ja' ? 'English' : '日本語';
  $('status').textContent = statusKey ? c[statusKey] : '';
}
$('language').addEventListener('click', () => { lang = lang === 'ja' ? 'en' : 'ja'; render(); });
let config;
try {
  const response = await fetch('/config');
  if (!response.ok) throw new Error('Configuration unavailable');
  config = await response.json();
  await new Promise((resolve, reject) => {
    const script = document.createElement('script');
    script.src = `${config.captchaOrigin}/fcaptcha.js`;
    script.onload = resolve; script.onerror = reject;
    document.head.append(script);
  });
  FCaptcha.configure({ serverUrl: config.captchaOrigin });
  ready = true;
} catch { statusKey = 'unavailable'; }
render();
$('contact').addEventListener('submit', async event => {
  event.preventDefault();
  if (!ready || busy) return;
  busy = true; statusKey = ''; render();
  try {
    const result = await FCaptcha.execute(config.siteKey, { action: 'contact', lang });
    if (!result.success || !result.token) { statusKey = 'rejected'; return; }
    const response = await fetch('/contact', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ message: $('message').value, token: result.token }),
      signal: AbortSignal.timeout(8000)
    });
    const body = await response.json();
    statusKey = response.ok && body.accepted === true ? 'success' :
      response.status >= 500 ? 'unavailable' : 'rejected';
  } catch { statusKey = 'unavailable'; }
  finally { busy = false; render(); }
});
