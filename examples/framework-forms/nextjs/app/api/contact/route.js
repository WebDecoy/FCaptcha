import { contactHandler } from '../../../../shared/contact.mjs';
export const runtime = 'nodejs';
export async function POST(request) {
  try {
    return await contactHandler({ origin: process.env.APP_ORIGIN,
      captchaOrigin: process.env.FCAPTCHA_ORIGIN, verifySecret: process.env.FCAPTCHA_VERIFY_SECRET })(request);
  } catch { return Response.json({ error: 'server_configuration_error' }, { status: 503 }); }
}
