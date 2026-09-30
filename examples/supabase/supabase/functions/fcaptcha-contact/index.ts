import { createHandler } from './handler.ts';

const handler = createHandler({
  appOrigin: Deno.env.get('APP_ORIGIN') ?? '',
  captchaOrigin: Deno.env.get('FCAPTCHA_ORIGIN') ?? '',
  verifySecret: Deno.env.get('FCAPTCHA_VERIFY_SECRET') ?? '',
});
Deno.serve(handler);
