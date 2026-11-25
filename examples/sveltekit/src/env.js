import { defineEnvVars } from '@sveltejs/kit/env';

export const variables = defineEnvVars({
  FCAPTCHA_ORIGIN: { schema: (value) => value },
  FCAPTCHA_PUBLIC_ORIGIN: { schema: (value) => value },
  FCAPTCHA_VERIFY_SECRET: { schema: (value) => value },
});
