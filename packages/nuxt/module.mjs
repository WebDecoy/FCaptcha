import { addComponent, createResolver, defineNuxtModule } from '@nuxt/kit';

export default defineNuxtModule({
  meta: { name: '@webdecoy/fcaptcha-nuxt', configKey: 'fcaptcha', compatibility: { nuxt: '^4.0.0' } },
  defaults: { siteKey: '', serverUrl: '', scriptSrc: '' },
  setup(options, nuxt) {
    const resolver = createResolver(import.meta.url);
    // Only public browser configuration is copied. Never put verification secrets here.
    nuxt.options.runtimeConfig.public.fcaptcha = {
      siteKey: options.siteKey,
      serverUrl: options.serverUrl,
      scriptSrc: options.scriptSrc || `${options.serverUrl.replace(/\/+$/, '')}/fcaptcha.js`,
      ...nuxt.options.runtimeConfig.public.fcaptcha,
    };
    addComponent({ name: 'FCaptcha', filePath: resolver.resolve('./runtime/FCaptcha.mjs'), mode: 'client' });
  },
});
