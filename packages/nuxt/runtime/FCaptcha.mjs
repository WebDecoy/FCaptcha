import { defineComponent, h, onBeforeUnmount, onMounted, ref, watch } from 'vue';
import { useRuntimeConfig } from '#app';
import { configureServer, loadClient } from './load-client.mjs';

export default defineComponent({
  name: 'FCaptcha',
  props: {
    siteKey: String,
    serverUrl: String,
    scriptSrc: String,
    theme: { type: String, default: 'light' },
    lang: String,
  },
  emits: ['verify', 'expire', 'error'],
  setup(props, { emit }) {
    const element = ref(null);
    const defaults = useRuntimeConfig().public.fcaptcha || {};
    let stop;
    onMounted(() => {
      stop = watch(() => [props.siteKey, props.serverUrl, props.scriptSrc, props.theme, props.lang], async (_, __, onCleanup) => {
        let active = true;
        let api;
        let widgetId;
        onCleanup(() => {
          active = false;
          if (api && widgetId !== undefined) api.destroy(widgetId);
        });
        try {
          const siteKey = props.siteKey || defaults.siteKey;
          if (!siteKey) throw new Error('FCaptcha requires a public siteKey');
          api = await loadClient(props.scriptSrc || defaults.scriptSrc || '/fcaptcha.js');
          if (!active || !element.value) return;
          configureServer(api, props.serverUrl || defaults.serverUrl);
          widgetId = api.render(element.value, {
            siteKey,
            theme: props.theme,
            lang: props.lang,
            callback: token => { if (active) emit('verify', token); },
            expiredCallback: () => { if (active) emit('expire'); },
            errorCallback: error => { if (active) emit('error', error); },
          });
        } catch (error) {
          if (active) emit('error', error);
        }
      }, { immediate: true });
    });
    onBeforeUnmount(() => stop?.());
    return () => h('div', { ref: element });
  },
});
