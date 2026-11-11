# `@webdecoy/fcaptcha-react`

The official React 18/19 component for FCaptcha's interactive widget.

```jsx
import { FCaptcha } from '@webdecoy/fcaptcha-react';

export function ContactProtection() {
  return (
    <FCaptcha
      siteKey="contact-form"
      serverUrl="https://captcha.example.com"
      scriptSrc="https://captcha.example.com/fcaptcha.js"
      onVerify={(token) => submitToYourBackend(token)}
      onError={(error) => console.error(error)}
    />
  );
}
```

The token is not a verdict by itself. Send it to your backend and verify it with
FCaptcha's `/siteverify` endpoint before performing the protected action.

`serverUrl` configures a process-wide browser global. Every component on a page
must use the same value; the wrapper reports conflicting values through
`onError` rather than silently redirecting another widget's requests.

The package loads `scriptSrc` once per resolved URL, is safe to import during
server-side rendering, and cleans up its widget when React unmounts it.
