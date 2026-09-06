---
name: threat-sveltekit
description: How MW-SEC and pytm rules manifest in SvelteKit fronts talking to an internal API.
---

# SvelteKit stack: evidence per rule

Model W fronts are SvelteKit servers proxying to the Django API over the
cluster network (`http://api`), forwarding the browser session cookie.

- **Routes**: `+server.ts` exports (`GET`, `POST`...), `+page.server.ts`
  `load` and `actions`. Mutating = `POST/PUT/PATCH/DELETE` exports or
  form `actions`.
- **MW-SEC-001**: an action/handler that mutates without checking
  `locals.user`/session; the API may enforce auth downstream -- say so
  and mark `depends_on` on both sides.
- **MW-SEC-010 plaintext internal hop**: `fetch("http://api/...")` with
  the `cookie` header forwarded. `ok` only with an https/mTLS internal
  endpoint or a derived short-lived token.
- **Public env exposure**: `$env/static/public` / `PUBLIC_*` variables
  reach the browser; a secret there is MW-SEC-009.
- **MW-SEC-005**: `@sentry/sveltekit` `sendDefaultPii`, `beforeSend`,
  `console.log` of request bodies in server code.
- **MW-SEC-002 uploads**: `formData.get("file")` forwarded without size
  or type checks.
- **MW-SEC-006 webhooks**: `+server.ts` receiving provider callbacks
  without signature verification.
- **Browser storage**: `localStorage`/`sessionStorage` writes of tokens
  or PII are `store:` elements with `credential`/items.
- **Third-party scripts**: GTM/analytics loaded without consent gating
  (`gtm.js`, `matomo`), `PUBLIC_GTM_ID`.

`depends_on` typically includes `src/hooks.server.ts`, the route file
and `svelte.config.js` / `vite.config.ts` when CSP or adapters matter.
