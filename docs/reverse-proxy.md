# Running the panel behind a reverse proxy

This note covers the deployments where a reverse proxy terminates TLS in
front of the panel: the browser reaches the proxy over HTTPS, and the proxy
talks plain HTTP to the panel on localhost or the internal network. The
panel itself never sees TLS in that setup, so three settings matter. Get
them wrong and the panel loads but login or the live status (WebSocket)
breaks.

## 1. Secure session cookie: `webSecureCookie`

When the panel serves HTTPS directly (a certificate is configured), the
login cookie gets the `Secure` flag automatically. Behind a proxy that
terminates TLS, the panel serves plain HTTP and cannot tell the browser
used HTTPS, so enable it explicitly:

Settings → Certificates → **Secure session cookie** (`webSecureCookie`).

Only enable it if the browser really reaches the panel over HTTPS,
otherwise the browser will refuse to send the cookie and login will loop.

## 2. WebSocket origin: `wsTrustedOrigins`

The WebSocket origin check compares the full origin — scheme, host and
effective port. Behind a proxy the panel sees its own origin as
`http://…` (plain HTTP, `r.TLS == nil`), while the browser's Origin is
the external `https://…`, so the two never match on their own. Tell the
panel which external origins are allowed:

Settings → Certificates → **Trusted WebSocket origins**
(`wsTrustedOrigins`), comma-separated full origins, for example:

```
https://panel.example.com
```

or, when the public address has a non-default port:

```
https://panel.example.com:8443
```

Rules:

- Each entry must be a complete origin: scheme, host and port (the port
  may be omitted only when it is the scheme default, 443 for HTTPS and
  80 for HTTP). A bare host never matches, and a trusted entry never
  covers a different port.
- Leave the field empty for same-origin-only deployments (no proxy, or a
  proxy on the same address).
- Changes take effect immediately; no panel restart is needed.

## 3. Preserve the external Host at the proxy

The proxy must forward the Host header the browser used. Without it the
panel sees its own backend address, and two checks compare against the
wrong name:

- the CSRF check requires the `Origin` (or `Referer`) header to match the
  request Host, so logins and panel API calls are refused with 403;
- the WebSocket origin check compares against the backend host instead of
  the public name.

nginx:

```nginx
location / {
    proxy_pass http://127.0.0.1:2053;
    proxy_http_version 1.1;
    proxy_set_header Host $host;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
}
```

Apache:

```apache
ProxyPreserveHost On
ProxyPass / http://127.0.0.1:2053/
ProxyPassReverse / http://127.0.0.1:2053/
```

Caddy's `reverse_proxy` passes the Host through by default.

## What not to do

Do not "fix" a mismatch by making the panel trust `X-Forwarded-Proto`
or `X-Forwarded-Host` from the client. Any client can send those
headers, so trusting them would let an HTTP attacker make the panel
believe a request came over HTTPS (wrong cookie flags, wrong origin
decisions). The panel deliberately never reads those headers for
security decisions; the three settings above are the explicit,
operator-controlled way to describe the proxy setup.

## HSTS

`Strict-Transport-Security` is sent only when the panel is served over
HTTPS — directly, or via a proxy with `webSecureCookie` enabled — so
plain-HTTP deployments are unaffected. The max-age is configurable
(`webHSTSMaxAge`, default 31536000 seconds, 0 disables the header).
