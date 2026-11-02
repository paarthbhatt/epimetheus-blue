# Blue Search Guard

Chromium/Brave Manifest V3 companion for the native Epimetheus Blue app.

## Protection

- Removes positively identified sponsored cards on Google, Bing, DuckDuckGo and
  Brave Search.
- Strips common campaign identifiers (`utm_*`, `gclid`, `fbclid`, etc.) from
  result links before navigation.
- Blocks a conservative built-in set of ad/tracker request domains with
  Declarative Net Request.
- Lets you block or allow the current domain. User rules are local to the
  browser profile and work on top-level navigation too.
- Adds `blue <query>` to Chromium's address bar as a provider-selectable,
  strict-safe-search shortcut.

It does not inspect page contents outside supported search pages, send browsing
history anywhere, load remote code, or claim that an unknown site is malicious.

## Install in Chromium or Brave

1. Open `chromium://extensions` or `brave://extensions`.
2. Enable **Developer mode**.
3. Select **Load unpacked**.
4. Choose this `browser-extension/` directory.

## Validate

```bash
node scripts/validate.mjs
```
