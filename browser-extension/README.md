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
- Checks up to 200 unique visible search-result domains at a time against the
  desktop app's active feed lists, using Chromium Native Messaging.
- Adds `blue <query>` to Chromium's address bar as a provider-selectable,
  strict-safe-search shortcut.

It does not inspect page contents outside supported search pages, send browsing
history anywhere, load remote code, or claim that an unknown site is malicious.

## Browser/desktop boundary

The extension intentionally does **not** copy the full desktop blocklist (about
77,000 entries and potentially more as feeds change) into Declarative Net
Request. DNR contains only the small built-in ruleset plus explicit user block
and allow entries. Native Messaging checks apply to links shown on supported
search pages; the desktop DNS shield applies the full feed to network requests.

The read-only native bridge exposes status, domain verdicts, and recent
findings. It cannot change settings, files, history, feeds, or browser state.

## Stable extension identity

The manifest contains only an RSA DER **public** key. Its stable Chromium
extension ID is:

```text
alfkkfmnmngogkkaenefploocfbdooji
```

The same value is machine-readable in [`EXTENSION_ID`](EXTENSION_ID) for the
native-host installer. No private key is stored in this repository.

## Install in Chromium or Brave

1. Open `chrome://extensions` or `brave://extensions`.
2. Enable **Developer mode**.
3. Select **Load unpacked**.
4. Choose this `browser-extension/` directory.

The desktop installer must register the Native Messaging host
`com.epimetheus.blue` for the extension ID above. If it is not registered, the
popup reports **Desktop: Disconnected** and browser-only protection continues.

## Validate

```bash
node scripts/validate.mjs
```
