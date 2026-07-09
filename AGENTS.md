# AGENTS.md

- **Build:** `npm run build` — webpack production build → `dist/ic-stoic-identity.js` (UMD, deps external).
- **Test:** `npm test` — `node --test`, runs `test/*.test.mjs` against a fake ICRC signer (no browser needed).
- **Deploy:** `npm publish` (manual, by maintainers). `dist/` is committed and must be rebuilt before releasing.

## Layout
- `src/icrc.js` — default `StoicIdentity`: ICRC-25/27/29/34 client (JSON-RPC 2.0 over postMessage, session delegation). Wire contract: see the stoic-wallet repo's ICRC signer handoff doc.
- `src/legacy.js` — `StoicIdentityLegacy`: the old `stoic-connect` (`?authorizeApp` / `?stoicTunnel`) protocol, kept for a deprecation window. Do not extend.
- `src/index.js` — public exports only.

## Gotchas
- Runtime deps are `@dfinity/* ^3.4.3` — the last releases under the `@dfinity` scope. The line is deprecated in favor of `@icp-sdk/core` (same code, subpath imports, needs exports-map-aware bundlers); switching is a follow-up rename once consumers are ready.
- `src/package.json` (`type: module`) exists so node can run the ESM sources in tests; don't delete it.
- The signer sends blobs as structured-cloned `Uint8Array` and `expiration` as a base-10 string; `toBytes()` in `src/icrc.js` also tolerates hex/base64.
