# Stoic Identity

Stoic Identity is an ICP identity that works directly with `@dfinity/agent` for signing canister messages using your [StoicWallet.com](https://www.stoicwallet.com) account.

**As of v7**, `StoicIdentity` connects to the Stoic wallet over the [ICRC signer standards](https://github.com/dfinity/wg-identity-authentication) — ICRC-25 (permissions), ICRC-27 (accounts), ICRC-29 (postMessage transport) and ICRC-34 (delegation). Instead of routing every canister call through the wallet, the wallet issues a short-lived **session delegation** and your app signs calls locally. That means:

- **One popup at login** — no wallet round-trip per canister call.
- **Sessions expire after at most 15 minutes** — call `StoicIdentity.connect()` again to renew (see below).
- Permissions are granted once and persist; users can review/revoke them in Stoic's Applications view.
- Optionally **scope the delegation to specific canisters** via `targets` (the target canisters must list your origin in `icrc28_trusted_origins`).

The previous `stoic-connect` implementation is still exported as `StoicIdentityLegacy` (drop-in for the old API) for a deprecation window.

## Installation

```
npm i ic-stoic-identity --save
```

## Usage

```javascript
import { StoicIdentity } from "ic-stoic-identity";

// Try to restore an existing (unexpired) session first
let identity = await StoicIdentity.load();
if (identity === false) {
  // No valid session — connect (opens the Stoic popup; call this from a click handler)
  identity = await StoicIdentity.connect();
}

// The connected principal
console.log(identity.getPrincipal().toText());

// The wallet's accounts:
// [{ owner: "<principal>", subaccount?: "<32-byte hex>", address: "<ICP account-id hex>" }]
const accounts = await identity.accounts();

// Use it with an agent — calls are signed locally, no popup
const actor = Actor.createActor(idlFactory, {
  agent: new HttpAgent({ identity }),
  canisterId,
});

// Disconnect (clears the stored session)
StoicIdentity.disconnect();
```

### Session expiry

The signer caps delegations at **15 minutes** (`identity.sessionExpiry` is the exact `Date`; `identity.isValid()` tells you if it is still usable). When the session expires, calls reject with a clear error — catch it and call `StoicIdentity.connect()` again from a user interaction. Because the permission was already granted, reconnecting is quick.

```javascript
if (!identity.isValid()) {
  identity = await StoicIdentity.connect();
}
```

### Options

```javascript
await StoicIdentity.connect("https://www.stoicwallet.com", {
  // Scope the delegation to specific canisters. Each target canister must
  // implement icrc28_trusted_origins and include your origin.
  targets: ["ryjl3-tyaaa-aaaaa-aaaba-cai"],
  // Requested TTL in nanoseconds (the signer caps this at 15 minutes).
  maxTimeToLive: 900000000000n,
  // Bring your own session key (default: a fresh Ed25519 key).
  sessionKey: myEd25519KeyIdentity,
});
```

## Migrating from v6

| | v6 (legacy) | v7 (ICRC) |
|---|---|---|
| Login | `?authorizeApp` popup | ICRC-29 handshake + ICRC-34 delegation popup |
| Canister calls | popup/iframe round-trip per call | signed locally with the session delegation |
| Session lifetime | indefinite | ≤ 15 minutes, renew with `connect()` |
| `accounts()` | JSON **string** from the wallet | **array** of `{ owner, subaccount?, address }` |
| `connect(host, transportMethod)` | 2nd arg = `"popup"`/`"iframe"` | 2nd arg = options object |

If you are not ready to migrate, the old implementation is unchanged:

```javascript
import { StoicIdentityLegacy as StoicIdentity } from "ic-stoic-identity";
```

The legacy path will be removed in a future major release.

## Development

```
npm install
npm test        # node --test (fake-signer protocol tests)
npm run build   # webpack → dist/ic-stoic-identity.js (UMD)
```
