import { Principal } from "@dfinity/principal";
import { SignIdentity } from "@dfinity/agent";
import {
  Delegation,
  DelegationChain,
  DelegationIdentity,
  Ed25519KeyIdentity,
} from "@dfinity/identity";
import jsSha256 from "js-sha256";

const { sha224 } = jsSha256;

const STOIC_ORIGIN = "https://www.stoicwallet.com";
const STORAGE_KEY = "_scIcrcApp";
const STATUS_POLL_MS = 750;
const HANDSHAKE_TIMEOUT_MS = 120000;
const NS_PER_MS = BigInt(1000000);
const POPUP_FEATURES =
  "width=500,height=700,toolbar=no,menubar=no,scrollbars=yes,resizable=yes";

// ---------------------------------------------------------------------------
// Byte helpers — the signer sends blobs as structured-cloned Uint8Array and
// accepts raw bytes / hex / base64 inbound; we tolerate all three outbound
// too so the wire encoding can never break us.
// ---------------------------------------------------------------------------
function toBytes(value, field) {
  if (value instanceof Uint8Array) return value;
  if (value instanceof ArrayBuffer) return new Uint8Array(value);
  if (ArrayBuffer.isView(value))
    return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
  if (Array.isArray(value)) return new Uint8Array(value);
  if (typeof value === "object" && value !== null)
    return new Uint8Array(Object.values(value));
  if (typeof value === "string") {
    if (/^[0-9a-fA-F]*$/.test(value) && value.length % 2 === 0)
      return hexToBytes(value);
    return base64ToBytes(value);
  }
  throw new Error("Unable to decode bytes for " + field);
}

// Uint8Array views can sit inside a larger ArrayBuffer; @dfinity/identity
// wants exact ArrayBuffers.
function toExactBuffer(bytes) {
  return bytes.slice().buffer;
}

function bytesToHex(bytes) {
  return [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function hexToBytes(hex) {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2)
    out[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  return out;
}

function base64ToBytes(b64) {
  const bin =
    typeof atob !== "undefined"
      ? atob(b64)
      : Buffer.from(b64, "base64").toString("binary");
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

// ---------------------------------------------------------------------------
// ICP account identifier (address) = crc32(h) . h, h = sha224("\x0Aaccount-id" . principal . subaccount)
// ---------------------------------------------------------------------------
const CRC_TABLE = (() => {
  const table = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    table[n] = c >>> 0;
  }
  return table;
})();

function crc32(bytes) {
  let crc = 0xffffffff;
  for (let i = 0; i < bytes.length; i++)
    crc = CRC_TABLE[(crc ^ bytes[i]) & 0xff] ^ (crc >>> 8);
  return (crc ^ 0xffffffff) >>> 0;
}

function principalToAccountId(principalText, subaccount) {
  const principal = Principal.fromText(principalText);
  const hash = sha224.create();
  hash.update(new TextEncoder().encode("\x0Aaccount-id"));
  hash.update(principal.toUint8Array());
  hash.update(subaccount || new Uint8Array(32));
  const h = new Uint8Array(hash.array());
  const crc = crc32(h);
  const out = new Uint8Array(4 + h.length);
  out[0] = (crc >>> 24) & 0xff;
  out[1] = (crc >>> 16) & 0xff;
  out[2] = (crc >>> 8) & 0xff;
  out[3] = crc & 0xff;
  out.set(h, 4);
  return bytesToHex(out);
}

// ---------------------------------------------------------------------------
// JSON-RPC 2.0 postMessage transport with the ICRC-29 handshake
// ---------------------------------------------------------------------------
class StoicTransport {
  constructor(signerWindow, origin) {
    this._window = signerWindow;
    this._origin = origin;
    this._pending = new Map();
    this._nextId = 1;
    this._aborted = null;
    this._closed = false;
    this._onMessage = (e) => {
      if (e.origin !== this._origin) return;
      if (e.source !== this._window) return;
      const d = e.data;
      if (!d || d.jsonrpc !== "2.0" || d.id === undefined || d.id === null) return;
      const pending = this._pending.get(d.id);
      if (!pending) return;
      this._pending.delete(d.id);
      if (d.error) {
        const err = new Error(
          "Stoic signer error " + d.error.code + ": " + d.error.message
        );
        err.code = d.error.code;
        pending.reject(err);
      } else {
        pending.resolve(d.result);
      }
    };
    window.addEventListener("message", this._onMessage);
    this._watchdog = setInterval(() => {
      if (this._window.closed)
        this._abort(new Error("Stoic signer window was closed"));
    }, 500);
  }

  static establish(origin) {
    const signerWindow = window.open(origin, "stoic-icrc-signer", POPUP_FEATURES);
    if (!signerWindow) {
      return Promise.reject(
        new Error(
          "Failed to open the Stoic signer window. It may have been blocked by the browser — call connect() from a user interaction."
        )
      );
    }
    const transport = new StoicTransport(signerWindow, origin);
    return transport._handshake().then(
      () => transport,
      (err) => {
        transport.close();
        throw err;
      }
    );
  }

  _handshake() {
    return new Promise((resolve, reject) => {
      let settled = false;
      const deadline = Date.now() + HANDSHAKE_TIMEOUT_MS;
      const attempt = () => {
        if (settled) return;
        if (this._aborted) {
          settled = true;
          return reject(this._aborted);
        }
        if (Date.now() > deadline) {
          settled = true;
          return reject(
            new Error("Timed out waiting for the Stoic signer to become ready (icrc29_status)")
          );
        }
        this.call("icrc29_status")
          .then((result) => {
            if (!settled && result === "ready") {
              settled = true;
              clearTimeout(this._handshakeTimer);
              resolve();
            }
          })
          .catch(() => {});
        this._handshakeTimer = setTimeout(attempt, STATUS_POLL_MS);
      };
      attempt();
    });
  }

  call(method, params) {
    if (this._closed)
      return Promise.reject(this._aborted || new Error("Transport is closed"));
    return new Promise((resolve, reject) => {
      const id = this._nextId++;
      this._pending.set(id, { resolve, reject });
      const message = { jsonrpc: "2.0", id, method };
      if (params !== undefined) message.params = params;
      this._window.postMessage(message, this._origin);
    });
  }

  _abort(error) {
    this._aborted = error;
    const pending = [...this._pending.values()];
    this._pending.clear();
    pending.forEach(({ reject }) => reject(error));
    this.close();
  }

  close() {
    if (this._closed) return;
    this._closed = true;
    clearInterval(this._watchdog);
    clearTimeout(this._handshakeTimer);
    window.removeEventListener("message", this._onMessage);
    const pending = [...this._pending.values()];
    this._pending.clear();
    pending.forEach(({ reject }) =>
      reject(this._aborted || new Error("Transport is closed"))
    );
    try {
      if (!this._window.closed) this._window.close();
    } catch (e) {
      // cross-origin close can throw in some browsers; the window stays open
    }
  }
}

// ---------------------------------------------------------------------------
// ICRC-34 response → DelegationChain
// ---------------------------------------------------------------------------
function chainFromIcrc34(result) {
  if (!result || !Array.isArray(result.signerDelegation) || !result.publicKey)
    throw new Error("Malformed icrc34_delegation response from the signer");
  return DelegationChain.fromDelegations(
    result.signerDelegation.map((sd) => ({
      delegation: new Delegation(
        toExactBuffer(toBytes(sd.delegation.pubkey, "delegation.pubkey")),
        BigInt(sd.delegation.expiration),
        sd.delegation.targets
          ? sd.delegation.targets.map((t) => Principal.fromText(t))
          : undefined
      ),
      signature: toExactBuffer(toBytes(sd.signature, "delegation.signature")),
    })),
    toExactBuffer(toBytes(result.publicKey, "publicKey"))
  );
}

function chainExpirationNs(chain) {
  return chain.delegations.reduce(
    (min, sd) =>
      min === null || sd.delegation.expiration < min
        ? sd.delegation.expiration
        : min,
    null
  );
}

function mapAccounts(result) {
  const accounts = (result && result.accounts) || [];
  return accounts.map((account) => {
    const subaccount = account.subaccount
      ? toBytes(account.subaccount, "account.subaccount")
      : undefined;
    const mapped = {
      owner: typeof account.owner === "string" ? account.owner : account.owner.toText(),
      address: principalToAccountId(
        typeof account.owner === "string" ? account.owner : account.owner.toText(),
        subaccount
      ),
    };
    if (subaccount) mapped.subaccount = bytesToHex(subaccount);
    return mapped;
  });
}

// ---------------------------------------------------------------------------
// The identity
// ---------------------------------------------------------------------------
export class StoicIdentity extends SignIdentity {
  constructor(sessionKey, chain, accounts, origin) {
    super();
    this._sessionKey = sessionKey;
    this._chain = chain;
    this._inner = DelegationIdentity.fromDelegation(sessionKey, chain);
    this._accounts = accounts || [];
    this._origin = origin;
  }

  /**
   * Connect to the Stoic signer over ICRC-25/27/29/34 and return an identity
   * backed by a local session delegation. Must be called from a user
   * interaction (it opens a popup).
   *
   * options.targets        — canister-id strings/Principals for a scoped
   *                          delegation (requires icrc28_trusted_origins on
   *                          every target canister).
   * options.maxTimeToLive  — requested TTL in nanoseconds (signer caps at 15 min).
   * options.sessionKey     — supply your own session SignIdentity (default:
   *                          a fresh Ed25519 key).
   */
  static async connect(host, options = {}) {
    const origin = new URL(host || STOIC_ORIGIN).origin;
    const transport = await StoicTransport.establish(origin);
    try {
      await transport.call("icrc25_request_permissions", {
        scopes: [{ method: "icrc27_accounts" }, { method: "icrc34_delegation" }],
      });
      const accountsResult = await transport.call("icrc27_accounts");
      const sessionKey = options.sessionKey || Ed25519KeyIdentity.generate();
      const params = {
        publicKey: bytesToHex(new Uint8Array(sessionKey.getPublicKey().toDer())),
      };
      if (options.targets)
        params.targets = options.targets.map((t) =>
          typeof t === "string" ? t : t.toText()
        );
      if (options.maxTimeToLive !== undefined)
        params.maxTimeToLive = options.maxTimeToLive.toString();
      const delegationResult = await transport.call("icrc34_delegation", params);
      const chain = chainFromIcrc34(delegationResult);
      const accounts = mapAccounts(accountsResult);
      const identity = new StoicIdentity(sessionKey, chain, accounts, origin);
      identity._save();
      return identity;
    } finally {
      transport.close();
    }
  }

  /**
   * Restore a previous session from localStorage. Resolves false if there is
   * none, it was created for a different signer origin, its session key can
   * only be restored for Ed25519, or the delegation has (nearly) expired —
   * in which case call connect() again.
   */
  static load(host) {
    return new Promise((resolve) => {
      try {
        const stored = JSON.parse(localStorage.getItem(STORAGE_KEY));
        if (!stored || stored.version !== 1) return resolve(false);
        const origin = new URL(host || STOIC_ORIGIN).origin;
        if (stored.origin !== origin) return resolve(false);
        const sessionKey = Ed25519KeyIdentity.fromParsedJson(stored.sessionKey);
        const chain = DelegationChain.fromJSON(stored.chain);
        const identity = new StoicIdentity(
          sessionKey,
          chain,
          stored.accounts,
          origin
        );
        if (!identity.isValid()) return resolve(false);
        resolve(identity);
      } catch (e) {
        resolve(false);
      }
    });
  }

  static disconnect() {
    try {
      localStorage.removeItem(STORAGE_KEY);
    } catch (e) {
      // storage unavailable — nothing to clear
    }
  }

  _save() {
    try {
      localStorage.setItem(
        STORAGE_KEY,
        JSON.stringify({
          version: 1,
          origin: this._origin,
          sessionKey: this._sessionKey.toJSON(),
          chain: this._chain.toJSON(),
          accounts: this._accounts,
        })
      );
    } catch (e) {
      // storage unavailable (private mode etc.) — session just won't persist
    }
  }

  getPublicKey() {
    return this._inner.getPublicKey();
  }

  sign(blob) {
    return this._inner.sign(blob);
  }

  getDelegation() {
    return this._inner.getDelegation();
  }

  /**
   * The connected Stoic accounts:
   * [{ owner: <principal text>, subaccount?: <32-byte hex>, address: <ICP account-id hex> }]
   * (Kept async for compatibility with the legacy accounts() API.)
   */
  accounts() {
    return Promise.resolve(this._accounts);
  }

  /** Expiry of the session delegation as a Date. */
  get sessionExpiry() {
    const ns = chainExpirationNs(this._chain);
    return ns === null ? null : new Date(Number(ns / NS_PER_MS));
  }

  /** True while the delegation is valid for at least bufferMs more (default 60s). */
  isValid(bufferMs = 60000) {
    const ns = chainExpirationNs(this._chain);
    if (ns === null) return false;
    return ns > BigInt(Date.now() + bufferMs) * NS_PER_MS;
  }

  transformRequest(request) {
    if (!this.isValid(0)) {
      return Promise.reject(
        new Error(
          "The Stoic session delegation has expired — call StoicIdentity.connect() again to renew it."
        )
      );
    }
    return this._inner.transformRequest(request);
  }
}
