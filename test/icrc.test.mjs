import { test, beforeEach } from "node:test";
import assert from "node:assert/strict";
import { Principal } from "@dfinity/principal";
import { requestIdOf } from "@dfinity/agent";
import { DelegationChain, Ed25519KeyIdentity } from "@dfinity/identity";
import { StoicIdentity, StoicIdentityLegacy } from "../src/index.js";

const SIGNER_ORIGIN = "https://www.stoicwallet.com";

// --- fake browser environment -------------------------------------------------

function hexToBytes(hex) {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2)
    out[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  return out;
}

function makeEnv() {
  const listeners = new Set();
  const win = {
    addEventListener: (type, fn) => type === "message" && listeners.add(fn),
    removeEventListener: (type, fn) => type === "message" && listeners.delete(fn),
    open: (url, name, features) => {
      win.opened.push({ url, name, features });
      return win.signerWindow;
    },
    opened: [],
    dispatch: (event) => [...listeners].forEach((fn) => fn(event)),
    signerWindow: null,
  };
  const storage = new Map();
  const localStorage = {
    getItem: (k) => (storage.has(k) ? storage.get(k) : null),
    setItem: (k, v) => storage.set(k, String(v)),
    removeItem: (k) => storage.delete(k),
  };
  return { win, localStorage };
}

// A fake Stoic signer implementing the wire protocol from the handoff doc.
// `blobEncoding` controls the OUTBOUND blob representation so we can prove
// the client tolerates Uint8Array (the real signer), hex, and base64.
function makeFakeSigner(env, { blobEncoding = "bytes", readyAfterPolls = 0, expiresAt } = {}) {
  const rootKey = Ed25519KeyIdentity.generate();
  const state = { rootKey, requests: [], statusPolls: 0 };

  const encodeBlob = (hex) => {
    if (blobEncoding === "hex") return hex;
    if (blobEncoding === "base64") return Buffer.from(hex, "hex").toString("base64");
    return hexToBytes(hex);
  };

  const signerWindow = {
    closed: false,
    close() {
      this.closed = true;
    },
    postMessage(message /*, targetOrigin */) {
      state.requests.push(message);
      queueMicrotask(async () => {
        if (!message || message.jsonrpc !== "2.0") return;
        const reply = (result) =>
          env.win.dispatch({
            origin: SIGNER_ORIGIN,
            source: signerWindow,
            data: { jsonrpc: "2.0", id: message.id, result },
          });
        switch (message.method) {
          case "icrc29_status":
            state.statusPolls++;
            if (state.statusPolls > readyAfterPolls) reply("ready");
            return;
          case "icrc25_request_permissions":
            reply({
              scopes: message.params.scopes.map((s) => ({
                scope: s,
                state: "granted",
              })),
            });
            return;
          case "icrc27_accounts":
            reply({
              accounts: [
                { owner: rootKey.getPrincipal().toText() },
                {
                  owner: rootKey.getPrincipal().toText(),
                  subaccount: hexToBytes("01".padStart(64, "0")),
                },
              ],
            });
            return;
          case "icrc34_delegation": {
            // The client must send the session key DER as hex (inbound blobs
            // may be raw/hex/base64; we pin our client to hex).
            assert.equal(typeof message.params.publicKey, "string");
            assert.match(message.params.publicKey, /^[0-9a-f]+$/);
            const sessionDer = hexToBytes(message.params.publicKey);
            const expiration = expiresAt || new Date(Date.now() + 15 * 60 * 1000);
            const chain = await DelegationChain.create(
              rootKey,
              { toDer: () => sessionDer },
              expiration
            );
            const json = chain.toJSON();
            reply({
              publicKey: encodeBlob(json.publicKey),
              signerDelegation: json.delegations.map((d) => ({
                delegation: {
                  pubkey: encodeBlob(d.delegation.pubkey),
                  // wire format: base-10 nanoseconds as string
                  expiration: BigInt("0x" + d.delegation.expiration).toString(10),
                },
                signature: encodeBlob(d.signature),
              })),
            });
            return;
          }
          default:
            env.win.dispatch({
              origin: SIGNER_ORIGIN,
              source: signerWindow,
              data: {
                jsonrpc: "2.0",
                id: message.id,
                error: { code: 2001, message: "unsupported: " + message.method },
              },
            });
        }
      });
    },
  };
  env.win.signerWindow = signerWindow;
  state.window = signerWindow;
  return state;
}

let env;
beforeEach(() => {
  env = makeEnv();
  globalThis.window = env.win;
  globalThis.localStorage = env.localStorage;
});

// --- tests --------------------------------------------------------------------

test("connect() performs handshake, permissions, accounts and delegation", async () => {
  const signer = makeFakeSigner(env);
  const identity = await StoicIdentity.connect();

  // identity acts as the wallet root identity
  assert.equal(
    identity.getPrincipal().toText(),
    signer.rootKey.getPrincipal().toText()
  );

  // protocol order: status → permissions → accounts → delegation
  const methods = signer.requests.map((r) => r.method);
  assert.ok(methods.includes("icrc29_status"));
  assert.deepEqual(
    methods.filter((m) => m !== "icrc29_status"),
    ["icrc25_request_permissions", "icrc27_accounts", "icrc34_delegation"]
  );

  // accounts carry principal + computed ICP account-id
  const accounts = await identity.accounts();
  assert.equal(accounts.length, 2);
  assert.equal(accounts[0].owner, signer.rootKey.getPrincipal().toText());
  assert.match(accounts[0].address, /^[0-9a-f]{64}$/);
  assert.equal(accounts[1].subaccount, "01".padStart(64, "0"));
  assert.notEqual(accounts[0].address, accounts[1].address);

  // session is valid for ~15 minutes
  assert.ok(identity.isValid());
  assert.ok(identity.sessionExpiry > new Date());

  // signer popup was closed after connecting
  assert.ok(signer.window.closed);
});

test("connect() keeps polling icrc29_status until the signer is ready", async () => {
  makeFakeSigner(env, { readyAfterPolls: 2 });
  const identity = await StoicIdentity.connect();
  assert.ok(identity.isValid());
});

for (const blobEncoding of ["hex", "base64"]) {
  test(`connect() tolerates ${blobEncoding}-encoded outbound blobs`, async () => {
    const signer = makeFakeSigner(env, { blobEncoding });
    const identity = await StoicIdentity.connect();
    assert.equal(
      identity.getPrincipal().toText(),
      signer.rootKey.getPrincipal().toText()
    );
  });
}

test("transformRequest attaches the delegation for agent calls", async () => {
  const signer = makeFakeSigner(env);
  const identity = await StoicIdentity.connect();

  const body = {
    request_type: "call",
    canister_id: Principal.fromText("ryjl3-tyaaa-aaaaa-aaaba-cai"),
    method_name: "transfer",
    arg: new Uint8Array([1, 2, 3]),
    sender: identity.getPrincipal(),
  };
  await requestIdOf(body); // sanity: body is hashable

  const transformed = await identity.transformRequest({
    endpoint: "call",
    body,
  });
  assert.ok(transformed.body.sender_sig);
  assert.equal(transformed.body.sender_delegation.length, 1);
  assert.deepEqual(
    new Uint8Array(transformed.body.sender_pubkey),
    new Uint8Array(signer.rootKey.getPublicKey().toDer())
  );
});

test("sessions persist: load() restores the same principal", async () => {
  const signer = makeFakeSigner(env);
  const connected = await StoicIdentity.connect();
  const loaded = await StoicIdentity.load();
  assert.notEqual(loaded, false);
  assert.equal(loaded.getPrincipal().toText(), connected.getPrincipal().toText());
  assert.equal(
    (await loaded.accounts())[0].address,
    (await connected.accounts())[0].address
  );
  assert.equal(signer.requests.filter((r) => r.method === "icrc34_delegation").length, 1);
});

test("load() resolves false with no session, after disconnect, and for other origins", async () => {
  assert.equal(await StoicIdentity.load(), false);
  makeFakeSigner(env);
  await StoicIdentity.connect();
  assert.notEqual(await StoicIdentity.load(), false);
  assert.equal(await StoicIdentity.load("https://evil.example.com"), false);
  StoicIdentity.disconnect();
  assert.equal(await StoicIdentity.load(), false);
});

test("expired delegations: load() resolves false, transformRequest rejects", async () => {
  makeFakeSigner(env, { expiresAt: new Date(Date.now() + 1000) }); // 1s TTL
  const identity = await StoicIdentity.connect();
  assert.equal(identity.isValid(), false); // < 60s buffer
  assert.equal(await StoicIdentity.load(), false);
  await new Promise((r) => setTimeout(r, 1100));
  await assert.rejects(
    identity.transformRequest({ endpoint: "call", body: {} }),
    /expired/
  );
});

test("scoped delegation options are forwarded to the signer", async () => {
  const signer = makeFakeSigner(env);
  await StoicIdentity.connect(undefined, {
    targets: ["ryjl3-tyaaa-aaaaa-aaaba-cai", Principal.fromText("qoctq-giaaa-aaaaa-aaaea-cai")],
    maxTimeToLive: 300000000000n,
  });
  const req = signer.requests.find((r) => r.method === "icrc34_delegation");
  assert.deepEqual(req.params.targets, [
    "ryjl3-tyaaa-aaaaa-aaaba-cai",
    "qoctq-giaaa-aaaaa-aaaea-cai",
  ]);
  assert.equal(req.params.maxTimeToLive, "300000000000");
});

test("signer errors surface with their ICRC error codes", async () => {
  const signer = makeFakeSigner(env);
  signer.window.postMessage = ((original) =>
    function (message) {
      if (message && message.method === "icrc34_delegation") {
        queueMicrotask(() =>
          env.win.dispatch({
            origin: SIGNER_ORIGIN,
            source: signer.window,
            data: {
              jsonrpc: "2.0",
              id: message.id,
              error: { code: 3001, message: "Action aborted" },
            },
          })
        );
        return;
      }
      return original.call(this, message);
    })(signer.window.postMessage);
  await assert.rejects(StoicIdentity.connect(), (err) => err.code === 3001);
});

test("legacy API remains exported", () => {
  assert.equal(typeof StoicIdentityLegacy, "function");
  assert.equal(typeof StoicIdentityLegacy.connect, "function");
  assert.equal(typeof StoicIdentityLegacy.load, "function");
  assert.equal(typeof StoicIdentityLegacy.disconnect, "function");
});
