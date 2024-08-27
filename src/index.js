import { Principal } from "@dfinity/principal";
import { requestIdOf } from '@dfinity/agent';
import { Cbor } from "@dfinity/agent";
import { SignIdentity } from '@dfinity/agent';
import { DelegationChain } from '@dfinity/identity';
import { Buffer } from 'buffer';
window.Buffer = Buffer;
const domainSeparator = Buffer.from(new TextEncoder().encode('\x0Aic-request'));
var _stoicOrigin = 'https://www.stoicwallet.com';

// Identity
class PublicKey {
  constructor(der, type) {
    this._der = der;
    this._type = type;
  }
  getType() {
    return this._type;
  }
  toDer() {
    return this._der;
  }
}
export class StoicIdentity extends SignIdentity {
  constructor(principal, pubkey) {
    super();
    this._principal = principal;
    this._publicKey = pubkey;
  }

  static disconnect() {
    return _stoicLogout();
  }

  static connect(host, transportMethod = "iframe") {
    return new Promise(async (resolve, reject) => {
      if (host) _stoicOrigin = host;
      _stoicLogin(_stoicOrigin, transportMethod)
        .then((data) => {
          resolve(
            new StoicIdentity(
              Principal.fromText(data.principal),
              new PublicKey(data.key, data.type)
            )
          );
        })
        .catch(reject);
    });
  }

  static load(host, transportMethod = "iframe") {
    return new Promise(async (resolve, reject) => {
      if (host) _stoicOrigin = host;
      var result = _stoicInit();
      if (result === false) {
        resolve(false);
      } else {
        var id = new StoicIdentity(
          Principal.fromText(result.principal),
          new PublicKey(result.key, result.type)
        );
        id.accounts(transportMethod)
          .then((r) => {
            resolve(id);
          })
          .catch((e) => {
            console.log(e);
            resolve(false);
          });
      }
    });
  }

  getPublicKey() {
    return this._publicKey;
  }

  sign(data, transportMethod = "iframe") {
    return this._transport(buf2hex(data), transportMethod);
  }

  _transport(data, transportMethod) {
    return _stoicSign("sign", data, this.getPrincipal().toText(), transportMethod);
  }

  accounts(transportMethod = "iframe") {
    return _stoicSign("accounts", "accounts", this.getPrincipal().toText(), transportMethod);
  }

  transformRequest(request) {
    return new Promise(async (resolve, reject) => {
      try {
        const { body, ...fields } = request;
        const requestId = await requestIdOf(body);
        const pubkey = this.getPublicKey();
        var response = {
          ...fields,
          body: {
            content: body,
          },
        };
        const result = JSON.parse(
          await this.sign(
            Buffer.from(Buffer.concat([domainSeparator, new Uint8Array(requestId)]))
          )
        );
        response.body.sender_sig = hex2buf(result.signed);
        if (pubkey.getType() == "DelegationIdentity") {
          var DIC = DelegationChain.fromJSON(result.chain);
          response.body.sender_pubkey = DIC.publicKey;
          response.body.sender_delegation = DIC.delegations;
        } else {
          response.body.sender_pubkey = new Uint8Array(Object.values(pubkey.toDer()));
        }
        resolve(response);
      } catch (e) {
        reject(e);
      }
    });
  }
}

// Login and sign calls
var _stoicWindow,
  _stoicWindowCB,
  _stoicApiKey,
  _stoicApp,
  _listenerIndex = 0,
  _listener = {},
  _frames = {};
const _stoicInit = () => {
  _stoicApp = JSON.parse(localStorage.getItem("_scApp"));
  return _stoicApp ? _stoicApp : false;
};
const _stoicLogout = () => {
  localStorage.removeItem("_scApp");
  _stoicApiKey = "";
  _stoicApp = null;
};

const _stoicLogin = (host, transportMethod = "iframe") => {
  return new Promise(async (resolve, reject) => {
    var app = await _generateKey();
    _stoicApiKey = app.apikey;
    if (transportMethod === "popup") {
      _stoicWindow = window.open(
        host + "?authorizeApp",
        "stoic",
        "width=500,height=600"
      );
    } else {
      _stoicWindow = window.open(host + "?authorizeApp", "stoic");
    }
    _stoicWindowCB = [
      (r) => {
        app.principal = r.principal;
        app.key = r.key;
        app.type = r.type;
        _stoicApp = app;
        localStorage.setItem("_scApp", JSON.stringify(app));
        resolve(app);
      },
      reject,
    ];
  });
};

const _stoicSign = (action, payload, principal, transportMethod = "iframe") => {
  return new Promise(async function (resolve, reject) {
    // Prepare the data to be sent
    var enc = new TextEncoder();
    var encdata = enc.encode(payload);
    var privk = await window.crypto.subtle.importKey(
      "jwk",
      _stoicApp.secretkey,
      {
        name: "ECDSA",
        namedCurve: "P-384",
      },
      true,
      ["sign"]
    );
    var signed = await window.crypto.subtle.sign(
      {
        name: "ECDSA",
        hash: { name: "SHA-384" },
      },
      privk,
      encdata
    );
    var sig = buf2hex(signed);

    const data = {
      action: action,
      payload: payload,
      principal: principal,
      apikey: _stoicApp.apikey,
      sig: sig, // Include the signature in the data
    };

    // Choose the transport method
    if (transportMethod === "popup") {
      _postToPopup(data, resolve, reject);
    } else {
      _postToFrame(data, resolve, reject);
    }
  });
};

// Private functions
function _generateKey() {
  return new Promise(async (resolve, reject) => {
    var keypair = await window.crypto.subtle.generateKey(
      {
        name: "ECDSA",
        namedCurve: "P-384",
      },
      true,
      ["sign", "verify"]
    );
    var pubk = await window.crypto.subtle.exportKey("spki", keypair.publicKey);
    var secretkey = await window.crypto.subtle.exportKey(
      "jwk",
      keypair.privateKey
    );
    resolve({
      principal: "",
      key: "",
      type: "",
      secretkey: secretkey,
      apikey: buf2hex(pubk),
    });
  });
}

function _removeFrame(id) {
  if (_frames[id].type === "iframe") {
    _frames[id].frame.parentNode.removeChild(_frames[id].frame);
  } else if (_frames[id].type === "popup") {
    _frames[id].frame.close();
  }
  //delete _frames[id];
}

function _postToPopup(data, resolve, reject) {
  var thisIndex = _listenerIndex;
  _listenerIndex += 1;
  _listener[thisIndex] = [resolve, reject];
  const popup = window.open(
    `${_stoicOrigin}/?stoicTunnel`,
    "stoic",
    "width=500,height=600"
  );
  if (!popup) {
    return reject("Failed to open popup window. It may have been blocked by the browser.");
  }
  _frames[thisIndex] = { frame: popup, type: "popup" };
  popup.onload = () => {
    data.listener = thisIndex;
    popup.postMessage(data, _stoicOrigin);
  };
}

function _postToFrame(data, resolve, reject) {
  var thisIndex = _listenerIndex;
  _listenerIndex += 1;
  _listener[thisIndex] = [resolve, reject];
  var ii = document.createElement("iframe");
  ii.setAttribute("id", "connect_iframe" + thisIndex);
  ii.setAttribute("width", "0");
  ii.setAttribute("height", "0");
  ii.setAttribute("border", "0");
  document.body.appendChild(ii);
  _frames[thisIndex] = { frame: ii, type: "iframe" };
  ii.addEventListener("load", function () {
    data.listener = thisIndex;
    _frames[thisIndex].frame.contentWindow.postMessage(data, "*");
  });
  ii.setAttribute("src", _stoicOrigin + "/?stoicTunnel");
}

function buf2hex(buffer) {
  return [...new Uint8Array(buffer)]
    .map((x) => x.toString(16).padStart(2, "0"))
    .join("");
}

function hex2buf(hex) {
  const view = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    view[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  }
  return view;
}

const deserialize = (d) => {
  return Cbor.decode(hex2buf(d));
};

const serialize = (d) => {
  return buf2hex(Cbor.encode(d));
};

// Message handler
window.addEventListener(
  "message",
  function (e) {
    if (e.origin == _stoicOrigin) {
      if (e && e.data && e.data.action === "STOIC-EXT") {
        const [resolve, reject] = _listener[e.data.listener] || [];
        if (typeof e.data.success !== "undefined" && e.data.success) {
          resolve(e.data.data);
        } else {
          reject(e.data.data);
        }
        _removeFrame(e.data.listener);
        //delete _listener[e.data.listener];
      } else if (e.data.action == "initiateStoicConnect") {
        _stoicWindow.postMessage(
          { action: "requestAuthorization", apikey: _stoicApiKey },
          "*"
        );
      } else if (e.data.action == "rejectAuthorization") {
        _stoicWindowCB[1]("Authorization Rejected");
        _stoicWindowCB = null;
        _stoicWindow.close();
      } else if (e.data.action == "confirmAuthorization") {
        _stoicWindowCB[0](e.data);
        _stoicWindowCB = null;
        _stoicWindow.close();
      }
    }
    return;
  },
  false
);