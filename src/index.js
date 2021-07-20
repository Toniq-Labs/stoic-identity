import { Principal } from "@dfinity/principal";
import { blobFromUint8Array } from '@dfinity/candid';
import { requestIdOf } from '@dfinity/agent';
import { Cbor } from "@dfinity/agent";
import { DelegationChain } from '@dfinity/identity';
var Buffer = require('buffer/').Buffer;
const domainSeparator = Buffer.from(new TextEncoder().encode('\x0Aic-request'));
class PublicKey {
  _der;
  _type;
  constructor(der, type, chain){
    this._der = der;
    this._type = type;
    this._chain = chain;
  };
  getType() {
    return this._type;
  };
  toDer() {
    return this._der;
  };
};
window.Buffer = Buffer;
var _stoicOrigin = 'https://www.stoicwallet.com';
function buf2hex(buffer) {
  return [...new Uint8Array(buffer)]
    .map(x => x.toString(16).padStart(2, '0'))
    .join('');
}
function hex2buf(hex) {
  const view = new Uint8Array(hex.length / 2)
  for (let i = 0; i < hex.length; i += 2) {
    view[i / 2] = parseInt(hex.substring(i, i + 2), 16)
  }
  return view
}
const deserialize = (d) => {
  return Cbor.decode(hex2buf(d));
};
const serialize = (d) => {
  return buf2hex(Cbor.encode(d));
};
class StoicIdentity {
  _principal;
  _publicKey;
  
  constructor(principal, pubkey) {
    this._principal = principal;
    this._publicKey = pubkey;
  };
  
  static disconnect() {
    return new Promise(async (resolve, reject) => {
      window.postMessage({ direction : "in", type : "disconnect", callbackID : _getListener(resolve, reject)}, "*");
    });
  };
  
  static connect(host) {
    return new Promise(async (resolve, reject) => {
      if (host) _stoicOrigin = host;
      _stoicLogin(_stoicOrigin).then(data => {
        resolve(new StoicIdentity(Principal.fromText(data.principal), new PublicKey(data.key, data.type)));
      }).catch(reject);
    });
  };
  
  static load(host) {
    return new Promise(async (resolve, reject) => {
      if (host) _stoicOrigin = host;
      window.postMessage({ direction : "in", type : "connect", callbackID : _getListener(result => {
        if (result === false) {
          StoicIdentity.connect().then(resolve).catch(reject);
        } else {
          resolve(new StoicIdentity(Principal.fromText(result.principal), new PublicKey(hex2buf(result.key), result.type)));
        };
      }, reject)}, "*");
    });
  };
  
  getPrincipal() {
    return this._principal;
  };
  getPublicKey() {
    return this._publicKey;
  };
  
  sign(data) {
    return new Promise(async (resolve, reject) => {
      window.postMessage({ direction : "in", type : "sign", callbackID : _getListener(resolve, reject), data : buf2hex(data)}, "*");
    });
  };
  
  transformRequest(request) {
    return new Promise(async (resolve, reject) => {
      try {
        const { body, ...fields } = request;
        const requestId = await requestIdOf(body)
        const pubkey = this.getPublicKey();
        var response = {
          ...fields,
          body : {
            content: body,
          }
        };
        const result = JSON.parse(await this.sign(blobFromUint8Array(Buffer.concat([domainSeparator, requestId]))));
        console.log(result);
        response.body.sender_sig = hex2buf(result.signed);
        if (pubkey.getType() == "DelegationIdentity") {
          var DIC = DelegationChain.fromJSON(result.chain);
          response.body.sender_pubkey = DIC.publicKey;
          response.body.sender_delegation = DIC.delegations;
        } else {
          response.body.sender_pubkey = pubkey.toDer();
        }
        resolve(response);
      } catch (e) {
        reject(e);
      }
    });
  };
};

var _listenerIndex = 0, _listener = {};
var _stoicWindow, _stoicWindowCB, _stoicApiKey;
const _getListener = (resolve, reject) => {
  var thisIndex = _listenerIndex;
  _listener[thisIndex] = [resolve, reject];
  _listenerIndex += 1;
  return thisIndex;
};
const _stoicLogin = (host) => {
  return new Promise(async (resolve, reject) => {
    window.postMessage({ direction : "in", type : "generateKey", callbackID : _getListener(result => {
      _stoicApiKey = result;
      _stoicWindow = window.open(host+'?authorizeApp', 'stoic');
      _stoicWindowCB = [r => {
        window.postMessage({ direction : "in", type : "setApplication", callbackID : _getListener(() => {
          resolve(r);
        }, reject),
        data : {
          principal : r.principal,
          key : buf2hex(r.key),
          type : r.type,
        }});
      }, reject];
    }, reject)}, "*");
  });
};

window.addEventListener("message", function(event) {
  if (event.origin == _stoicOrigin) {
    if (event.data.action == "initiateStoicConnect") {      
      _stoicWindow.postMessage({action : "requestAuthorization", apikey : _stoicApiKey}, "*");
    } else if (event.data.action == "rejectAuthorization") {      
      _stoicWindowCB[1]("Authorization Rejected");
      _stoicWindowCB = null;
      _stoicWindow.close();
    } else if (event.data.action == "confirmAuthorization") {
      _stoicWindowCB[0](event.data);
      _stoicWindowCB = null;
      _stoicWindow.close();
    }
    return;
  }
  if (event.source != window || event.data.direction != "out") return;
  if (event.data.type != "callback") return;
  if (typeof _listener[event.data.callbackID] != 'undefined') {
    if (event.data.response.success) {
      _listener[event.data.callbackID][0](event.data.response.result);
    } else {
      _listener[event.data.callbackID][1](event.data.response.error);
    }
  } else console.error(event);
}, false);
window.StoicIdentity = StoicIdentity;
export default StoicIdentity;