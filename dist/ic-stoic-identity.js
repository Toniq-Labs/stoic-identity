/*! For license information please see ic-stoic-identity.js.LICENSE.txt */
!function webpackUniversalModuleDefinition(e,r){"object"==typeof exports&&"object"==typeof module?module.exports=r():"function"==typeof define&&define.amd?define("ic-stoic-identity",[],r):"object"==typeof exports?exports["ic-stoic-identity"]=r():e["ic-stoic-identity"]=r()}(self,(function(){return(()=>{"use strict";var __webpack_modules__={"./src/index.js":(__unused_webpack_module,__webpack_exports__,__webpack_require__)=>{eval('__webpack_require__.r(__webpack_exports__);\n/* harmony export */ __webpack_require__.d(__webpack_exports__, {\n/* harmony export */   "StoicIdentity": () => (/* binding */ StoicIdentity)\n/* harmony export */ });\n/* harmony import */ var _dfinity_principal__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! @dfinity/principal */ "@dfinity/principal");\n/* harmony import */ var _dfinity_principal__WEBPACK_IMPORTED_MODULE_0___default = /*#__PURE__*/__webpack_require__.n(_dfinity_principal__WEBPACK_IMPORTED_MODULE_0__);\n/* harmony import */ var _dfinity_candid__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! @dfinity/candid */ "@dfinity/candid");\n/* harmony import */ var _dfinity_candid__WEBPACK_IMPORTED_MODULE_1___default = /*#__PURE__*/__webpack_require__.n(_dfinity_candid__WEBPACK_IMPORTED_MODULE_1__);\n/* harmony import */ var _dfinity_agent__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! @dfinity/agent */ "@dfinity/agent");\n/* harmony import */ var _dfinity_agent__WEBPACK_IMPORTED_MODULE_2___default = /*#__PURE__*/__webpack_require__.n(_dfinity_agent__WEBPACK_IMPORTED_MODULE_2__);\n/* harmony import */ var _dfinity_identity__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(/*! @dfinity/identity */ "@dfinity/identity");\n/* harmony import */ var _dfinity_identity__WEBPACK_IMPORTED_MODULE_3___default = /*#__PURE__*/__webpack_require__.n(_dfinity_identity__WEBPACK_IMPORTED_MODULE_3__);\n\r\n\r\n\r\n\r\n\r\n\r\nvar Buffer = __webpack_require__(/*! buffer/ */ "buffer/").Buffer;\r\nwindow.Buffer = Buffer;\r\nconst domainSeparator = Buffer.from(new TextEncoder().encode(\'\\x0Aic-request\'));\r\nvar _stoicOrigin = \'https://www.stoicwallet.com\';\r\n//Identity\r\nclass PublicKey {\r\n  _der;\r\n  _type;\r\n  constructor(der, type){\r\n    this._der = der;\r\n    this._type = type;\r\n  };\r\n  getType() {\r\n    return this._type;\r\n  };\r\n  toDer() {\r\n    return this._der;\r\n  };\r\n};\r\nclass StoicIdentity extends _dfinity_agent__WEBPACK_IMPORTED_MODULE_2__.SignIdentity {\r\n  _principal;\r\n  _publicKey;\r\n  \r\n  constructor(principal, pubkey) {\r\n    super();\r\n    this._principal = principal;\r\n    this._publicKey = pubkey;\r\n  };\r\n  \r\n  static disconnect() {\r\n    return _stoicLogout();\r\n  };\r\n  \r\n  static connect(host) {\r\n    return new Promise(async (resolve, reject) => {\r\n      if (host) _stoicOrigin = host;\r\n      _stoicLogin(_stoicOrigin).then(data => {\r\n        resolve(new StoicIdentity(_dfinity_principal__WEBPACK_IMPORTED_MODULE_0__.Principal.fromText(data.principal), new PublicKey(data.key, data.type)));\r\n      }).catch(reject);\r\n    });\r\n  };\r\n  \r\n  static load(host) {\r\n    return new Promise(async (resolve, reject) => {\r\n      if (host) _stoicOrigin = host;\r\n      var result = _stoicInit();\r\n      if (result === false) {\r\n        resolve(false);\r\n      } else {\r\n        resolve(new StoicIdentity(_dfinity_principal__WEBPACK_IMPORTED_MODULE_0__.Principal.fromText(result.principal), new PublicKey(hex2buf(result.key), result.type)));\r\n      };\r\n    });\r\n  };\r\n  \r\n  getPublicKey() {\r\n    return this._publicKey;\r\n  };\r\n  \r\n  sign(data) {\r\n    return this._transport(buf2hex(data));\r\n  };\r\n  _transport(data) {\r\n    return _stoicSign("sign", data, this.getPrincipal().toText());\r\n  };\r\n  transformRequest(request) {\r\n    return new Promise(async (resolve, reject) => {\r\n      try {\r\n        const { body, ...fields } = request;\r\n        const requestId = await (0,_dfinity_agent__WEBPACK_IMPORTED_MODULE_2__.requestIdOf)(body)\r\n        const pubkey = this.getPublicKey();\r\n        var response = {\r\n          ...fields,\r\n          body : {\r\n            content: body,\r\n          }\r\n        };\r\n        const result = JSON.parse(await this.sign((0,_dfinity_candid__WEBPACK_IMPORTED_MODULE_1__.blobFromUint8Array)(Buffer.concat([domainSeparator, requestId]))));\r\n        response.body.sender_sig = hex2buf(result.signed);\r\n        if (pubkey.getType() == "DelegationIdentity") {\r\n          var DIC = _dfinity_identity__WEBPACK_IMPORTED_MODULE_3__.DelegationChain.fromJSON(result.chain);\r\n          response.body.sender_pubkey = DIC.publicKey;\r\n          response.body.sender_delegation = DIC.delegations;\r\n        } else {\r\n          response.body.sender_pubkey = pubkey.toDer();\r\n        }\r\n        resolve(response);\r\n      } catch (e) {\r\n        reject(e);\r\n      }\r\n    });\r\n  };\r\n};\r\n\r\n//Login and sign calls\r\nvar _stoicWindow, _stoicWindowCB, _stoicApiKey, _stoicApp, _listenerIndex = 0, _listener = {}, _frames = {};\r\nconst _stoicInit = () => {\r\n  _stoicApp = JSON.parse(localStorage.getItem("_scApp"));\r\n  return _stoicApp ? _stoicApp : false;\r\n};\r\nconst _stoicLogout = () => {\r\n  localStorage.removeItem("_scApp");\r\n  _stoicApiKey = \'\';\r\n  _stoicApp = null;\r\n};\r\nconst _stoicLogin = (host) => {\r\n  return new Promise(async (resolve, reject) => {\r\n    var app = await _generateKey();\r\n    _stoicApiKey = app.apikey;\r\n    _stoicWindow = window.open(host+\'?authorizeApp\', \'stoic\');\r\n    _stoicWindowCB = [r => {\r\n      app.principal = r.principal;\r\n      app.key = r.key;\r\n      app.type = r.type;\r\n      _stoicApp = app;\r\n      localStorage.setItem("_scApp", JSON.stringify(app));\r\n      resolve(app);\r\n    }, reject];\r\n  });\r\n};\r\nconst _stoicSign = (action, payload, principal) => {\r\n  return new Promise(async function(resolve, reject){\r\n    var enc = new TextEncoder();\r\n    var encdata = enc.encode(payload);\r\n    var privk = await window.crypto.subtle.importKey(\r\n      "jwk",\r\n      _stoicApp.secretkey,\r\n      {\r\n        name: "ECDSA",\r\n        namedCurve: "P-384"\r\n      },\r\n      true,\r\n      ["sign"]\r\n    );\r\n    var signed = await window.crypto.subtle.sign(\r\n      {\r\n        name: "ECDSA",\r\n        hash: {name: "SHA-384"},\r\n      },\r\n      privk,\r\n      encdata\r\n    );\r\n    var sig = buf2hex(signed);\r\n    _postToFrame({\r\n      target :  "STOIC-IFRAME",\r\n      action : action,\r\n      payload : payload,\r\n      principal : principal,\r\n      apikey : _stoicApp.apikey,\r\n      sig : sig\r\n    }, resolve, reject);\r\n  });  \r\n}\r\n\r\n//Private functions\r\nfunction _generateKey() {\r\n  return new Promise(async (resolve, reject) => {\r\n    var keypair = await window.crypto.subtle.generateKey({\r\n      name: "ECDSA",\r\n      namedCurve: "P-384"},\r\n      true,\r\n      ["sign", "verify"]);\r\n    var pubk = await window.crypto.subtle.exportKey(\r\n      "spki",\r\n      keypair.publicKey\r\n    );\r\n    var secretkey = await window.crypto.subtle.exportKey(\r\n      "jwk",\r\n      keypair.privateKey\r\n    );\r\n    resolve({\r\n      principal : "",\r\n      key : "",\r\n      type : "",\r\n      secretkey : secretkey,\r\n      apikey : buf2hex(pubk),\r\n    });\r\n  });\r\n}\r\nfunction _removeFrame(id) {\r\n  _frames[id].parentNode.removeChild(_frames[id]);\r\n};\r\nfunction _postToFrame(data, resolve, reject) {\r\n    var thisIndex = _listenerIndex;\r\n    _listener[thisIndex] = [resolve, reject];\r\n    var ii = document.createElement(\'iframe\');\r\n    ii.setAttribute(\'id\', \'connect_iframe\');\r\n    ii.setAttribute(\'width\', \'0\');\r\n    ii.setAttribute(\'height\', \'0\');\r\n    ii.setAttribute(\'border\', \'0\');\r\n    document.body.appendChild(ii);\r\n    _frames[thisIndex] = document.getElementById(\'connect_iframe\');\r\n    _frames[thisIndex].addEventListener("load", function() {\r\n      data.listener = thisIndex;\r\n      _frames[thisIndex].contentWindow.postMessage(data, "*");      \r\n    });\r\n    ii.setAttribute(\'src\', _stoicOrigin+\'/?stoicTunnel\');\r\n    _listenerIndex += 1;\r\n};\r\nfunction buf2hex(buffer) {\r\n  return [...new Uint8Array(buffer)]\r\n    .map(x => x.toString(16).padStart(2, \'0\'))\r\n    .join(\'\');\r\n}\r\nfunction hex2buf(hex) {\r\n  const view = new Uint8Array(hex.length / 2)\r\n  for (let i = 0; i < hex.length; i += 2) {\r\n    view[i / 2] = parseInt(hex.substring(i, i + 2), 16)\r\n  }\r\n  return view\r\n}\r\nconst deserialize = (d) => {\r\n  return _dfinity_agent__WEBPACK_IMPORTED_MODULE_2__.Cbor.decode(hex2buf(d));\r\n};\r\nconst serialize = (d) => {\r\n  return buf2hex(_dfinity_agent__WEBPACK_IMPORTED_MODULE_2__.Cbor.encode(d));\r\n};\r\n\r\n//Message handler\r\nwindow.addEventListener("message", function(e){\r\n  if (e.origin == _stoicOrigin) {\r\n    if (e && e.data && e.data.target === \'STOIC-EXT\') {\r\n      if (typeof e.data.success != \'undefined\' && e.data.success){\r\n        _listener[e.data.listener][0](e.data.data);      \r\n      } else {\r\n        _listener[e.data.listener][1](e.data.data);      \r\n      }\r\n      _removeFrame(e.data.listener);\r\n    }else if (e.data.action == "initiateStoicConnect") {      \r\n      _stoicWindow.postMessage({action : "requestAuthorization", apikey : _stoicApiKey}, "*");\r\n    } else if (e.data.action == "rejectAuthorization") {      \r\n      _stoicWindowCB[1]("Authorization Rejected");\r\n      _stoicWindowCB = null;\r\n      _stoicWindow.close();\r\n    } else if (e.data.action == "confirmAuthorization") {\r\n      _stoicWindowCB[0](e.data);\r\n      _stoicWindowCB = null;\r\n      _stoicWindow.close();\r\n    } \r\n  }\r\n  return;\r\n}, false);\n\n//# sourceURL=webpack://ic-stoic-identity/./src/index.js?')},"@dfinity/agent":e=>{e.exports=require("@dfinity/agent")},"@dfinity/candid":e=>{e.exports=require("@dfinity/candid")},"@dfinity/identity":e=>{e.exports=require("@dfinity/identity")},"@dfinity/principal":e=>{e.exports=require("@dfinity/principal")},"buffer/":e=>{e.exports=require("buffer/")}},__webpack_module_cache__={};function __webpack_require__(e){var r=__webpack_module_cache__[e];if(void 0!==r)return r.exports;var n=__webpack_module_cache__[e]={exports:{}};return __webpack_modules__[e](n,n.exports,__webpack_require__),n.exports}__webpack_require__.n=e=>{var r=e&&e.__esModule?()=>e.default:()=>e;return __webpack_require__.d(r,{a:r}),r},__webpack_require__.d=(e,r)=>{for(var n in r)__webpack_require__.o(r,n)&&!__webpack_require__.o(e,n)&&Object.defineProperty(e,n,{enumerable:!0,get:r[n]})},__webpack_require__.o=(e,r)=>Object.prototype.hasOwnProperty.call(e,r),__webpack_require__.r=e=>{"undefined"!=typeof Symbol&&Symbol.toStringTag&&Object.defineProperty(e,Symbol.toStringTag,{value:"Module"}),Object.defineProperty(e,"__esModule",{value:!0})};var __webpack_exports__=__webpack_require__("./src/index.js");return __webpack_exports__})()}));