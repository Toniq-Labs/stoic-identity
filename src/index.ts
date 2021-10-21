import {
    DerEncodedPublicKey,
    HttpAgentRequest,
    PublicKey as PublicKeyInterface,
    requestIdOf,
    Signature,
    SignIdentity,
} from '@dfinity/agent';
import {DelegationChain} from '@dfinity/identity';
import {Principal} from '@dfinity/principal';
import {Buffer} from 'buffer';

window.Buffer = Buffer;
const domainSeparator = Buffer.from(new TextEncoder().encode('\x0Aic-request'));
let globalStoicOrigin = 'https://www.stoicwallet.com';

class PublicKey implements PublicKeyInterface {
    constructor(private readonly _der: Uint8Array, private readonly _type: string) {}

    public getType() {
        return this._type;
    }
    public toDer(): DerEncodedPublicKey {
        return Object.assign(this._der, {__derEncodedPublicKey__: undefined});
    }
}

export class StoicIdentity extends SignIdentity {
    constructor(
        protected override readonly _principal: Principal,
        private readonly _publicKey: PublicKey,
    ) {
        super();
    }

    static disconnect() {
        return stoicLogout();
    }

    /**
     * @param {string} host Override the wallet host to connect to. This will be preserved across
     *   calls to this or other methods that accept a host input. Defaults to
     *   https://www.stoicwallet.com if host has not been a truthy string yet.
     * @returns StoicIdentity
     */
    static async connect(host?: string): Promise<StoicIdentity> {
        if (host) {
            globalStoicOrigin = host;
        }
        const data = await stoicLogin(globalStoicOrigin);
        return new StoicIdentity(
            Principal.fromText(data.principal),
            new PublicKey(data.key, data.type),
        );
    }

    /**
     * @param {string} host Override the wallet host to connect to. This will be preserved across
     *   calls to this or other methods that accept a host input. Defaults to
     *   https://www.stoicwallet.com if host has not been a truthy string yet.
     * @param {boolean} ignoreAccounts Optional, defaults to false. If true, accounts will not be
     *   loaded as part of the authorization process.
     * @returns StoicIdentity | undefined
     */
    static async load(
        host?: string,
        ignoreAccounts: boolean = false,
    ): Promise<StoicIdentity | undefined> {
        if (host) {
            globalStoicOrigin = host;
        }
        const result = stoicInit();
        if (result) {
            const stoicIdentity = new StoicIdentity(
                Principal.fromText(result.principal),
                new PublicKey(result.key, result.type),
            );
            try {
                if (!ignoreAccounts) {
                    await stoicIdentity.accounts();
                }
                return stoicIdentity;
            } catch (error) {
                console.error(error);
                return undefined;
            }
        } else {
            return undefined;
        }
    }

    public getPublicKey(): PublicKey {
        return this._publicKey;
    }

    public async sign(blob: ArrayBuffer): Promise<Signature> {
        return this.transport(buf2hex(blob));
    }

    private transport(data: string): Promise<Signature> {
        if (globalStoicKeys) {
            return stoicSign('sign', data, this.getPrincipal().toText(), globalStoicKeys);
        } else {
            throw new Error(`Can't transport data, Stoic app was not initialized yet.`);
        }
    }

    public accounts() {
        if (globalStoicKeys) {
            return stoicSign('accounts', 'accounts', this.getPrincipal().toText(), globalStoicKeys);
        } else {
            throw new Error(`Can't get accounts, stoic app was not initialized yet.`);
        }
    }

    public override transformRequest(request: HttpAgentRequest) {
        return new Promise(async (resolve, reject) => {
            try {
                const {body, ...fields} = request;
                const requestId = requestIdOf(body);
                const pubkey = this.getPublicKey();
                const response: any = {
                    ...fields,
                    body: {
                        content: body,
                    },
                };
                const result = JSON.parse(
                    String(
                        await this.sign(
                            Buffer.from(
                                Buffer.concat([domainSeparator, new Uint8Array(requestId)]),
                            ),
                        ),
                    ),
                );
                response.body.sender_sig = hex2buf(result.signed);
                if (pubkey.getType() == 'DelegationIdentity') {
                    const DIC = DelegationChain.fromJSON(result.chain);
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

//Login and sign calls
let stoicApiKey: string = '';
let globalStoicKeys: StoicKeys | undefined;
const localStorageStoicAppDataKey = '_scApp';
let listenerIndex = 0;
const listeners: {resolve: Function; reject: Function}[] = [];
const iframeElements: HTMLIFrameElement[] = [];
let stoicWindow: Window | undefined;

let stoicWindowCallback:
    | {
          resolve: (data: ConfirmAuthorizationData) => void;
          reject: (error: unknown) => void;
      }
    | undefined;

function stoicInit(): StoicKeys | undefined {
    globalStoicKeys = readStoredKeys();
    return globalStoicKeys;
}

type SerializedStoicKeys = {
    apikey: string;
    key: number[];
    principal: string;
    secretkey: JsonWebKey;
    type: string;
};

function readStoredKeys(): StoicKeys | undefined {
    const localStorageData: string | undefined =
        localStorage.getItem(localStorageStoicAppDataKey) ?? undefined;
    if (!localStorageData) {
        return undefined;
    }

    try {
        const serializedData: SerializedStoicKeys = JSON.parse(localStorageData);
        const deserialized: StoicKeys = {
            ...serializedData,
            key: new Uint8Array(serializedData.key),
        };
        return deserialized;
    } catch (error) {
        console.error(`Failed to parse localStorage stoicApp data`, error);
        return undefined;
    }
}

function stoicLogout() {
    localStorage.removeItem(localStorageStoicAppDataKey);
    stoicApiKey = '';
    globalStoicKeys = undefined;
}

async function stoicLogin(host: string): Promise<StoicKeys> {
    return new Promise(async (resolve, reject) => {
        const defaultKeys = await generateDefaultKeys();
        stoicApiKey = defaultKeys.apikey;
        stoicWindow = window.open(host + '?authorizeApp', 'stoic') ?? undefined;
        stoicWindowCallback = {
            resolve: (data) => {
                const keys: StoicKeys = {
                    ...defaultKeys,
                    principal: data.principal,
                    key: data.key,
                    type: data.type,
                };
                globalStoicKeys = keys;
                localStorage.setItem(
                    localStorageStoicAppDataKey,
                    JSON.stringify({...keys, key: Array.from(keys.key)}),
                );
                resolve(keys);
            },
            reject,
        };
    });
}

async function stoicSign(
    action: string,
    payload: string,
    principal: string,
    keys: StoicKeys,
): Promise<Signature> {
    return new Promise<Signature>(async function (resolve, reject) {
        const encoder = new TextEncoder();
        const encodedData = encoder.encode(payload);
        const privateKey = await window.crypto.subtle.importKey(
            'jwk',
            keys.secretkey,
            {
                name: 'ECDSA',
                namedCurve: 'P-384',
            },
            true,
            ['sign'],
        );
        const signed = await window.crypto.subtle.sign(
            {
                name: 'ECDSA',
                hash: {name: 'SHA-384'},
            },
            privateKey,
            encodedData,
        );
        const signature = buf2hex(signed);
        postToIframe(
            {
                target: 'STOIC-IFRAME',
                action: action,
                payload: payload,
                principal: principal,
                apikey: keys.apikey,
                sig: signature,
            },
            resolve,
            reject,
        );
    });
}

//Private functions

type StoicKeys = {
    principal: string;
    key: Uint8Array;
    type: string;
    secretkey: JsonWebKey;
    apikey: string;
};

async function generateDefaultKeys(): Promise<Pick<StoicKeys, 'secretkey' | 'apikey'>> {
    const keyPair = await window.crypto.subtle.generateKey(
        {
            name: 'ECDSA',
            namedCurve: 'P-384',
        },
        true,
        ['sign', 'verify'],
    );

    if (!keyPair.privateKey || !keyPair.publicKey) {
        throw new Error(`Failed to generate private/public key pair for stoic identity`);
    }

    const publicKey = await window.crypto.subtle.exportKey('spki', keyPair.publicKey);
    const secretKey = await window.crypto.subtle.exportKey('jwk', keyPair.privateKey);

    return {
        secretkey: secretKey,
        apikey: buf2hex(publicKey),
    };
}

function removeFrame(frameIndex: number): void {
    const iframe = iframeElements[frameIndex];
    if (iframe) {
        iframe.remove();
    }
}

type FramePostData = {
    action: string;
    apikey: string;
    payload: string;
    principal: string;
    sig: string;
    listener?: number;
    target: string;
};

function postToIframe(
    data: FramePostData,
    resolve: (signature: Signature) => void,
    reject: Function,
) {
    const currentIndex = listenerIndex;
    listenerIndex += 1;
    listeners[currentIndex] = {resolve, reject};

    const iframeElement = document.createElement('iframe');
    iframeElement.setAttribute('id', 'connect_iframe' + currentIndex);
    iframeElement.setAttribute('width', '0');
    iframeElement.setAttribute('height', '0');
    iframeElement.setAttribute('border', '0');
    document.body.appendChild(iframeElement);

    iframeElements[currentIndex] = iframeElement;
    iframeElement.addEventListener('load', function () {
        data.listener = currentIndex;
        if (iframeElement.contentWindow) {
            iframeElement.contentWindow.postMessage(data, '*');
        } else {
            throw new Error(`iframe fired load event but it doesn't have a contentWindow yet.`);
        }
    });
    iframeElement.setAttribute('src', globalStoicOrigin + '/?stoicTunnel');
}

function buf2hex(buffer: ArrayBuffer): string {
    return [...new Uint8Array(buffer)].map((x) => x.toString(16).padStart(2, '0')).join('');
}

function hex2buf(hex: string): Uint8Array {
    const view = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) {
        view[i / 2] = parseInt(hex.substring(i, i + 2), 16);
    }
    return view;
}

type InitiateStoicConnectData = {
    action: 'initiateStoicConnect';
};
type RejectAuthorizationData = {
    action: 'rejectAuthorization';
};
type ConfirmAuthorizationData = {
    action: 'confirmAuthorization';
    key: Uint8Array;
    principal: string;
    type: string;
};
type AccountsData = {
    action: 'accounts';
    data: string;
    listener: number;
    success?: boolean;
    target: 'STOIC-EXT';
};

type StoicMessageData =
    | InitiateStoicConnectData
    | ConfirmAuthorizationData
    | RejectAuthorizationData
    | AccountsData;

function isAccountsData(data: StoicMessageData): data is AccountsData {
    return data && 'target' in data && data.target === 'STOIC-EXT';
}

window.addEventListener(
    'message',
    (event?: MessageEvent<StoicMessageData>) => {
        if (event && event.origin == globalStoicOrigin) {
            const eventData = event.data;

            if (isAccountsData(eventData)) {
                const listener = listeners[eventData.listener];
                if (!listener) {
                    throw new Error(`No listener exists at index ${eventData.listener}`);
                }

                if (eventData.success != undefined && eventData.success) {
                    listener.resolve(eventData.data);
                } else {
                    listener.reject(eventData.data);
                }

                removeFrame(eventData.listener);
            } else if (eventData.action == 'initiateStoicConnect') {
                if (stoicWindow) {
                    stoicWindow.postMessage(
                        {action: 'requestAuthorization', apikey: stoicApiKey},
                        '*',
                    );
                } else {
                    throw new Error(`Tried to post to Stoic window but one doesn't exist yet.`);
                }
            } else if (event.data.action == 'rejectAuthorization') {
                stoicWindowCallback?.reject('Authorization Rejected');
                stoicWindowCallback = undefined;
                stoicWindow?.close();
            } else if (event.data.action == 'confirmAuthorization') {
                stoicWindowCallback?.resolve(event.data);
                stoicWindowCallback = undefined;
                stoicWindow?.close();
            }
        }
    },
    false,
);
