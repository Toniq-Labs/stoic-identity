import { DerEncodedPublicKey, HttpAgentRequest, PublicKey as PublicKeyInterface, Signature, SignIdentity } from '@dfinity/agent';
import { Principal } from '@dfinity/principal';
declare class PublicKey implements PublicKeyInterface {
    private readonly _der;
    private readonly _type;
    constructor(_der: Uint8Array, _type: string);
    getType(): string;
    toDer(): DerEncodedPublicKey;
}
export declare class StoicIdentity extends SignIdentity {
    protected readonly _principal: Principal;
    private readonly _publicKey;
    constructor(_principal: Principal, _publicKey: PublicKey);
    static disconnect(): void;
    /**
     * @param {string} host Override the wallet host to connect to. This will be preserved across
     *   calls to this or other methods that accept a host input. Defaults to
     *   https://www.stoicwallet.com if host has not been a truthy string yet.
     * @returns StoicIdentity
     */
    static connect(host?: string): Promise<StoicIdentity>;
    /**
     * @param {string} host Override the wallet host to connect to. This will be preserved across
     *   calls to this or other methods that accept a host input. Defaults to
     *   https://www.stoicwallet.com if host has not been a truthy string yet.
     * @param {boolean} ignoreAccounts Optional, defaults to false. If true, accounts will not be
     *   loaded as part of the authorization process.
     * @returns StoicIdentity | undefined
     */
    static load(host?: string, ignoreAccounts?: boolean): Promise<StoicIdentity | undefined>;
    getPublicKey(): PublicKey;
    sign(blob: ArrayBuffer): Promise<Signature>;
    private transport;
    accounts(): Promise<Signature>;
    transformRequest(request: HttpAgentRequest): Promise<unknown>;
}
export {};
