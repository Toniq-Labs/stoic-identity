// ic-stoic-identity
//
// v7+: the default StoicIdentity connects over the ICRC signer standards
// (ICRC-25/27/29/34) and signs canister calls locally with a session
// delegation (max 15 minutes — renew with connect()).
//
// The previous stoic-connect implementation remains available as
// StoicIdentityLegacy for a deprecation window and is a drop-in for the old
// API.
export { StoicIdentity } from "./icrc.js";
export { StoicIdentity as StoicIdentityLegacy } from "./legacy.js";
