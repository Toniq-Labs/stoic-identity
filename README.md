# Stoic Identity
Stoic Identity is an ICP Identity that works directly with the @dfinity/agent for signing canister messages using your StoicWallet.com account. Stoic Identity allows 3rd party dapps to connect to your wallet using a local-only bridge. Applications must request authorization to connect to your wallet, and can only access your wallet on your local PC with the web-wallet unlocked.

3rd party developers are not granted direct remote access - only local, and you can revoke local access directly from the StoicWallet app. **Your private keys are not exposed, but if you authorize your wallet with an application than that application can sign any canister message on your behalf.**

In future, we will add **canister scopes** to authorization requests, so applications must define which canister ID's they will use with their application.

## Installation
```
npm i ic-stoic-identity --save-dev
```

### In the browser:
```
import {StoicIdentity} from "ic-stoic-identity";
```
Usage:
```
StoicIdentity.load().then(async id => {
  if (id !== false) {
    //ID is a already connected wallet!
  } else {
    //No existing connection, lets make one!
    id = await StoicIdentity.connect();
  }
  
  //Lets display the connected principal!
  console.log(id.getPrincipal().toText());
  
  //Disconnect
  StoicIdentity.disconnect();
})
```
