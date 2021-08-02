# Stoic Identity
Stoic Identity is an ICP Identity that works directly with the @dfinity/agent for signing canister messages using your StoicWallet.com account. Stoic Identity allows 3rd party dapps to connect to your wallet using a local-only bridge. Applications must request authorization to connect to your wallet, and can only access your wallet on your local PC with the web-wallet unlocked.

3rd party developers are not granted direct remote access - only local, and you can revoke local access directly from the StoicWallet app. **Your private keys are not exposed, but if you authorize your wallet with an application than that application can sign any canister message on your behalf.**

In future, we will add **canister scopes** to authorization requests, so applications must define which canister ID's they will use with their application.

![screen-capture (5)](https://user-images.githubusercontent.com/13844325/127801017-c173c688-1871-4b65-b5cb-40ab4db28fbd.gif)

## Installation
```
npm i ic-stoic-identity --save-dev
```

### In the browser:
```javascript
import {StoicIdentity} from "ic-stoic-identity";
```
Usage:
```javascript
StoicIdentity.load().then(async identity => {
  if (identity !== false) {
    //ID is a already connected wallet!
  } else {
    //No existing connection, lets make one!
    identity = await StoicIdentity.connect();
  }
  
  //Lets display the connected principal!
  console.log(identity.getPrincipal().toText());
  
  //Create an actor canister
  const actor = Actor.createActor(idlFactory, {
    agent: new HttpAgent({
      identity,
    }),
    canisterId,
  });
  
  //Disconnect after
  StoicIdentity.disconnect();
})
```

### Authorization in StoicWallet:

![image](https://user-images.githubusercontent.com/13844325/127787841-1d7cda5d-f1a7-4cbb-b251-c28dbf4e9068.png)

### Manage Applications in StoicWallet:

![image](https://user-images.githubusercontent.com/13844325/127787891-4c052b21-7844-410f-bb03-ff0caa148f6e.png)


