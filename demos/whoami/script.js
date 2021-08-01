document.addEventListener('DOMContentLoaded', async () => {
  const identity = await StoicIdentity.load();
  const API = extjs.connect();
  API.setIdentity(identity);
  API.idl('qlfqk-fqaaa-aaaah-qakfq-cai', window.whoamiIDL);
  window.API = API;
  var whoami = await API.canister('qlfqk-fqaaa-aaaah-qakfq-cai').whoami();
  console.log(whoami.toText());
  StoicIdentity.disconnect();
});