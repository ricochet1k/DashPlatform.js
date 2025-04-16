
export const rpcAuthUrl = "https://api:null@trpc.digitalcash.dev";
const zmqUuid = crypto.randomUUID();
export const zmqAuthUrl = `https://tzmq.digitalcash.dev/api/zmq/eventsource/${zmqUuid}`;

export const L1_VERSION_PLATFORM = 3;
// const L1_VERSION_PLATFORM = 0;
export const TYPE_ASSET_LOCK = 8;
export const VERSION_ASSET_LOCK = 1;
// const L2_VERSION_PLATFORM = 1; // actually constant "0" ??
// const ST_CREATE_IDENTITY = 2;

export const VERSIONS_TESTNET = ["8c", "ef"];

export const KEY_TYPES = {
  0: "ECDSA_SECP256K1",
  ECDSA_SECP256K1: 0,
};

export const NETWORK = "testnet";
export const COIN_TYPE = NETWORK == "testnet" ? 1 : 5;

// const IDENTITY_ECDSA_PATH = (() => {
//   // m/purpose'/coin_type'/feature'/subfeature'/keytype'/identityindex'/keyindex'
//   // ex: m/9'/5'/5'/0'/0'/<id>/<key>
//   const PURPOSE_DIP13 = 9;
//   const FEATURE_ID = 5;
//   const SUBFEATURE_KEY = 0;
//   const KEY_TYPE = KEY_TYPES.ECDSA_SECP256K1;
//   return `m/${PURPOSE_DIP13}'/${COIN_TYPE}'/${FEATURE_ID}'/${SUBFEATURE_KEY}'/${KEY_TYPE}'`;
// })();
