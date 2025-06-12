import Dash from "dash"

const NETWORK = 'testnet';

export const client = new Dash.Client({
  network: NETWORK,
  // Picking a known good ip address can sometimes help reliability
  // Uncomment the next line if network is throwing errors
  // dapiAddresses: ["44.227.137.77:1443"],
  wallet: {
    offlineMode: true,
  },
})


client.getDAPIClient()