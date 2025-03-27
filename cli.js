import Dotenv from "dotenv"
import DashPhrase from "dashphrase"
import DashHd from "dashhd"
import * as QRCode from "./_qr.js"
import * as DashTx from "dashtx/dashtx.js"
import Fs from "node:fs/promises";

Dotenv.config({ path: ".env" })

export async function loadWallet() {
  let coinType = 5
  let testnet = true // TODO
  if (testnet) {
    coinType = 1
  }

  // void (await WasmDpp.default());

  let walletPhrase = process.env.DASH_WALLET_PHRASE
  let walletSalt = process.env.DASH_WALLET_SALT ?? ""
  if (!walletPhrase) {
    console.error("")
    console.error("ERROR")
    console.error("   'DASH_WALLET_PHRASE' is not set")
    console.error("")
    console.error("SOLUTION")
    let newPhrase = await DashPhrase.generate()
    console.error(`   echo 'DASH_WALLET_PHRASE="${newPhrase}"' >> .env`)
    console.error(`   echo 'DASH_WALLET_SALT=""' >> .env`)
    console.error("")
    process.exit(1)
  }

  let seed = await DashPhrase.toSeed(walletPhrase, walletSalt)
  let walletKey = await DashHd.fromSeed(seed)

  return walletKey
}

/**
 * @param {String} fundingAddress
 * @param {Number} needSats
 */
export function promptQr(fundingAddress, needSats) {
  let dashAmount = DashTx.toDash(needSats)
  let content = `dash:${fundingAddress}?amount=${dashAmount}`
  let ascii = QRCode.ascii(content, {
    indent: 3,
    padding: 4,
    width: 256,
    height: 256,
    color: "#000000",
    background: "#ffffff",
    ecl: "M",
  })
  console.error()
  console.error(`ERROR`)
  console.error(
    `   not enough DASH at funding address (including instant send)`,
  )
  console.error()
  console.error(`SOLUTION`)
  console.error(`   send ${dashAmount} to ${fundingAddress}`)
  console.error(``)
  console.error(ascii)
  console.error()
}

/**
 * Reads a hex file as text, stripping comments (anything including and after a non-hex character), removing whitespace, and joining as a single string
 * @param {String} path
 */
export async function readHex(path) {
  let text = await Fs.readFile(path, "utf8")
  let lines = text.split("\n")
  let hexes = []
  for (let line of lines) {
    line = line.replace(/\s/g, "")
    line = line.replace(/[^0-9a-f].*/i, "")
    hexes.push(line)
  }

  let hex = hexes.join("")
  return hex
}

/**
 * @param {String} path
 */
export async function readWif(path) {
  let wif = await Fs.readFile(path, "utf8")
  wif = wif.trim()

  return wif
}
