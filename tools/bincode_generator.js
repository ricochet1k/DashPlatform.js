import { opendir, readFile } from "fs/promises"
import { join } from "path"

const ATTRS_RE = /((?:#\[[^\]]+\]\s*)*)/
const TUPLE_ITEM_RE = /^((?:#\[[^\]]+\]\s*)*)(?:pub )?([\w[\]; <>]+)$/

async function* walk(dir) {
    for await (const d of await opendir(dir)) {
        const entry = join(dir, d.name);
        if (d.isDirectory()) yield* walk(entry);
        else if (d.isFile()) yield entry;
    }
}

const IMPORT_ITEMS = 'Bool, Bytes, Constant, Enum, FixedBytes, Lazy, Struct, Uint16, Uint32, Uint64, Uint8, Float64, VarUint, Vec, Option, String'

const TYPE_REPLACEMENTS = {
    'bool': 'Bool',
    'u8': 'Uint8',
    'u16': 'Uint16',
    'u32': 'Uint32',
    'u64': 'Uint64',
    'u128': 'Uint128',
    'i8': 'Int8',
    'i16': 'Int16',
    'i32': 'Int32',
    'i64': 'Int64',
    'i128': 'Int128',
    'f64': 'Float64',
}

/** @type {Record<string, boolean>} */
const writtenItems = {};

for (let item of IMPORT_ITEMS.split(', ')) {
    writtenItems[item] = true;
}

/** @typedef {{name: string, str: string, deps: string[]}} Item */

/** @type {Record<string, Item>} */
const haveItems = {};

/** @type {Array<Item>} */
let availableItems = [];

function convertTypeCollectDeps(type, deps) {
    return type.replaceAll('<', '(').replaceAll('>', ')')
        .replaceAll(/\[u8; (\d+)\]/g, (_m, num) => `FixedBytes(${num})`)
        .replaceAll(/[A-Za-z]\w*/g, str => {
            let replace = TYPE_REPLACEMENTS[str];
            if (replace) return replace;
            if (!writtenItems[str]) deps.push(str);
            return str
        })
}

console.log(`
import { ${IMPORT_ITEMS}, NotSignable } from "./bincode"
/** @import {BinCodeable} from './bincode' */
`)

for (const dir of ["../../platform/packages/rs-platform-value/src", "../../platform/packages/rs-dpp/src"]) {
    for await (const f of walk(dir)) {
        const contents = await readFile(f, "utf8")

        // find all type aliases
        for (const m of contents.matchAll(/^pub type (\w+) = ([\w<>, &'[\];()\n]+);$/gm)) {
            // console.error("Alias", Array.from(m))

            let [, name, type] = m;
            const deps = []

            type = convertTypeCollectDeps(type, deps)

            const str = `export const ${name} = ${type}`;

            const item = {name, str, deps}
            haveItems[name] = item;
            // availableItems.push(item)
        }

        // find all enums
        for (const m of contents.matchAll(/((?:#\[[^\]]+\]\s*)*)\s*pub enum (\w+) \{(.*?)^\}/gsm)) {
            const [_, attrs, name, contents] = m
            if (name.endsWith('Error')) continue;
            // if (!attrs.includes('Encode') || !attrs.includes('Decode')) continue;

            // const simpleFields = Array.from(contents.matchAll(/^\s*(\w+)(?:\(| =|,)/gm))
            const fields = Array.from(contents.matchAll(/((?:#\[[^\]]+\]\s*)*)\s*(\w+)(?:\((.*?)\)| = (\d+))?,/gs))
            // if (simpleFields.length != fields.length) {
            //     console.error('Mismatched fields', name, contents, simpleFields.map(f => f[1]), fields.map(f => f[2]))
            // }

            // for (let i = 0; i < fields.length; i++) {
            //     let [_, attrs, fieldName, type] = fields[i]
            //     if (attrs) {
            //         for (const attr of attrs.trim().split('\n')) {
            //             console.log('  // ' + attr.trim())
            //         }
            //     }

            //     console.log(`export const ${name}${fieldName} = Struct("${name}${fieldName}", {`)
            //     for (let typeItem of type.split(', ')) {
            //         typeItem = typeItem.replace('<', '(').replace('>', ')')

            //         const itemName = typeItem[0].toLowerCase() + typeItem.slice(1)
                        
            //         console.log(`  ${itemName}: ${typeItem},`)
            //     }
            //     console.log(`})`)
            // }
            
            // const hasNoType = fields.filter(([_, attrs, fieldName, type, rawValue]) => type === undefined)
            // if (hasNoType.length != 0 && hasNoType.length != fields.length) {
            //     console.log("// WARNING: Some fields have a type, some do not! :(")
            // }

            // if (hasNoType.length == fields.length) {
            //     // This isn't really an Enum, it's just a number
            // }

            let str = '';
            /** @type {string[]} */
            let deps = [];

            str += `export const ${name} = Enum("${name}", {\n`
            for (let i = 0; i < fields.length; i++) {
                let [_, attrs, fieldName, type, rawValue] = fields[i]
                if (attrs) {
                    for (const attr of attrs.trim().split('\n')) {
                        if (attr.startsWith('#[display(')) {
                            // ignore
                        } else {
                            str += `  // ${attr.trim()}\n`
                        }
                    }
                }

                if (type === undefined && rawValue === undefined) {
                    str += `  ${fieldName}: Constant(${i}),\n`
                } else if (rawValue !== undefined) {
                    str += `  ${fieldName}: Constant(${rawValue}),\n`
                } else {
                    // str += `  ${i}: ${name}${fieldName},`
                    if (/^\w+$/.test(type)) {
                        type = convertTypeCollectDeps(type, deps)
                        str += `  ${fieldName}: ${type},\n`
                    } else {
                        str += `  ${fieldName}: Struct("${name}${fieldName}", {\n`
                        for (let typeItem of type.split(/,\s*/)) {
                            if (!typeItem) continue;
                            // console.log('typeItem', JSON.stringify(typeItem))
                            const m = typeItem.trim().match(TUPLE_ITEM_RE)
                            if (!m) {
                                console.error("Could not match tuple item", name, JSON.stringify(typeItem))
                            }
                            /** @type {string[]} */
                            let [_, attrs, typeVal] = m
                            typeVal = convertTypeCollectDeps(typeVal, deps)

                            const itemName = typeVal[0].toLowerCase() + typeVal.slice(1)
                                
                            str += `    ${itemName}: ${typeVal},\n`
                        }
                        str += `  }),\n`
                    }
                }
            }
            str += `})\n\n`

            const item = {name, str, deps}
            haveItems[name] = item;
            if (attrs.includes('Encode') && attrs.includes('Decode'))
                availableItems.push(item)
        }

        // find all structs
        for (const m of contents.matchAll(/((?:#\[[^\]]+\]\s*)*)^pub struct (\w+)(?: \{([^}]*)\}|\(([^)]*)\))/gm)) {
            const [_, attrs, name, contents, tupleContents] = m
            if (name.endsWith('Error')) continue;
            // if (!attrs.includes('Encode') || !attrs.includes('Decode')) continue;

            let str = '';
            /** @type {string[]} */
            let deps = [];

            if (tupleContents) {
                const fields = tupleContents.split(', ');

                str += `export const ${name} = Struct("${name}", {\n`
            
                for (let i = 0; i < fields.length; i++) {
                    const field = fields[i];

                    const m = field.match(TUPLE_ITEM_RE)
                    if (!m) {
                        console.error("Tuple item doesn't match", JSON.stringify(tupleContents))
                    }
                    let [, attrs, typeVal] = m

                    typeVal = convertTypeCollectDeps(typeVal, deps)

                    str += `F${i}: ${typeVal}\n`
                }

                str += `})\n`


            } else {
                // if (name != "IdentityCreateTransitionV0") continue;
                // const simpleFields = Array.from(contents.matchAll(/\w+: /g))
                const fields = Array.from(contents.matchAll(/((?:#\[[^\]]+\]\s*)*)\s*^\s*(pub(?:\([^\)]+\))? )?(\w+): (.+?),$/gm))
                // if (simpleFields.length != fields.length) {
                //     console.error('Mismatched fields', name, contents, simpleFields.map(f => Array.from(f)), fields.map(f => Array.from(f)))
                // }

                str += `export const ${name} = Struct("${name}", {\n`
                for (let [_, attrs, pub, name, type] of fields) {
                    if (attrs) {
                        for (const attr of attrs.trim().split('\n')) {
                            if (attr.includes('exclude_from_sig_hash')) {
                                type = `NotSignable(${type})`
                            } else if (attr == '#[cfg_attr(feature = "state-transition-serde-conversion", serde(skip))]') {
                                // ignore
                            } else {
                                str += `  // ${attr.trim()}\n`
                            }
                        }
                    }

                    type = convertTypeCollectDeps(type, deps)
                        
                    str += '  ' + name + ': ' + type + ',\n'
                }
                str += `})\n\n`
            }

            const item = {name, str, deps}
            haveItems[name] = item;
            if (attrs.includes('Encode') && attrs.includes('Decode'))
                availableItems.push(item)
        }
    }
}

// activate all items used by known encode/decode items
let newItems = availableItems
while (newItems.length) {
    const items = newItems
    newItems = []
    for (const item of items) {
        for (const dep of item.deps) {
            const aliasItem = haveItems[dep]
            if (aliasItem) {
                delete haveItems[dep]
                haveItems[aliasItem.name] = true
                availableItems.unshift(aliasItem)
                newItems.push(aliasItem)
            }
        }
    }
}

console.error("Items: ", availableItems.length)

// now write the items out if their depencencies area already written
let lastLength = 0;
while (availableItems.length && availableItems.length != lastLength) {
    lastLength = availableItems.length
    availableItems = availableItems.filter(item => {
        
        if (item.deps.every(dep => !haveItems[dep] || writtenItems[dep])) {
            console.log("// " + item.deps.join(', '))
            console.log(item.str);
            writtenItems[item.name] = true;
            return false; // remove from the list
        }
        return true; // keep in the list
    })
}

if (availableItems.length) {
    console.error("Some dependencies missing")
    console.log("/*==== Some dependencies missing ====*/")
    for (const item of availableItems) {
        console.log("// " + item.deps.join(', '))
        console.log(item.str);
    }
}