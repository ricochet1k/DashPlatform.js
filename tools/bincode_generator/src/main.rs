use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fs::{self, File};
use std::mem::swap;

use collect::ItemCollector;
use fmtjs::write_js;
use fmtts::write_dts;
use fs_walk::WalkOptions;
use syn::parse_quote;

mod collect;
mod cycle;
mod deps;
mod fmtjs;
mod fmtts;

fn main() -> Result<(), Box<dyn Error>> {
    let mut collector = ItemCollector {
        all_items: BTreeMap::new(),
    };

    for pkg in &[
        // "../../../platform/packages/rs-sdk/src",
        "../../../rust-dashcore/dash/src",
        "../../../platform/packages/rs-platform-value/src",
        "../../../platform/packages/rs-dpp/src",
    ] {
        let options = WalkOptions::new().files().extension("rs");
        for entry in options.walk(pkg) {
            if let Ok(filepath) = entry {
                // eprintln!("// FILE {:?}", &filepath);
                let content = fs::read_to_string(filepath)?;
                let ast = syn::parse_file(&content)?;

                // println!("{} items", ast.items.len());

                collector.collect_items(&ast.items);
            }
        }
    }

    let mut all_items = collector.all_items;

    all_items.get_mut("StateTransition").unwrap().needed = true;
    all_items.get_mut("AssetLockPayload").unwrap().needed = true;

    // Transaction is replaced by a custom implementation in bincode_support.ts
    // provided by DashTx.js
    all_items.remove("Transaction");

    // Serialize implemented by converting to/from RawInstantLockProof first
    // We just replace it here.
    all_items.insert(
        "InstantAssetLockProof".to_string(),
        Item {
            name: "InstantAssetLockProof".to_string(),
            item: parse_quote!(
                type InstantAssetLockProof = RawInstantLockProof;
            ),
            deps: {
                let mut set = BTreeSet::new();
                set.insert("RawInstantLockProof".to_string());
                set
            },
            needed: false,
            is_encode: true,
        },
    );
    all_items.get_mut("RawInstantLockProof").unwrap().needed = true;

    // DashcoreScript is renamed in the use declaration
    // TODO: handle the use declaration renaming
    all_items.insert(
        "DashcoreScript".to_string(),
        Item {
            name: "DashcoreScript".to_string(),
            item: parse_quote!(
                type DashcoreScript = ScriptBuf;
            ),
            deps: {
                let mut deps = BTreeSet::new();
                deps.insert("ScriptBuf".to_string());
                deps
            },
            needed: true,
            is_encode: true,
        },
    );

    let mut needed = BTreeSet::new();
    for item in all_items.values() {
        if item.needed {
            needed.extend(item.deps.iter().cloned());
        }
    }

    // mark all items that are needed repeating until no new items are needed
    let mut newly_needed = BTreeSet::new();
    while !needed.is_empty() {
        // TODO: might be faster to iter then clear after rather than pop_first
        while let Some(name) = needed.pop_first() {
            if let Some(item) = all_items.get_mut(&name) {
                if !item.needed {
                    item.needed = true;
                    newly_needed.extend(item.deps.iter().cloned());
                }
            }
        }
        swap(&mut needed, &mut newly_needed);
    }

    // println!("GCP: {:?}", all_items.get("GroupContractPosition"));

    {
        let mut js_file = File::create("../../generated_bincode.js").unwrap();
        write_js(&mut js_file, &mut all_items).unwrap();
    }

    {
        let mut dts_file = File::create("../../generated_bincode.d.ts").unwrap();
        write_dts(&mut dts_file, &mut all_items).unwrap();
    }

    Ok(())
}

#[derive(Clone)]
pub struct Item {
    name: String,
    item: syn::Item,
    deps: BTreeSet<String>,
    needed: bool,
    is_encode: bool,
}
