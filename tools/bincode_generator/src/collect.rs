use crate::deps::CollectDeps;
use std::collections::BTreeMap;
use std::collections::BTreeSet;

use crate::Item;

pub struct ItemCollector {
    pub all_items: BTreeMap<String, Item>,
}

impl ItemCollector {
    pub fn collect_items(&mut self, items: &[syn::Item]) {
        for item in items {
            self.collect_item(item);
        }
    }

    fn collect_item(&mut self, item: &syn::Item) {
        match item {
            syn::Item::Struct(item_struct) => {
                let mut is_encode = false;
                let mut is_error = false;
                for attr in &item_struct.attrs {
                    if attr.path().is_ident("error") {
                        is_error = true;
                    } else if attr.path().is_ident("derive") {
                        if attr_meta_contains_encode(attr) {
                            is_encode = true;
                        }
                    } else {
                        // println!("// {}", Fmt(attr));
                    }
                }
                if is_error {
                    // continue;
                }
                // if !is_encode {
                //     println!("// !ENCODE");
                // }
                // println!("{}", Fmt(&item_struct))
                let mut deps = BTreeSet::new();
                item_struct.collect_deps(&mut deps);

                let name = item_struct.ident.to_string();
                if let Some(duplicate) = self.all_items.insert(
                    name.clone(),
                    Item {
                        name: name.clone(),
                        item: syn::Item::Struct(item_struct.clone()),
                        deps,
                        needed: false, //is_encode,
                        is_encode,
                    },
                ) {
                    eprintln!("Duplicate item found! {}", item_struct.ident);
                    self.all_items.get_mut(&name).unwrap().name = format!("DUPLICATE_{}", name);
                };
            }
            syn::Item::Type(item_type) => {
                let mut deps = BTreeSet::new();
                item_type.ty.collect_deps(&mut deps);

                // eprintln!("type {}: {:?}", item_type.ident, deps);

                let name = item_type.ident.to_string();
                if let Some(duplicate) = self.all_items.insert(
                    name.clone(),
                    Item {
                        name: name.clone(),
                        item: syn::Item::Type(item_type.clone()),
                        deps,
                        needed: false,
                        // types will never be derive(Encode), just ignore
                        is_encode: true,
                    },
                ) {
                    eprintln!("Duplicate item found! {}", item_type.ident);
                    self.all_items.get_mut(&name).unwrap().name = format!("DUPLICATE_{}", name);
                };
            }
            syn::Item::Enum(item_enum) => {
                let mut is_encode: bool = false;
                for attr in &item_enum.attrs {
                    if attr.path().is_ident("derive") {
                        if attr_meta_contains_encode(attr) {
                            is_encode = true;
                        }
                    } else {
                        // println!("// {}", Fmt(attr));
                    }
                }
                // if !is_encode {
                //     println!("// !ENCODE");
                // }
                // println!("{}", Fmt(&item_enum))
                let mut deps = BTreeSet::new();
                item_enum.collect_deps(&mut deps);

                let name = item_enum.ident.to_string();
                if let Some(duplicate) = self.all_items.insert(
                    name.clone(),
                    Item {
                        name: name.clone(),
                        item: syn::Item::Enum(item_enum.clone()),
                        deps,
                        needed: false, //is_encode,
                        is_encode,
                    },
                ) {
                    eprintln!("Duplicate item found! {}", item_enum.ident);
                    self.all_items.get_mut(&name).unwrap().name = format!("DUPLICATE_{}", name);
                }
            }
            syn::Item::Mod(item_mod) => {
                if let Some(content) = &item_mod.content {
                    self.collect_items(&content.1);
                }
            }

            // syn::Item::Const(item_const) => todo!(),
            // syn::Item::ExternCrate(item_extern_crate) => todo!(),
            // syn::Item::Fn(item_fn) => todo!(),
            // syn::Item::ForeignMod(item_foreign_mod) => todo!(),
            // syn::Item::Impl(item_impl) => todo!(),
            syn::Item::Macro(item_macro) => {
                if let Some(ident) = &item_macro.mac.path.get_ident() {
                    // eprintln!("macro: {}", ident);
                    if ident.to_string() == "hash_newtype" {
                        let block = syn::parse2::<syn::Block>(
                            proc_macro2::TokenTree::Group(proc_macro2::Group::new(
                                proc_macro2::Delimiter::Brace,
                                item_macro.mac.tokens.clone(),
                            ))
                            .into(),
                        )
                        .unwrap();
                        for stmt in &block.stmts {
                            match stmt {
                                syn::Stmt::Item(item) => {
                                    self.collect_item(item);
                                }
                                _ => {}
                            }
                        }
                        // println!("// {}", Fmt(&));
                    }
                }
            }
            // syn::Item::Static(item_static) => todo!(),
            // syn::Item::Trait(item_trait) => todo!(),
            // syn::Item::TraitAlias(item_trait_alias) => todo!(),
            // syn::Item::Union(item_union) => todo!(),
            // syn::Item::Use(item_use) => todo!(),
            // syn::Item::Verbatim(token_stream) => todo!(),
            _ => {}
        }
    }
}

fn attr_meta_contains_encode(attr: &syn::Attribute) -> bool {
    match &attr.meta {
        syn::Meta::List(meta_list) => {
            for token in meta_list.tokens.clone() {
                match token {
                    proc_macro2::TokenTree::Ident(ident) => {
                        if ident.to_string() == "Encode" {
                            return true;
                        }
                    }
                    _ => {}
                }
            }
        }
        syn::Meta::Path(path) => todo!(),
        syn::Meta::NameValue(meta_name_value) => todo!(),
    }

    false
}
