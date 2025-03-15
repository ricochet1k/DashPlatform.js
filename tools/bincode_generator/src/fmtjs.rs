use std::collections::{BTreeMap, BTreeSet};

use crate::{Item, cycle::CycleDetector};

pub struct Fmt<T>(pub T);

pub fn write_js<W: std::io::Write>(
    mut f: W,
    all_items: &mut BTreeMap<String, Item>,
) -> Result<(), std::io::Error> {
    writeln!(f, "import {{")?;
    writeln!(
        f,
        "  Bool, Bytes, Enum, VariantDiscriminant, FixedBytes, Lazy, Struct, StructTuple,"
    )?;
    writeln!(
        f,
        "  Int128, Int16, Int32, Int64, Int8, Uint128, Uint16, Uint32, Uint64, Uint8, Float64,"
    )?;
    writeln!(
        f,
        "  VarInt, VarUint, Vec, Tuple, Map, Option, String, Nothing, Range, NotSignable,"
    )?;
    writeln!(f, "  SocketAddr,")?;
    writeln!(f, "}} from \"./bincode.ts\"")?;
    writeln!(f, "import {{ Transaction }} from \"./bincode_types.ts\";")?;
    writeln!(f, "export const Hash = FixedBytes(32)")?;
    writeln!(f, "")?;

    // Detect cycles
    let cyclic_items = CycleDetector::cycle_detect(&all_items);
    for name in &cyclic_items {
        eprintln!("CYCLIC: {}", name);
        let item = all_items.remove(name).unwrap();
        // item.needed = true;
        all_items.insert(format!("REAL_{}", name), item);

        writeln!(f, "/** @type {{*}} */")?;
        writeln!(
            f,
            "export const {} = Lazy(\"{}\", () => REAL_{});",
            name, name, name
        )?;
    }

    writeln!(f)?;

    let mut item_printed = BTreeSet::new();

    let mut need_print = true;
    let mut printed_something = true;
    while printed_something {
        need_print = false;
        printed_something = false;

        for (name, item) in &*all_items {
            if item_printed.contains(&item.name) {
                continue;
            }

            if item.needed {
                if item.deps.iter().all(|dep| {
                    if let Some(dep_item) = all_items.get(dep) {
                        if !item_printed.contains(&dep_item.name) {
                            return false;
                        }
                    }
                    // items we don't have can be ignored
                    true
                }) {
                    // writeln!(f, "// deps: {:?}", item.deps);
                    if !item.is_encode {
                        writeln!(f, "// !ENCODE")?;
                    }
                    writeln!(f, "{}", Fmt((&**name, &item.item)))?;
                    item_printed.insert(item.name.clone());
                    printed_something = true;
                } else {
                    need_print = true;
                }
            }
        }
    }

    if need_print {
        // Items needed but not printed due to a cycle
        writeln!(f, "// CYCLICAL ITEMS")?;
        for (name, item) in &*all_items {
            if item.needed && !item_printed.contains(&item.name) {
                writeln!(f, "// deps: {:?}", item.deps)?;
                if !item.is_encode {
                    writeln!(f, "// !ENCODE")?;
                }
                writeln!(f, "{}", Fmt((&**name, &item.item)))?;
            }
        }
    }

    for item in all_items.values() {
        if !item.needed {
            writeln!(f, "// NOT NEEDED: {}", item.name)?;
            // println!("{}", item.contents);
        }
    }
    Ok(())
}

impl std::fmt::Display for Fmt<(&'_ str, &'_ Vec<syn::Attribute>)> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut doc_started = false;
        for attr in self.0.1 {
            if attr.path().is_ident("error") {
            } else if attr.path().is_ident("derive") {
            } else if attr.path().is_ident("cfg_attr") {
            } else if attr.path().is_ident("cfg") {
            } else if attr.path().is_ident("serde") {
            } else if attr.path().is_ident("display") {
            } else if attr.path().is_ident("bincode") {
            } else if attr.path().is_ident("platform_serialize") {
            } else if attr.path().is_ident("doc") {
                if !doc_started {
                    writeln!(f, "{}/**", self.0.0)?;
                    doc_started = true;
                }
                writeln!(
                    f,
                    "{} *{}",
                    self.0.0,
                    Fmt(&attr.meta.require_name_value().unwrap().value)
                )?;
            } else {
                writeln!(f, "{}// {}", self.0.0, Fmt(attr))?;
            }
        }
        if doc_started {
            writeln!(f, "{} */", self.0.0)?;
        }
        Ok(())
    }
}

impl std::fmt::Display for Fmt<(&'_ str, &'_ syn::Item)> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (name, item) = self.0;
        match &item {
            syn::Item::Struct(item_struct) => write!(f, "{}", Fmt((name, item_struct))),
            syn::Item::Enum(item_enum) => write!(f, "{}", Fmt((name, item_enum))),
            syn::Item::Type(item_type) => write!(f, "{}", Fmt((name, item_type))),
            _ => todo!(),
        }
    }
}

impl std::fmt::Display for Fmt<(&'_ str, &'_ syn::ItemStruct)> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (name, item) = self.0;

        write!(f, "{}", Fmt(("", &item.attrs)))?;
        // if item.fields.len() == 0 {
        //     return write!(f, "{{}}");
        // }
        match &item.fields {
            syn::Fields::Named(fields_named) => {
                writeln!(f, "export const {} = Struct(\"{}\", {{", name, item.ident,)?;
                for field in &fields_named.named {
                    write!(f, "{}", Fmt(("  ", &field.attrs)))?;
                    writeln!(
                        f,
                        "  {}: {},",
                        field.ident.as_ref().unwrap(),
                        Fmt(&field.ty)
                    )?;
                }
                writeln!(f, "}});")
            }
            syn::Fields::Unnamed(fields_unnamed) => {
                writeln!(f, "export const {} = StructTuple(\"{}\",", name, item.ident,)?;
                for (i, field) in fields_unnamed.unnamed.iter().enumerate() {
                    write!(f, "{}", Fmt(("  ", &field.attrs)))?;
                    writeln!(f, "  {},", Fmt(&field.ty))?;
                }
                writeln!(f, ");")
            }
            syn::Fields::Unit => writeln!(
                f,
                "export const {} = StructTuple(\"{}\");",
                name, item.ident
            ),
        }
    }
}

impl std::fmt::Display for Fmt<(&'_ str, &'_ syn::ItemEnum)> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (name, item) = self.0;

        write!(f, "{}", Fmt(("", &item.attrs)))?;
        writeln!(
            f,
            "export const {} = Enum(\"{}\", /** @type {{const}} */ ({{",
            name, item.ident
        )?;
        for (i, variant) in item.variants.iter().enumerate() {
            write!(f, "{}", Fmt(("  ", &variant.attrs)))?;
            write!(f, "  {}: ", variant.ident)?;
            let custom_discriminant = if let Some(disc) = &variant.discriminant {
                let num = match &disc.1 {
                    syn::Expr::Lit(lit) => match &lit.lit {
                        syn::Lit::Int(lit_int) => lit_int.base10_digits().parse::<u64>().unwrap(),
                        _ => todo!(),
                    },
                    _ => todo!(),
                };
                if i as u64 != num {
                    // write!(f, "  // discriminant: {}", Fmt(&disc.1))?;
                    write!(f, "VariantDiscriminant(")?;
                    Some(&disc.1)
                } else {
                    None
                }
            } else {
                None
            };
            match &variant.fields {
                syn::Fields::Named(fields_named) => {
                    writeln!(f, "{{")?;
                    for field in &fields_named.named {
                        write!(f, "{}", Fmt(("    ", &field.attrs)))?;
                        writeln!(
                            f,
                            "    {}: {},",
                            field.ident.as_ref().unwrap(),
                            Fmt(&field.ty)
                        )?;
                    }
                    write!(f, "  }}")?;
                }
                syn::Fields::Unnamed(fields_unnamed) => {
                    write!(f, "[")?;
                    let mut first = true;
                    for (i, field) in fields_unnamed.unnamed.iter().enumerate() {
                        if first {
                            first = false;
                        } else {
                            write!(f, ", ")?;
                        }
                        write!(f, "{}", Fmt(("    ", &field.attrs)))?;
                        write!(f, "{}", Fmt(&field.ty))?;
                    }
                    write!(f, "]")?;
                }
                syn::Fields::Unit => write!(f, "[]")?,
            }
            if let Some(disc) = custom_discriminant {
                write!(f, ", {})", Fmt(disc))?;
            }
            writeln!(f, ",")?;
        }
        writeln!(f, "}}))")?;
        // writeln!(
        //     f,
        //     "/** @namespace @typedef {{typeof {}.$$type}} {} */",
        //     name, name
        // )?;
        // for variant in &item.variants {
        //     writeln!(
        //         f,
        //         "/** @typedef {{ReturnType<typeof {}.{}>}} {}.{} */",
        //         name, variant.ident, name, variant.ident
        //     )?;
        // }
        Ok(())
    }
}

impl std::fmt::Display for Fmt<(&'_ str, &'_ syn::ItemType)> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (name, item) = self.0;

        writeln!(f, "export const {} = {}", name, Fmt(&*item.ty))
    }
}

impl<'a> std::fmt::Display for Fmt<&'a syn::Type> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.0 {
            syn::Type::Array(type_array) => {
                match &*type_array.elem {
                    syn::Type::Path(type_path) => {
                        if type_path.path.is_ident("u8") {
                            return write!(f, "FixedBytes({})", Fmt(&type_array.len));
                        }
                    }
                    _ => {}
                }
                write!(f, "[{}; {}]", Fmt(&*type_array.elem), Fmt(&type_array.len))
            }
            syn::Type::BareFn(type_bare_fn) => {
                write!(f, "we_dont_care_about fn () -> ()...")
            }
            syn::Type::Group(type_group) => todo!(),
            syn::Type::ImplTrait(type_impl_trait) => todo!(),
            syn::Type::Infer(type_infer) => todo!(),
            syn::Type::Macro(type_macro) => todo!(),
            syn::Type::Never(type_never) => todo!(),
            syn::Type::Paren(type_paren) => todo!(),
            syn::Type::Path(type_path) => {
                let last_seg = type_path.path.segments.last().unwrap();
                if last_seg.ident == "NotNan" {
                    // TODO: Stop assuming the inner type is Float64 and not Float32!
                    match &last_seg.arguments {
                        syn::PathArguments::AngleBracketed(args) => {
                            for arg in &args.args {
                                return write!(f, "{}", Fmt(arg));
                            }
                            todo!()
                        }
                        _ => todo!(),
                    }
                } else {
                    write!(f, "{}", Fmt(type_path))
                }
            }
            syn::Type::Ptr(type_ptr) => todo!(),
            syn::Type::Reference(type_reference) => write!(f, "&{}", Fmt(&*type_reference.elem)),
            syn::Type::Slice(type_slice) => write!(f, "[{}]", Fmt(&*type_slice.elem)),
            syn::Type::TraitObject(type_trait_object) => {
                write!(f, "dyn ")?;
                for bound in &type_trait_object.bounds {
                    write!(f, " + {}", Fmt(bound))?;
                }
                Ok(())
            }
            syn::Type::Tuple(type_tuple) => {
                write!(f, "Tuple(")?;
                for (i, elem) in type_tuple.elems.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{}", Fmt(elem))?;
                }
                write!(f, ")")
            }
            syn::Type::Verbatim(token_stream) => todo!(),
            _ => todo!(),
        }
    }
}

impl<'a> std::fmt::Display for Fmt<&'a syn::Expr> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.0 {
            syn::Expr::Array(expr_array) => todo!(),
            syn::Expr::Assign(expr_assign) => todo!(),
            syn::Expr::Async(expr_async) => todo!(),
            syn::Expr::Await(expr_await) => todo!(),
            syn::Expr::Binary(expr_binary) => todo!(),
            syn::Expr::Block(expr_block) => todo!(),
            syn::Expr::Break(expr_break) => todo!(),
            syn::Expr::Call(expr_call) => todo!(),
            syn::Expr::Cast(expr_cast) => todo!(),
            syn::Expr::Closure(expr_closure) => todo!(),
            syn::Expr::Const(expr_const) => write!(
                f,
                "const {{ {:?} }}",
                expr_const.const_token.span.source_text().unwrap()
            ),
            syn::Expr::Continue(expr_continue) => todo!(),
            syn::Expr::Field(expr_field) => todo!(),
            syn::Expr::ForLoop(expr_for_loop) => todo!(),
            syn::Expr::Group(expr_group) => todo!(),
            syn::Expr::If(expr_if) => todo!(),
            syn::Expr::Index(expr_index) => todo!(),
            syn::Expr::Infer(expr_infer) => todo!(),
            syn::Expr::Let(expr_let) => todo!(),
            syn::Expr::Lit(expr_lit) => {
                write!(f, "{}", Fmt(&expr_lit.lit))
            }
            syn::Expr::Loop(expr_loop) => todo!(),
            syn::Expr::Macro(expr_macro) => todo!(),
            syn::Expr::Match(expr_match) => todo!(),
            syn::Expr::MethodCall(expr_method_call) => todo!(),
            syn::Expr::Paren(expr_paren) => todo!(),
            syn::Expr::Path(expr_path) => write!(f, "{}", Fmt(&expr_path.path)),
            syn::Expr::Range(expr_range) => todo!(),
            syn::Expr::RawAddr(expr_raw_addr) => todo!(),
            syn::Expr::Reference(expr_reference) => todo!(),
            syn::Expr::Repeat(expr_repeat) => todo!(),
            syn::Expr::Return(expr_return) => todo!(),
            syn::Expr::Struct(expr_struct) => todo!(),
            syn::Expr::Try(expr_try) => todo!(),
            syn::Expr::TryBlock(expr_try_block) => todo!(),
            syn::Expr::Tuple(expr_tuple) => todo!(),
            syn::Expr::Unary(expr_unary) => todo!(),
            syn::Expr::Unsafe(expr_unsafe) => todo!(),
            syn::Expr::Verbatim(token_stream) => todo!(),
            syn::Expr::While(expr_while) => todo!(),
            syn::Expr::Yield(expr_yield) => todo!(),
            _ => todo!(),
        }
    }
}

impl<'a> std::fmt::Display for Fmt<&'a syn::TypePath> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.0.qself.is_some() {
            todo!()
        }
        write!(f, "{}", Fmt(&self.0.path))
    }
}

impl<'a> std::fmt::Display for Fmt<&'a syn::Path> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let last_seg = self.0.segments.last().unwrap();
        write!(f, "{}", Fmt(last_seg))?;
        // if self.0.segments.len() != 1 {
        //     write!(f, " /* ")?;
        //     for (i, seg) in self.0.segments.iter().enumerate() {
        //         if i > 0 {
        //             write!(f, ".")?;
        //         }
        //         write!(f, "{}", Fmt(seg))?;
        //     }
        //     write!(f, " */")?;
        // }

        Ok(())
    }
}

fn one_argument(args: &syn::PathArguments) -> Option<String> {
    match args {
        syn::PathArguments::None => None,
        syn::PathArguments::AngleBracketed(args) => {
            if args.args.len() == 1 {
                let arg = args.args.first().unwrap();
                match arg {
                    syn::GenericArgument::Type(syn::Type::Path(type_path)) => {
                        type_path.path.get_ident().map(|i| i.to_string())
                    }
                    _ => None,
                }
            } else {
                None
            }
        }
        syn::PathArguments::Parenthesized(args) => todo!(),
    }
}

impl<'a> std::fmt::Display for Fmt<&'a syn::PathSegment> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // TODO: Replace Rust types with JS types
        match self.0.ident.to_string().as_str() {
            "bool" => write!(f, "Bool"),
            "i8" => write!(f, "Int8"),
            "i16" => write!(f, "VarInt"),
            "i32" => write!(f, "VarInt"),
            "i64" => write!(f, "VarInt"),
            "i128" => write!(f, "VarInt"),
            "u8" => write!(f, "Uint8"),
            "u16" => write!(f, "VarUint"),
            "u32" => write!(f, "VarUint"),
            "u64" => write!(f, "VarUint"),
            "u128" => write!(f, "VarUint"),
            "usize" => write!(f, "VarUint"),
            "f32" => write!(f, "Float32"),
            "f64" => write!(f, "Float64"),
            "BTreeMap" => write!(f, "Map"),
            "IntMap" => write!(f, "Map"),
            // Ugly way of checking for Vec<u8>
            "Vec"
                if one_argument(&self.0.arguments)
                    .map(|arg| arg == "u8")
                    .unwrap_or(false) =>
            {
                return write!(f, "Bytes");
            }
            other => write!(f, "{}", other),
        }?;

        match &self.0.arguments {
            syn::PathArguments::None => {}
            syn::PathArguments::AngleBracketed(args) => {
                // Remember, this isn't being printed as Rust, it's being printed as JS
                write!(f, "(")?;
                for (i, arg) in args.args.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{}", Fmt(arg))?;
                }
                write!(f, ")")?;
            }
            syn::PathArguments::Parenthesized(args) => {
                write!(f, "(")?;
                for (i, arg) in args.inputs.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{}", Fmt(arg))?;
                }
                write!(f, ")")?;
            }
        }
        Ok(())
    }
}

impl<'a> std::fmt::Display for Fmt<&'a syn::GenericArgument> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.0 {
            syn::GenericArgument::Lifetime(lifetime) => write!(f, "'{}", lifetime.ident),
            syn::GenericArgument::Type(ty) => write!(f, "{}", Fmt(ty)),
            syn::GenericArgument::Const(expr) => todo!(),
            syn::GenericArgument::AssocType(assoc_type) => todo!(),
            syn::GenericArgument::AssocConst(assoc_const) => todo!(),
            syn::GenericArgument::Constraint(constraint) => todo!(),
            _ => todo!(),
        }
    }
}

impl<'a> std::fmt::Display for Fmt<&'a syn::TypeParamBound> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.0 {
            syn::TypeParamBound::Trait(trait_bound) => {
                write!(f, "{}", Fmt(&trait_bound.path))
            }
            syn::TypeParamBound::Lifetime(lifetime) => todo!(),
            syn::TypeParamBound::PreciseCapture(precise_capture) => todo!(),
            syn::TypeParamBound::Verbatim(token_stream) => todo!(),
            _ => todo!(),
        }
    }
}

impl<'a> std::fmt::Display for Fmt<&'a syn::Lit> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.0 {
            syn::Lit::Str(lit_str) => write!(f, "{}", lit_str.value()),
            syn::Lit::ByteStr(lit_byte_str) => write!(f, "{:?}", lit_byte_str.value()),
            syn::Lit::CStr(lit_cstr) => write!(f, "{:?}", lit_cstr.value()),
            syn::Lit::Byte(lit_byte) => write!(f, "{}", lit_byte.value()),
            syn::Lit::Char(lit_char) => write!(f, "{}", lit_char.value()),
            syn::Lit::Int(lit_int) => write!(f, "{}", lit_int.base10_digits()),
            syn::Lit::Float(lit_float) => write!(f, "{}", lit_float.base10_digits()),
            syn::Lit::Bool(lit_bool) => write!(f, "{}", lit_bool.value()),
            syn::Lit::Verbatim(literal) => write!(f, "{}", literal.span().source_text().unwrap()),
            _ => todo!(),
        }
    }
}

impl<'a> std::fmt::Display for Fmt<&'a syn::Attribute> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.0.meta {
            syn::Meta::Path(path) => write!(f, "{}", Fmt(path)),
            syn::Meta::List(meta_list) => {
                write!(f, "{} {}", Fmt(&meta_list.path), meta_list.tokens)
            }
            syn::Meta::NameValue(meta_name_value) => write!(
                f,
                "{} = {}",
                Fmt(&meta_name_value.path),
                Fmt(&meta_name_value.value)
            ),
        }
    }
}
