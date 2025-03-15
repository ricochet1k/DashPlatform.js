use std::collections::BTreeMap;

use crate::{Item, fmtjs::Fmt};

pub struct FmtTs<T>(pub T);

pub fn write_dts<W: std::io::Write>(
    mut f: W,
    all_items: &mut BTreeMap<String, Item>,
) -> Result<(), std::io::Error> {
    writeln!(
        f,
        "import {{ BinCode, BinCodeable }} from \"./bincode.ts\";"
    )?;
    writeln!(
        f,
        "import {{ Option, FixedBytes, Hash, SocketAddr, Transaction }} from \"./bincode_types.ts\";"
    )?;
    writeln!(f, "declare module \"./generated_bincode.js\" {{")?;
    writeln!(f)?;
    for (name, item) in all_items {
        if !item.needed {
            continue;
        }

        writeln!(f, "{}", FmtTs((&**name, &item.item)))?;
    }
    writeln!(f)?;
    writeln!(f, "}}")?;
    Ok(())
}

impl std::fmt::Display for FmtTs<(&'_ str, &'_ Vec<syn::Attribute>)> {
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

impl std::fmt::Display for FmtTs<(&'_ str, &'_ syn::Item)> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (name, item) = self.0;
        match &item {
            syn::Item::Struct(item_struct) => write!(f, "{}", FmtTs((name, item_struct))),
            syn::Item::Enum(item_enum) => write!(f, "{}", FmtTs((name, item_enum))),
            syn::Item::Type(item_type) => write!(f, "{}", FmtTs((name, item_type))),
            _ => todo!(),
        }
    }
}

impl std::fmt::Display for FmtTs<(&'_ str, &'_ syn::ItemStruct)> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (name, item) = self.0;

        write!(f, "{}", FmtTs(("", &item.attrs)))?;
        // if item.fields.len() == 0 {
        //     return write!(f, "{{}}");
        // }
        match &item.fields {
            syn::Fields::Named(fields_named) => {
                writeln!(
                    f,
                    "const {} : BinCodeable<{}> & ((data: {{",
                    item.ident, item.ident,
                )?;
                {
                    for field in &fields_named.named {
                        write!(f, "{}", FmtTs(("    ", &field.attrs)))?;
                        writeln!(f, "  {},", FmtTs((field.ident.as_ref().unwrap(), field)))?;
                    }
                }
                writeln!(f, "}}) => {});", item.ident)?;

                writeln!(f, "interface {} {{", item.ident)?;
                for field in &fields_named.named {
                    write!(f, "{}", FmtTs(("  ", &field.attrs)))?;
                    writeln!(f, "  {};", FmtTs((field.ident.as_ref().unwrap(), field)))?;
                }
                writeln!(f, "}}")?;
            }
            syn::Fields::Unnamed(fields_unnamed) => {
                writeln!(f, "const {} : BinCodeable<{}> & ((", item.ident, item.ident,)?;
                {
                    for (i, field) in fields_unnamed.unnamed.iter().enumerate() {
                        write!(f, "{}", FmtTs(("    ", &field.attrs)))?;
                        writeln!(f, "    f{}: {},", i, FmtTs(&field.ty))?;
                    }
                }
                writeln!(f, ") => {});", item.ident)?;

                writeln!(f, "interface {} {{", item.ident,)?;
                for (i, field) in fields_unnamed.unnamed.iter().enumerate() {
                    write!(f, "{}", FmtTs(("  ", &field.attrs)))?;
                    writeln!(f, "  [{}]: {};", i, FmtTs(&field.ty))?;
                }
                writeln!(f, "}}")?;
            }
            syn::Fields::Unit => {
                writeln!(f, "export class {} {{", item.ident)?;
                writeln!(f, "}}")?;
            }
        }
        Ok(())
    }
}

impl std::fmt::Display for FmtTs<(&'_ str, &'_ syn::ItemEnum)> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (name, item) = self.0;

        write!(f, "{}", FmtTs(("", &item.attrs)))?;
        writeln!(f, "export abstract class {} {{", item.ident)?;
        writeln!(f, "  #private;")?;
        writeln!(f, "  static name: string;")?;
        writeln!(f, "  static isValid(v: unknown): boolean;")?;
        writeln!(f, "  static encode(bc: BinCode, v: {}): void;", item.ident)?;
        writeln!(f, "  static decode(bc: BinCode): {};", item.ident)?;
        writeln!(f, "}}")?;
        writeln!(f, "namespace {} {{", item.ident)?;
        for (i, variant) in item.variants.iter().enumerate() {
            write!(f, "{}", FmtTs(("  ", &variant.attrs)))?;
            if variant.fields.len() > 0 {
                match &variant.fields {
                    syn::Fields::Named(fields_named) => {
                        writeln!(f, "  const {}: (data: {{", variant.ident,)?;
                        for field in &fields_named.named {
                            write!(f, "{}", FmtTs(("    ", &field.attrs)))?;
                            writeln!(f, "    {},", FmtTs((&field.ident.as_ref().unwrap(), field)))?;
                        }
                        writeln!(f, "  }}) => {}.{};", item.ident, variant.ident)?;

                        writeln!(f, "  interface {} extends {} {{", variant.ident, item.ident)?;
                        for field in &fields_named.named {
                            write!(f, "{}", FmtTs(("    ", &field.attrs)))?;
                            writeln!(f, "    {};", FmtTs((field.ident.as_ref().unwrap(), field)))?;
                        }
                        writeln!(f, "  }}")?;
                    }
                    syn::Fields::Unnamed(fields_unnamed) => {
                        write!(f, "  const {}: (", variant.ident,)?;
                        let mut first = true;
                        for (i, field) in fields_unnamed.unnamed.iter().enumerate() {
                            if first {
                                first = false;
                            } else {
                                write!(f, ", ")?;
                            }
                            write!(f, "{}", FmtTs(("  ", &field.attrs)))?;
                            write!(f, "f{}: {}", i, FmtTs(&field.ty))?;
                        }
                        writeln!(f, ") => {}.{};", item.ident, variant.ident)?;

                        writeln!(f, "  interface {} extends {} {{", variant.ident, item.ident)?;
                        for (i, field) in fields_unnamed.unnamed.iter().enumerate() {
                            write!(f, "{}", FmtTs(("    ", &field.attrs)))?;
                            writeln!(f, "    [{}]: {};", i, FmtTs(&field.ty))?;
                        }
                        writeln!(f, "  }}")?;
                    }
                    syn::Fields::Unit => write!(f, "")?,
                }
            }
        }
        writeln!(f, "}}")?;
        Ok(())
    }
}

impl std::fmt::Display for FmtTs<(&'_ str, &'_ syn::ItemType)> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (name, item) = self.0;

        writeln!(f, "export type {} = {};", name, FmtTs(&*item.ty))
    }
}

impl<'a> std::fmt::Display for FmtTs<&'a syn::Type> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let ty = self.0;

        match ty {
            syn::Type::Array(type_array) => {
                match &*type_array.elem {
                    syn::Type::Path(type_path) => {
                        if type_path.path.is_ident("u8") {
                            return write!(f, "FixedBytes<{}>", Fmt(&type_array.len));
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
                                return write!(f, "{}", FmtTs(arg));
                            }
                            todo!()
                        }
                        _ => todo!(),
                    }
                } else {
                    write!(f, "{}", FmtTs(type_path))
                }
            }
            syn::Type::Ptr(type_ptr) => todo!(),
            syn::Type::Reference(type_reference) => {
                write!(f, "&{}", FmtTs(&*type_reference.elem))
            }
            syn::Type::Slice(type_slice) => write!(f, "[{}]", FmtTs(&*type_slice.elem)),
            syn::Type::TraitObject(type_trait_object) => {
                write!(f, "dyn ")?;
                for bound in &type_trait_object.bounds {
                    write!(f, " + {}", Fmt(bound))?;
                }
                Ok(())
            }
            syn::Type::Tuple(type_tuple) => {
                write!(f, "[")?;
                for (i, elem) in type_tuple.elems.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{}", FmtTs(elem))?;
                }
                write!(f, "]")
            }
            syn::Type::Verbatim(token_stream) => todo!(),
            _ => todo!(),
        }
    }
}

impl<'a> std::fmt::Display for FmtTs<&'a syn::TypePath> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.0.qself.is_some() {
            todo!()
        }
        write!(f, "{}", FmtTs(&self.0.path))
    }
}

impl<'a> std::fmt::Display for FmtTs<&'a syn::Path> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let last_seg = self.0.segments.last().unwrap();
        write!(f, "{}", FmtTs(last_seg))?;
        Ok(())
    }
}

fn one_argument(args: &syn::PathArguments) -> Option<&syn::GenericArgument> {
    match args {
        syn::PathArguments::None => None,
        syn::PathArguments::AngleBracketed(args) => args.args.first(),
        syn::PathArguments::Parenthesized(args) => todo!(),
    }
}

impl<'a, Ident: std::fmt::Display> std::fmt::Display for FmtTs<(Ident, &'a syn::Field)> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(inner) = is_option(&self.0.1.ty) {
            write!(f, "{}?: {}", self.0.0, FmtTs(inner))
        } else {
            write!(f, "{}: {}", self.0.0, FmtTs(&self.0.1.ty))
        }
    }
}
fn is_option(ty: &syn::Type) -> Option<&syn::Type> {
    match ty {
        syn::Type::Path(type_path) => {
            let last = type_path.path.segments.last().unwrap();
            if last.ident.to_string() == "Option" {
                let arg = one_argument(&last.arguments).unwrap();
                match arg {
                    syn::GenericArgument::Lifetime(lifetime) => todo!(),
                    syn::GenericArgument::Type(ty) => Some(ty),
                    syn::GenericArgument::Const(expr) => todo!(),
                    syn::GenericArgument::AssocType(assoc_type) => todo!(),
                    syn::GenericArgument::AssocConst(assoc_const) => todo!(),
                    syn::GenericArgument::Constraint(constraint) => todo!(),
                    _ => todo!(),
                }
            } else {
                None
            }
        }
        syn::Type::Array(type_array) => None,
        syn::Type::BareFn(type_bare_fn) => todo!(),
        syn::Type::Group(type_group) => todo!(),
        syn::Type::ImplTrait(type_impl_trait) => todo!(),
        syn::Type::Infer(type_infer) => todo!(),
        syn::Type::Macro(type_macro) => todo!(),
        syn::Type::Never(type_never) => todo!(),
        syn::Type::Paren(type_paren) => todo!(),
        syn::Type::Ptr(type_ptr) => todo!(),
        syn::Type::Reference(type_reference) => todo!(),
        syn::Type::Slice(type_slice) => todo!(),
        syn::Type::TraitObject(type_trait_object) => todo!(),
        syn::Type::Tuple(type_tuple) => todo!(),
        syn::Type::Verbatim(token_stream) => todo!(),
        _ => todo!(),
    }
}

impl<'a> std::fmt::Display for FmtTs<&'a syn::PathSegment> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // TODO: Replace Rust types with JS types
        match self.0.ident.to_string().as_str() {
            "bool" => write!(f, "boolean"),
            "i8" => write!(f, "number"),
            "i16" => write!(f, "number"),
            "i32" => write!(f, "number"),
            "i64" => write!(f, "number"),
            "i128" => write!(f, "number"),
            "u8" => write!(f, "number"),
            "u16" => write!(f, "number"),
            "u32" => write!(f, "number"),
            "u64" => write!(f, "number"),
            "u128" => write!(f, "number"),
            "usize" => write!(f, "number"),
            "f32" => write!(f, "number"),
            "f64" => write!(f, "number"),
            "String" => write!(f, "string"),
            "BTreeMap" => write!(f, "Map"),
            "IntMap" => write!(f, "Map"),
            // Ugly way of checking for Vec<u8>
            "Vec"
                if one_argument(&self.0.arguments)
                    .map(|arg| match arg {
                        syn::GenericArgument::Type(syn::Type::Path(path)) => {
                            path.path.is_ident("u8")
                        }
                        _ => false,
                    })
                    .unwrap_or(false) =>
            {
                return write!(f, "Uint8Array");
            }
            "Vec" if matches!(one_argument(&self.0.arguments), Some(_)) => {
                return write!(f, "{}[]", FmtTs(one_argument(&self.0.arguments).unwrap()));
            }

            other => write!(f, "{}", other),
        }?;

        match &self.0.arguments {
            syn::PathArguments::None => {}
            syn::PathArguments::AngleBracketed(args) => {
                // Remember, this isn't being printed as Rust, it's being printed as JS
                write!(f, "<")?;
                for (i, arg) in args.args.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{}", FmtTs(arg))?;
                }
                write!(f, ">")?;
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

impl<'a> std::fmt::Display for FmtTs<&'a syn::GenericArgument> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.0 {
            syn::GenericArgument::Lifetime(lifetime) => write!(f, "'{}", lifetime.ident),
            syn::GenericArgument::Type(ty) => write!(f, "{}", FmtTs(ty)),
            syn::GenericArgument::Const(expr) => todo!(),
            syn::GenericArgument::AssocType(assoc_type) => todo!(),
            syn::GenericArgument::AssocConst(assoc_const) => todo!(),
            syn::GenericArgument::Constraint(constraint) => todo!(),
            _ => todo!(),
        }
    }
}
