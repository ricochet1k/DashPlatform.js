use std::collections::BTreeSet;

pub trait CollectDeps {
    fn collect_deps(&self, deps: &mut BTreeSet<String>);
}

impl CollectDeps for syn::ItemStruct {
    fn collect_deps(&self, deps: &mut BTreeSet<String>) {
        for field in &self.fields {
            field.ty.collect_deps(deps);
        }
    }
}

impl CollectDeps for syn::ItemEnum {
    fn collect_deps(&self, deps: &mut BTreeSet<String>) {
        for variant in &self.variants {
            for field in &variant.fields {
                field.ty.collect_deps(deps);
            }
        }
    }
}

impl CollectDeps for syn::Type {
    fn collect_deps(&self, deps: &mut BTreeSet<String>) {
        match self {
            syn::Type::Array(type_array) => {
                type_array.elem.collect_deps(deps);
            }
            syn::Type::BareFn(type_bare_fn) => {}
            syn::Type::Group(type_group) => todo!(),
            syn::Type::ImplTrait(type_impl_trait) => todo!(),
            syn::Type::Infer(type_infer) => todo!(),
            syn::Type::Macro(type_macro) => todo!(),
            syn::Type::Never(type_never) => {}
            syn::Type::Paren(type_paren) => todo!(),
            syn::Type::Path(type_path) => {
                let last_seg = type_path.path.segments.last().unwrap();
                if last_seg.ident == "NotNan" {
                    // ignore
                } else {
                    deps.insert(last_seg.ident.to_string());
                }
                match &last_seg.arguments {
                    syn::PathArguments::None => {}
                    syn::PathArguments::AngleBracketed(args) => {
                        for arg in &args.args {
                            arg.collect_deps(deps);
                        }
                    }
                    syn::PathArguments::Parenthesized(args) => {
                        for arg in &args.inputs {
                            arg.collect_deps(deps);
                        }
                        match &args.output {
                            syn::ReturnType::Default => {}
                            syn::ReturnType::Type(_, ty) => ty.collect_deps(deps),
                        }
                    }
                }
            }
            syn::Type::Ptr(type_ptr) => todo!(),
            syn::Type::Reference(type_reference) => {
                type_reference.elem.collect_deps(deps);
            }
            syn::Type::Slice(type_slice) => {
                type_slice.elem.collect_deps(deps);
            }
            syn::Type::TraitObject(type_trait_object) => {}
            syn::Type::Tuple(type_tuple) => {
                for elem in &type_tuple.elems {
                    elem.collect_deps(deps);
                }
            }
            syn::Type::Verbatim(token_stream) => todo!(),
            _ => {}
        }
    }
}

impl CollectDeps for syn::GenericArgument {
    fn collect_deps(&self, deps: &mut BTreeSet<String>) {
        match self {
            syn::GenericArgument::Lifetime(lifetime) => {}
            syn::GenericArgument::Type(ty) => {
                ty.collect_deps(deps);
            }
            syn::GenericArgument::Const(expr) => todo!(),
            syn::GenericArgument::AssocType(assoc_type) => todo!(),
            syn::GenericArgument::AssocConst(assoc_const) => todo!(),
            syn::GenericArgument::Constraint(constraint) => todo!(),
            _ => todo!(),
        }
    }
}
