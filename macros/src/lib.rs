#![feature(if_let_guard)]
#![feature(let_chains)]

use syn::*;

mod id;
mod wire;

#[proc_macro_derive(Wire, attributes(wire, payload, no_payload, prefix))]
pub fn derive_wire(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    match wire::derive(parse_macro_input!(input as DeriveInput)) {
        Ok(tokens) => tokens.into(),
        Err(error) => error.to_compile_error().into(),
    }
}

#[proc_macro]
pub fn gen_id(args: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let prefix = if args.is_empty() {
        quote::quote!(typenum)
    } else {
        args.into()
    };
    id::gen(prefix).into()
}
