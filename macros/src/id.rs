use std::sync::atomic::AtomicUsize;

use quote::{__private::TokenStream, quote};

static ID: AtomicUsize = AtomicUsize::new(0);

pub(crate) fn gen(prefix: TokenStream) -> TokenStream {
    let mut id = ID.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let mut tok = quote! { #prefix::uint::UTerm };
    while id > 0 {
        let bit = if id & 1 == 1 {
            quote!(#prefix::bit::B1)
        } else {
            quote!(#prefix::bit::B0)
        };
        tok = quote!(#prefix::uint::UInt<#tok, #bit>);
        id >>= 1;
    }
    tok
}
