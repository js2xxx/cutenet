#![feature(if_let_guard)]
#![feature(let_chains)]

use std::ops::ControlFlow;

use quote::{
    __private::{Span, TokenStream},
    format_ident, quote, ToTokens,
};
use syn::*;

const MSG_UNION: &str = "`Wire` cannot be derived on unions";
const MSG_ONCE_STRUCT: &str =
    "`Wire` requires exactly one field with `#[wire]`, `#[payload]` or `#[no_payload]`";
const MSG_ONCE_VARIANT: &str =
    "`Wire` requires exactly one field with `#[wire]`, `#[payload]` or `#[no_payload]` in each variant";
const MSG_ONCE_TY: &str = "`Wire` requires at most one type param with";

#[proc_macro_derive(Wire, attributes(wire, payload, no_payload, prefix))]
pub fn derive_wire(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    match derive_impl(parse_macro_input!(input as DeriveInput)) {
        Ok(tokens) => tokens.into(),
        Err(error) => error.to_compile_error().into(),
    }
}

enum IdentOrIndex {
    Ident(Ident),
    Index(usize),
}

impl ToTokens for IdentOrIndex {
    fn to_tokens(&self, tokens: &mut TokenStream) {
        match self {
            IdentOrIndex::Ident(ident) => ident.to_tokens(tokens),
            IdentOrIndex::Index(index) => format_ident!("_{index}").to_tokens(tokens),
        }
    }
}

enum WireType {
    Wire,
    Payload,
    NoPayload,
}

struct WirePayload {
    ident: IdentOrIndex,
    ty: WireType,
}

struct Branch {
    payload_len: TokenStream,
    substitute_pat: TokenStream,
    substitute_expr: TokenStream,
    wire: WirePayload,
}

struct WireTys {
    wire_ty: Option<Ident>,
    payload_ty: Ident,
    no_payload_ty: Ident,
}

impl WireTys {
    fn bounds<'a>(
        &self,
        prefix: &Path,
        main_ident: &Ident,
        addi_list: impl IntoIterator<Item = &'a Type>,
    ) -> TokenStream {
        let addi_list = addi_list.into_iter();
        let WireTys {
            wire_ty,
            payload_ty,
            no_payload_ty,
        } = self;
        let wire_bound = wire_ty.as_ref().map(|wire_ty| {
            quote! {
                #wire_ty: #prefix:: #main_ident<#(#addi_list,)* Payload = #payload_ty>,
            }
        });

        quote! {
            #wire_bound
            #payload_ty: #prefix::Payload<NoPayload = #no_payload_ty>,
            #no_payload_ty: #prefix::NoPayload<Init = #payload_ty>,
        }
    }
}

fn derive_fields(
    ident: &Ident,
    fields: Fields,
    msg: &str,
) -> Result<(WirePayload, Vec<IdentOrIndex>, Vec<IdentOrIndex>)> {
    let pred_a = |attr: &Attribute| {
        matches!(
            &attr.meta,
            Meta::Path(p)
                if p.is_ident("wire") || p.is_ident("payload") || p.is_ident("no_payload")
        )
    };
    let pred_f = |(_, field): &(usize, &Field)| field.attrs.iter().any(pred_a);

    let filtered: Vec<(usize, &Field)> = fields.iter().enumerate().filter(pred_f).collect();

    let (index, this) = match &*filtered {
        [(ime, me)] => {
            (*ime, WirePayload {
                ident: match me.ident.clone() {
                    Some(ident) => IdentOrIndex::Ident(ident),
                    None => IdentOrIndex::Index(*ime),
                },
                ty: {
                    let [wire, payload, no_payload] = me.attrs.iter().fold([false; 3], |[wire, payload, no_payload], attr| [
                        wire || matches!(&attr.meta, Meta::Path(p) if p.is_ident("wire")),
                        payload || matches!(&attr.meta, Meta::Path(p) if p.is_ident("payload")),
                        no_payload || matches!(&attr.meta, Meta::Path(p) if p.is_ident("no_payload")),
                    ]);
                    match (wire, payload, no_payload) {
                        (true, false, false) => WireType::Wire,
                        (false, true, false) => WireType::Payload,
                        (false, false, true) => WireType::NoPayload,
                        _ => return Err(Error::new_spanned(&me.ident, msg)),
                    }
                },
            })
        }
        [] => return Err(Error::new_spanned(ident, msg)),
        [_, (_, two), ..] => {
            return Err(match &two.ident {
                Some(ident) => Error::new_spanned(ident, msg),
                None => Error::new_spanned(&two.ty, msg),
            })
        }
    };

    let (before, after) = fields.iter().enumerate().fold(
        (Vec::new(), Vec::new()),
        |(mut before, mut after), (i, field)| {
            let item = match field.ident {
                Some(ref ident) => IdentOrIndex::Ident(ident.clone()),
                None => IdentOrIndex::Index(i),
            };
            match i.cmp(&index) {
                std::cmp::Ordering::Less => before.push(item),
                std::cmp::Ordering::Equal => {}
                std::cmp::Ordering::Greater => after.push(item),
            }
            (before, after)
        },
    );

    Ok((this, before, after))
}

fn derive_variant(prefix: &Path, ident: &Ident, fields: Fields, msg: &str) -> Result<Branch> {
    let (wire, before, after) = derive_fields(ident, fields, msg)?;
    Ok(match &wire.ident {
        IdentOrIndex::Ident(field) => match wire.ty {
            WireType::Wire => Branch {
                payload_len: quote! {
                    #ident { #field, .. } =>
                    #prefix::Wire::payload_len(#field)
                },
                substitute_pat: quote!(#ident { #(#before,)* #field, #(#after,)* } =>),
                substitute_expr: quote! {
                    #ident {
                        #(#before,)*
                        #field: #field .substitute(__sub_payload, __sub_no_payload),
                        #(#after,)*
                    }
                },
                wire,
            },
            WireType::Payload => Branch {
                payload_len: quote! {
                    #ident { #field, .. } =>
                    #prefix::Payload::len(#field)
                },
                substitute_pat: quote!(#ident { #(#before,)* #field, #(#after,)* } =>),
                substitute_expr: quote! {
                    #ident {
                        #(#before,)*
                        #field: __sub_payload(#field),
                        #(#after,)*
                    }
                },
                wire,
            },
            WireType::NoPayload => Branch {
                payload_len: quote!(#ident { .. } => 0),
                substitute_pat: quote!(#ident { #(#before,)* #field, #(#after,)* } =>),
                substitute_expr: quote! {
                    #ident {
                        #(#before,)*
                        #field: __sub_no_payload(#field),
                        #(#after,)*
                    }
                },
                wire,
            },
        },
        &IdentOrIndex::Index(_) => match wire.ty {
            WireType::Wire => Branch {
                payload_len: quote! {
                    #ident (#(#before,)* field, ..) =>
                    #prefix::Wire::payload_len(field)
                },
                substitute_pat: quote!(#ident ( #(#before,)* field, #(#after,)* ) =>),
                substitute_expr: quote! {
                    #ident (
                        #(#before,)*
                        field .substitute(__sub_payload, __sub_no_payload),
                        #(#after,)*
                    )
                },
                wire,
            },
            WireType::Payload => Branch {
                payload_len: quote! {
                    #ident (#(#before,)* field, ..) =>
                    #prefix::Payload::len(field)
                },
                substitute_pat: quote!(#ident ( #(#before,)* field, #(#after,)* ) =>),
                substitute_expr: quote! {
                    #ident (
                        #(#before,)*
                        __sub_payload(field),
                        #(#after,)*
                    )
                },
                wire,
            },
            WireType::NoPayload => Branch {
                payload_len: quote!(#ident (..) => 0),
                substitute_pat: quote!(#ident ( #(#before,)* field, #(#after,)* ) =>),
                substitute_expr: quote! {
                    #ident (
                        #(#before,)*
                        __sub_no_payload(field),
                        #(#after,)*
                    )
                },
                wire,
            },
        },
    })
}

fn derive_struct(prefix: &Path, ident: &Ident, data: DataStruct) -> Result<Vec<Branch>> {
    derive_variant(prefix, ident, data.fields, MSG_ONCE_STRUCT).map(|branch| vec![branch])
}

fn derive_enum(prefix: &Path, ident: &Ident, data: DataEnum) -> Result<Vec<Branch>> {
    let to_tokens = |variant: Variant| -> Result<Branch> {
        derive_variant(prefix, &variant.ident, variant.fields, MSG_ONCE_VARIANT).map(
            |Branch {
                 payload_len,
                 substitute_pat,
                 substitute_expr,
                 wire,
             }| Branch {
                payload_len: quote! { #ident :: #payload_len },
                substitute_pat: quote! { #ident :: #substitute_pat },
                substitute_expr: quote! { #ident :: #substitute_expr },
                wire,
            },
        )
    };
    data.variants.into_iter().map(to_tokens).collect()
}

fn derive_generics(generics: &mut Generics) -> Result<(Generics, WireTys)> {
    fn type_param(generics: &mut Generics, ident: &str) -> Result<Option<TypeParam>> {
        let pred_a = |attr: &Attribute| matches!(&attr.meta, Meta::Path(p) if p.is_ident(ident));
        let mut wire_ty = generics
            .type_params_mut()
            .filter(|p| p.attrs.iter().any(pred_a))
            .collect::<Vec<_>>();
        Ok(match &mut *wire_ty {
            [] => None,
            [param] => {
                param.attrs.retain(|attr| !pred_a(attr));
                Some(param.clone())
            }
            [_, two, ..] => {
                return Err(Error::new_spanned(two, format!("{MSG_ONCE_TY} #[{ident}]")))
            }
        })
    }

    let wire_ty = type_param(generics, "wire")?;
    let payload_ty = type_param(generics, "payload")?;
    let no_payload_ty = type_param(generics, "no_payload")?;

    let orig = generics.clone();
    generics.make_where_clause();

    Ok((orig, WireTys {
        wire_ty: wire_ty.map(|TypeParam { ident, .. }| ident),
        payload_ty: match payload_ty {
            Some(TypeParam { ident, .. }) => ident,
            None => {
                let ident = Ident::new("__PayloadType", Span::call_site());
                generics.params.push(parse_quote!(#ident));
                ident
            }
        },
        no_payload_ty: match no_payload_ty {
            Some(TypeParam { ident, .. }) => ident,
            None => {
                let ident = Ident::new("__NoPayloadType", Span::call_site());
                generics.params.push(parse_quote!(#ident));
                ident
            }
        },
    }))
}

fn derive_impl(mut input: DeriveInput) -> Result<TokenStream> {
    let prefix = input.attrs.iter().try_for_each(|attr| {
        if attr.meta.path().is_ident("prefix") {
            return ControlFlow::Break(attr.meta.require_list().map(|meta| {
                let value = &meta.tokens;
                parse_quote!(#value)
            }));
        }
        ControlFlow::Continue(())
    });

    let prefix: syn::Path = match prefix {
        ControlFlow::Break(prefix) => prefix?,
        _ => parse_quote!(cutenet::wire),
    };

    let branches = match input.data {
        syn::Data::Struct(data) => derive_struct(&prefix, &input.ident, data)?,
        syn::Data::Enum(data) => derive_enum(&prefix, &input.ident, data)?,
        syn::Data::Union(_) => return Err(Error::new_spanned(input.ident, MSG_UNION)),
    };

    let (gc, wire_tys) = derive_generics(&mut input.generics)?;

    let ident = &input.ident;
    let (gimpl, _, gwhere) = input.generics.split_for_impl();
    let gwhere = &gwhere.unwrap().predicates;
    let (_, gty, _) = gc.split_for_impl();

    let payload_len = branches.iter().map(|b| &b.payload_len);

    let WireTys {
        wire_ty,
        payload_ty,
        no_payload_ty,
    } = &wire_tys;

    let main_bounds = wire_tys.bounds(&prefix, &Ident::new("Wire", Span::call_site()), []);
    let main = quote! {
        impl #gimpl #prefix::Wire for #ident #gty where #gwhere #main_bounds {
            type Payload = #payload_ty;

            fn payload_len(&self) -> usize {
                match self { #(#payload_len,)* }
            }
        }
    };

    let sub_ty = Ident::new("____Sub", Span::call_site());

    let sub_generics = gc
        .params
        .iter()
        .map(|param| match param {
            GenericParam::Type(TypeParam { ident, .. })
                if let Some(wire_ty) = wire_ty
                    && wire_ty == ident =>
            {
                parse_quote!(<#ident as #prefix::WireSubstitute<#sub_ty>>::Output)
            }
            GenericParam::Type(TypeParam { ident, .. }) if payload_ty == ident => {
                parse_quote!(#sub_ty)
            }
            GenericParam::Type(TypeParam { ident, .. }) if no_payload_ty == ident => {
                parse_quote!(<#sub_ty as #prefix::Payload>::NoPayload)
            }
            GenericParam::Type(TypeParam { ident, .. }) => parse_quote!(#ident),
            GenericParam::Const(ConstParam { ident, .. }) => parse_quote!(#ident),
            GenericParam::Lifetime(LifetimeParam { lifetime, .. }) => parse_quote!(#lifetime),
        })
        .collect::<Vec<TokenStream>>();

    input.generics.params.push(parse_quote!(#sub_ty));

    let (gimpl, _, gwhere) = input.generics.split_for_impl();
    let gwhere = &gwhere.unwrap().predicates;

    let substitute_pat = branches.iter().map(|b| &b.substitute_pat);
    let substitute_expr = branches.iter().map(|b| &b.substitute_expr);

    let sub_bounds = wire_tys.bounds(&prefix, &Ident::new("WireSubstitute", Span::call_site()), [
        &parse_quote!(#sub_ty),
    ]);
    let substitute = quote! {
        impl #gimpl #prefix::WireSubstitute<#sub_ty> for #ident #gty
        where
            #gwhere
            #sub_bounds
            #sub_ty: #prefix::Payload,
        {
            type Output = #ident <#(#sub_generics,)*>;

            fn substitute<F, G>(
                self,
                __sub_payload: F,
                __sub_no_payload: G
            ) -> Self::Output
            where
                F: FnOnce(#payload_ty) -> #sub_ty,
                G: FnOnce(<#payload_ty as #prefix::Payload>::NoPayload)
                    -> <#sub_ty as #prefix::Payload>::NoPayload,
            {
                match self { #(#substitute_pat #substitute_expr,)* }
            }
        }
    };

    Ok([main, substitute].into_iter().collect())
}
