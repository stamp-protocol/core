use proc_macro::TokenStream;
use proc_macro_crate::{FoundCrate, crate_name};
use proc_macro2::{Span, TokenStream as TokenStream2};
use quote::{format_ident, quote};
use syn::fold::Fold;
use syn::parse::ParseStream;
use syn::punctuated::Punctuated;
use syn::spanned::Spanned;
use syn::visit::Visit;
use syn::{
    Attribute, Data, DeriveInput, Fields, GenericParam, Generics, Ident, LitStr, Result, Type, TypeParamBound, WhereClause,
    parse_macro_input,
};

#[proc_macro_derive(PrivateParts, attributes(parts, private))]
pub fn derive_private_parts(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    match expand_private_parts(input) {
        Ok(tokens) => tokens.into(),
        Err(err) => err.to_compile_error().into(),
    }
}

fn expand_private_parts(input: DeriveInput) -> Result<TokenStream2> {
    let crate_path = crate_path();
    let parts = PartsAttr::from_attrs(&input.attrs, &crate_path)?;
    let privacy_param = find_privacy_param(&input)?;
    let private_replacements = vec![ModeReplacement {
        ident: privacy_param.clone(),
        ty: parts.private_mode.clone(),
    }];
    let public_replacements = vec![ModeReplacement {
        ident: privacy_param.clone(),
        ty: parts.public_mode.clone(),
    }];
    let private_struct = instantiate_type(&input.ident, &input.generics, &private_replacements);
    let public_struct = instantiate_type(&input.ident, &input.generics, &public_replacements);
    let impl_generics = build_impl_generics(&input.generics, &privacy_param, &private_replacements);
    let (impl_generics_tokens, _, where_clause) = impl_generics.split_for_impl();
    let impl_body = match &input.data {
        Data::Struct(data) => match &data.fields {
            Fields::Named(fields) => expand_named_struct(
                &crate_path,
                &parts,
                &input,
                &fields,
                &privacy_param,
                &private_struct,
                &public_struct,
                impl_generics_tokens,
                where_clause,
            ),
            Fields::Unnamed(fields) => expand_tuple_struct(
                &crate_path,
                &parts,
                &input,
                &fields,
                &privacy_param,
                &private_struct,
                &public_struct,
                impl_generics_tokens,
                where_clause,
            ),
            Fields::Unit => Err(syn::Error::new(input.ident.span(), "PrivateParts derive requires fields")),
        }?,
        Data::Enum(data) => expand_enum(
            &crate_path,
            &parts,
            &data,
            &privacy_param,
            &private_struct,
            &public_struct,
            impl_generics_tokens,
            where_clause,
        )?,
        _ => return Err(syn::Error::new(input.ident.span(), "PrivateParts derive only supports structs and enums")),
    };

    Ok(impl_body)
}

fn expand_named_struct(
    crate_path: &TokenStream2,
    parts: &PartsAttr,
    input: &DeriveInput,
    fields: &syn::FieldsNamed,
    privacy_param: &Ident,
    private_struct: &InstantiatedType,
    public_struct: &InstantiatedType,
    impl_generics: syn::ImplGenerics<'_>,
    where_clause: Option<&WhereClause>,
) -> Result<TokenStream2> {
    let private_ty = private_struct.ty();
    let public_ty = public_struct.ty();
    let public_expr = public_struct.expr();
    let NamedFieldsCode {
        destruct_self_fields,
        strip_private_stmts,
        public_field_inits,
        public_destruct_pattern,
        merge_private_stmts,
        self_field_inits,
        private_data_ident,
    } = prepare_named_fields(crate_path, fields, privacy_param, input.ident.span(), false)?;
    let private_data_ident = &private_data_ident;
    let strip_private_stmts = &strip_private_stmts;
    let merge_private_stmts = &merge_private_stmts;
    let private_data_ty = &parts.private_data_ty;

    Ok(quote! {
        impl #impl_generics #crate_path::PrivateParts for #private_ty #where_clause {
            type PublicView = #public_ty;
            type PrivateData = #private_data_ty;
            type MergeError = #crate_path::MergeError;

            fn strip(self) -> (Self::PublicView, Self::PrivateData) {
                let Self { #( #destruct_self_fields ),* } = self;
                #( #strip_private_stmts )*
                let public = #public_expr {
                    #( #public_field_inits ),*
                };
                (public, #private_data_ident)
            }

            fn merge(
                public: Self::PublicView,
                privatedata: &mut Self::PrivateData,
            ) -> ::core::result::Result<Self, Self::MergeError> {
                let #public_expr { #( #public_destruct_pattern ),* } = public;
                #( #merge_private_stmts )*
                ::core::result::Result::Ok(Self {
                    #( #self_field_inits ),*
                })
            }
        }

        impl #impl_generics ::core::convert::From<#private_ty> for #public_ty #where_clause {
            fn from(value: #private_ty) -> Self {
                let (public, _private) = #crate_path::PrivateParts::strip(value);
                public
            }
        }
    })
}

fn expand_tuple_struct(
    crate_path: &TokenStream2,
    parts: &PartsAttr,
    input: &DeriveInput,
    fields: &syn::FieldsUnnamed,
    privacy_param: &Ident,
    private_struct: &InstantiatedType,
    public_struct: &InstantiatedType,
    impl_generics: syn::ImplGenerics<'_>,
    where_clause: Option<&WhereClause>,
) -> Result<TokenStream2> {
    let private_ty = private_struct.ty();
    let public_ty = public_struct.ty();
    let public_expr = public_struct.expr();
    let TupleFieldsCode {
        self_bindings,
        strip_private_stmts,
        public_values,
        public_bindings,
        merge_private_stmts,
        merge_values,
        private_ident,
    } = prepare_tuple_fields(crate_path, fields, privacy_param, input.ident.span(), false)?;
    let private_ident = &private_ident;
    let strip_private_stmts = &strip_private_stmts;
    let merge_private_stmts = &merge_private_stmts;
    let private_data_ty = &parts.private_data_ty;

    Ok(quote! {
        impl #impl_generics #crate_path::PrivateParts for #private_ty #where_clause {
            type PublicView = #public_ty;
            type PrivateData = #private_data_ty;
            type MergeError = #crate_path::MergeError;

            fn strip(self) -> (Self::PublicView, Self::PrivateData) {
                let Self( #( #self_bindings ),* ) = self;
                #( #strip_private_stmts )*
                let public = #public_expr( #( #public_values ),* );
                (public, #private_ident)
            }

            fn merge(
                public: Self::PublicView,
                privatedata: &mut Self::PrivateData,
            ) -> ::core::result::Result<Self, Self::MergeError> {
                let #public_expr( #( #public_bindings ),* ) = public;
                #( #merge_private_stmts )*
                ::core::result::Result::Ok(Self( #( #merge_values ),* ))
            }
        }

        impl #impl_generics ::core::convert::From<#private_ty> for #public_ty #where_clause {
            fn from(value: #private_ty) -> Self {
                let (public, _private) = #crate_path::PrivateParts::strip(value);
                public
            }
        }
    })
}

fn expand_enum(
    crate_path: &TokenStream2,
    parts: &PartsAttr,
    data: &syn::DataEnum,
    privacy_param: &Ident,
    private_struct: &InstantiatedType,
    public_struct: &InstantiatedType,
    impl_generics: syn::ImplGenerics<'_>,
    where_clause: Option<&WhereClause>,
) -> Result<TokenStream2> {
    let private_ty = private_struct.ty();
    let public_ty = public_struct.ty();
    let public_expr = public_struct.expr();
    let mut strip_arms = Vec::new();
    let mut merge_arms = Vec::new();

    for variant in &data.variants {
        match &variant.fields {
            Fields::Named(fields) => {
                let NamedFieldsCode {
                    destruct_self_fields,
                    strip_private_stmts,
                    public_field_inits,
                    public_destruct_pattern,
                    merge_private_stmts,
                    self_field_inits,
                    private_data_ident,
                } = prepare_named_fields(crate_path, fields, privacy_param, variant.ident.span(), true)?;
                let private_data_ident = private_data_ident;
                let strip_private_stmts = strip_private_stmts;
                let merge_private_stmts = merge_private_stmts;
                let variant_ident = &variant.ident;
                strip_arms.push(quote! {
                    Self::#variant_ident { #( #destruct_self_fields ),* } => {
                        #( #strip_private_stmts )*
                        let public = #public_expr::#variant_ident { #( #public_field_inits ),* };
                        (public, #private_data_ident)
                    }
                });
                merge_arms.push(quote! {
                    #public_expr::#variant_ident { #( #public_destruct_pattern ),* } => {
                        #( #merge_private_stmts )*
                        ::core::result::Result::Ok(Self::#variant_ident {
                            #( #self_field_inits ),*
                        })
                    }
                });
            }
            Fields::Unnamed(fields) => {
                let TupleFieldsCode {
                    self_bindings,
                    strip_private_stmts,
                    public_values,
                    public_bindings,
                    merge_private_stmts,
                    merge_values,
                    private_ident,
                } = prepare_tuple_fields(crate_path, fields, privacy_param, variant.ident.span(), true)?;
                let variant_ident = &variant.ident;
                let private_ident = private_ident;
                let strip_private_stmts = strip_private_stmts;
                let merge_private_stmts = merge_private_stmts;
                strip_arms.push(quote! {
                    Self::#variant_ident( #( #self_bindings ),* ) => {
                        #( #strip_private_stmts )*
                        let public = #public_expr::#variant_ident( #( #public_values ),* );
                        (public, #private_ident)
                    }
                });
                merge_arms.push(quote! {
                    #public_expr::#variant_ident( #( #public_bindings ),* ) => {
                        #( #merge_private_stmts )*
                        ::core::result::Result::Ok(Self::#variant_ident( #( #merge_values ),* ))
                    }
                });
            }
            Fields::Unit => {
                let variant_ident = &variant.ident;
                strip_arms.push(quote! {
                    Self::#variant_ident => {
                        let privatedata: Self::PrivateData = ::core::default::Default::default();
                        let public = #public_expr::#variant_ident;
                        (public, privatedata)
                    }
                });
                merge_arms.push(quote! {
                    #public_expr::#variant_ident => {
                        ::core::result::Result::Ok(Self::#variant_ident)
                    }
                });
            }
        }
    }

    let private_data_ty = &parts.private_data_ty;

    Ok(quote! {
        impl #impl_generics #crate_path::PrivateParts for #private_ty #where_clause {
            type PublicView = #public_ty;
            type PrivateData = #private_data_ty;
            type MergeError = #crate_path::MergeError;

            fn strip(self) -> (Self::PublicView, Self::PrivateData) {
                match self {
                    #( #strip_arms ),*
                }
            }

            fn merge(
                public: Self::PublicView,
                privatedata: &mut Self::PrivateData,
            ) -> ::core::result::Result<Self, Self::MergeError> {
                match public {
                    #( #merge_arms ),*
                }
            }
        }

        impl #impl_generics ::core::convert::From<#private_ty> for #public_ty #where_clause {
            fn from(value: #private_ty) -> Self {
                let (public, _private) = #crate_path::PrivateParts::strip(value);
                public
            }
        }
    })
}

fn validate_private_field_count(span: Span, fields: &[NamedFieldCtx], allow_no_private_fields: bool) -> Result<()> {
    let count = fields.iter().filter(|field| field.is_private).count();
    if count == 0 && !allow_no_private_fields {
        return Err(syn::Error::new(span, "derive(PrivateParts) requires at least one private field"));
    }
    Ok(())
}

fn validate_private_field_count_tuple(span: Span, fields: &[TupleFieldCtx], allow_no_private_fields: bool) -> Result<()> {
    let count = fields.iter().filter(|field| field.is_private).count();
    if count == 0 && !allow_no_private_fields {
        return Err(syn::Error::new(span, "derive(PrivateParts) requires at least one private field"));
    }
    Ok(())
}

fn has_private_attr(field: &syn::Field) -> bool {
    field.attrs.iter().any(|attr| attr.path().is_ident("private"))
}

struct NamedFieldCtx {
    ident: Ident,
    is_private: bool,
    stripped_ident: Option<Ident>,
    private_ident: Option<Ident>,
    merged_ident: Option<Ident>,
    public_binding: Ident,
}

impl NamedFieldCtx {
    fn strip_stmt(&self, crate_path: &TokenStream2) -> TokenStream2 {
        if !self.is_private {
            return TokenStream2::new();
        }
        let field = &self.ident;
        let stripped_ident = self.stripped_ident.as_ref().expect("private field has stripped ident");
        let private_ident = self.private_ident.as_ref().expect("private field has private ident");
        quote! {
            let (#stripped_ident, #private_ident) = #crate_path::PrivateParts::strip(#field);
        }
    }

    fn merge_stmt(&self, crate_path: &TokenStream2) -> TokenStream2 {
        if !self.is_private {
            return TokenStream2::new();
        }
        let binding = &self.public_binding;
        let merged_ident = self.merged_ident.as_ref().expect("private field has merged ident");
        quote! {
            let #merged_ident = match #crate_path::PrivateParts::merge(#binding, privatedata) {
                ::core::result::Result::Ok(value) => value,
                ::core::result::Result::Err(err) => {
                    return ::core::result::Result::Err(err);
                }
            };
        }
    }
}

struct TupleFieldCtx {
    binding: Ident,
    public_binding: Ident,
    is_private: bool,
    stripped_ident: Option<Ident>,
    private_ident: Option<Ident>,
    merged_ident: Option<Ident>,
}

impl TupleFieldCtx {
    fn strip_stmt(&self, crate_path: &TokenStream2, binding: &Ident) -> TokenStream2 {
        if !self.is_private {
            return TokenStream2::new();
        }
        let stripped_ident = self.stripped_ident.as_ref().expect("private tuple field stripped ident");
        let private_ident = self.private_ident.as_ref().expect("private tuple field private ident");
        quote! {
            let (#stripped_ident, #private_ident) = #crate_path::PrivateParts::strip(#binding);
        }
    }

    fn merge_stmt(&self, crate_path: &TokenStream2) -> TokenStream2 {
        if !self.is_private {
            return TokenStream2::new();
        }
        let binding = &self.public_binding;
        let merged_ident = self.merged_ident.as_ref().expect("private tuple field merged ident");
        quote! {
            let #merged_ident = match #crate_path::PrivateParts::merge(#binding, privatedata) {
                ::core::result::Result::Ok(value) => value,
                ::core::result::Result::Err(err) => {
                    return ::core::result::Result::Err(err);
                }
            };
        }
    }
}

struct NamedFieldsCode {
    destruct_self_fields: Vec<Ident>,
    strip_private_stmts: Vec<TokenStream2>,
    public_field_inits: Vec<TokenStream2>,
    public_destruct_pattern: Vec<TokenStream2>,
    merge_private_stmts: Vec<TokenStream2>,
    self_field_inits: Vec<TokenStream2>,
    private_data_ident: Ident,
}

struct TupleFieldsCode {
    self_bindings: Vec<Ident>,
    strip_private_stmts: Vec<TokenStream2>,
    public_values: Vec<TokenStream2>,
    public_bindings: Vec<Ident>,
    merge_private_stmts: Vec<TokenStream2>,
    merge_values: Vec<TokenStream2>,
    private_ident: Ident,
}

fn prepare_named_fields(
    crate_path: &TokenStream2,
    fields: &syn::FieldsNamed,
    privacy_param: &Ident,
    span: Span,
    allow_no_private_fields: bool,
) -> Result<NamedFieldsCode> {
    let mut named_fields = Vec::new();
    let explicit_private_count = fields.named.iter().filter(|field| has_private_attr(field)).count();
    let infer_private = explicit_private_count == 0;
    for field in &fields.named {
        let ident = field.ident.clone().expect("named field");
        let is_private = has_private_attr(field) || (infer_private && type_uses_privacy_param(&field.ty, privacy_param));
        let stripped_ident = if is_private {
            Some(format_ident!("__private_parts_stripped_{}", ident))
        } else {
            None
        };
        let private_ident = if is_private {
            Some(format_ident!("__private_parts_private_data_{}", ident))
        } else {
            None
        };
        let merged_ident = if is_private {
            Some(format_ident!("__private_parts_merged_{}", ident))
        } else {
            None
        };
        let public_binding = format_ident!("__private_parts_public_{}", ident);
        named_fields.push(NamedFieldCtx {
            ident,
            is_private,
            stripped_ident,
            private_ident,
            merged_ident,
            public_binding,
        });
    }

    validate_private_field_count(span, &named_fields, allow_no_private_fields)?;
    let private_fields: Vec<_> = named_fields.iter().filter(|field| field.is_private).collect();

    let destruct_self_fields: Vec<_> = named_fields.iter().map(|field| field.ident.clone()).collect();
    let private_data_ident = match private_fields.len() {
        0 => format_ident!("__private_parts_default_private_data"),
        1 => field_private_ident(private_fields[0]),
        _ => format_ident!("__private_parts_private_data_container"),
    };
    let uses_accumulator = private_fields.len() != 1;

    let mut strip_private_stmts = Vec::new();
    if uses_accumulator {
        strip_private_stmts.push(quote! {
            let mut #private_data_ident: Self::PrivateData = ::core::default::Default::default();
        });
    }
    for field in &named_fields {
        if !field.is_private {
            continue;
        }
        strip_private_stmts.push(field.strip_stmt(crate_path));
        if uses_accumulator {
            let private_ident = field_private_ident(field);
            strip_private_stmts.push(quote! {
                let mut #private_ident = #private_ident;
                while let ::core::option::Option::Some(value) = #private_ident.pop_private() {
                    #private_data_ident.push_private(value);
                }
            });
        }
    }

    let public_field_inits: Vec<_> = named_fields
        .iter()
        .map(|field| {
            let ident = &field.ident;
            let value = if field.is_private {
                let stripped = field.stripped_ident.as_ref().expect("private fields have stripped ident");
                quote!(#stripped)
            } else {
                quote!(#ident)
            };
            quote!(#ident: #value)
        })
        .collect();

    let public_destruct_pattern: Vec<_> = named_fields
        .iter()
        .map(|field| {
            let ident = &field.ident;
            let binding = &field.public_binding;
            quote!(#ident: #binding)
        })
        .collect();

    let merge_private_stmts: Vec<_> = private_fields.iter().map(|field| field.merge_stmt(crate_path)).collect();

    let self_field_inits: Vec<_> = named_fields
        .iter()
        .map(|field| {
            let ident = &field.ident;
            if field.is_private {
                let merged = field.merged_ident.as_ref().expect("private fields have merged ident");
                quote!(#ident: #merged)
            } else {
                let binding = &field.public_binding;
                quote!(#ident: #binding)
            }
        })
        .collect();

    Ok(NamedFieldsCode {
        destruct_self_fields,
        strip_private_stmts,
        public_field_inits,
        public_destruct_pattern,
        merge_private_stmts,
        self_field_inits,
        private_data_ident,
    })
}

fn prepare_tuple_fields(
    crate_path: &TokenStream2,
    fields: &syn::FieldsUnnamed,
    privacy_param: &Ident,
    span: Span,
    allow_no_private_fields: bool,
) -> Result<TupleFieldsCode> {
    if fields.unnamed.is_empty() {
        return Err(syn::Error::new(span, "tuple structs or variants must contain fields"));
    }

    let mut tuple_fields = Vec::new();
    let explicit_private_count = fields.unnamed.iter().filter(|field| has_private_attr(field)).count();
    let infer_private = explicit_private_count == 0;
    for (index, field) in fields.unnamed.iter().enumerate() {
        let binding = format_ident!("__private_parts_field_{}", index);
        let public_binding = format_ident!("__private_parts_public_field_{}", index);
        let is_private = has_private_attr(field) || (infer_private && type_uses_privacy_param(&field.ty, privacy_param));
        let stripped_ident = if is_private {
            Some(format_ident!("__private_parts_stripped_field_{}", index))
        } else {
            None
        };
        let private_ident = if is_private {
            Some(format_ident!("__private_parts_private_field_{}", index))
        } else {
            None
        };
        let merged_ident = if is_private {
            Some(format_ident!("__private_parts_merged_field_{}", index))
        } else {
            None
        };
        tuple_fields.push(TupleFieldCtx {
            binding,
            public_binding,
            is_private,
            stripped_ident,
            private_ident,
            merged_ident,
        });
    }

    validate_private_field_count_tuple(span, &tuple_fields, allow_no_private_fields)?;
    let private_fields: Vec<_> = tuple_fields.iter().filter(|field| field.is_private).collect();

    let self_bindings: Vec<_> = tuple_fields.iter().map(|field| field.binding.clone()).collect();
    let private_ident = match private_fields.len() {
        0 => format_ident!("__private_parts_default_private_data"),
        1 => field_private_ident_tuple(private_fields[0]),
        _ => format_ident!("__private_parts_private_data_container"),
    };
    let uses_accumulator = private_fields.len() != 1;

    let mut strip_private_stmts = Vec::new();
    if uses_accumulator {
        strip_private_stmts.push(quote! {
            let mut #private_ident: Self::PrivateData = ::core::default::Default::default();
        });
    }
    for field in &tuple_fields {
        if !field.is_private {
            continue;
        }
        let binding = &field.binding;
        strip_private_stmts.push(field.strip_stmt(crate_path, binding));
        if uses_accumulator {
            let private_ident_field = field_private_ident_tuple(field);
            strip_private_stmts.push(quote! {
                let mut #private_ident_field = #private_ident_field;
                while let ::core::option::Option::Some(value) = #private_ident_field.pop_private() {
                    #private_ident.push_private(value);
                }
            });
        }
    }

    let public_values: Vec<_> = tuple_fields
        .iter()
        .map(|field| {
            if field.is_private {
                let stripped = field.stripped_ident.as_ref().expect("private tuple field has strip ident");
                quote!(#stripped)
            } else {
                let binding = &field.binding;
                quote!(#binding)
            }
        })
        .collect();

    let public_bindings: Vec<_> = tuple_fields.iter().map(|field| field.public_binding.clone()).collect();

    let merge_private_stmts: Vec<_> = private_fields.iter().map(|field| field.merge_stmt(crate_path)).collect();

    let merge_values: Vec<_> = tuple_fields
        .iter()
        .map(|field| {
            if field.is_private {
                let merged = field.merged_ident.as_ref().expect("private tuple field has merged ident");
                quote!(#merged)
            } else {
                let binding = &field.public_binding;
                quote!(#binding)
            }
        })
        .collect();

    Ok(TupleFieldsCode {
        self_bindings,
        strip_private_stmts,
        public_values,
        public_bindings,
        merge_private_stmts,
        merge_values,
        private_ident,
    })
}

fn field_private_ident(field: &NamedFieldCtx) -> Ident {
    field.private_ident.as_ref().expect("private field has private ident").clone()
}

fn field_private_ident_tuple(field: &TupleFieldCtx) -> Ident {
    field.private_ident.as_ref().expect("private tuple field private ident").clone()
}

#[derive(Clone)]
struct ModeReplacement {
    ident: Ident,
    ty: Type,
}

struct InstantiatedType {
    type_tokens: TokenStream2,
    expr_tokens: TokenStream2,
}

fn instantiate_type(ident: &Ident, generics: &Generics, replacements: &[ModeReplacement]) -> InstantiatedType {
    if generics.params.is_empty() {
        let ty = quote!(#ident);
        return InstantiatedType {
            type_tokens: ty.clone(),
            expr_tokens: ty,
        };
    }
    let mut segments = Vec::new();
    for param in generics.params.iter() {
        match param {
            GenericParam::Type(ty_param) => {
                if let Some(replacement) = replacements.iter().find(|replacement| replacement.ident == ty_param.ident) {
                    let ty = &replacement.ty;
                    segments.push(quote!(#ty));
                } else {
                    let ident = &ty_param.ident;
                    segments.push(quote!(#ident));
                }
            }
            GenericParam::Lifetime(lt_param) => {
                let lifetime = &lt_param.lifetime;
                segments.push(quote!(#lifetime));
            }
            GenericParam::Const(const_param) => {
                let ident = &const_param.ident;
                segments.push(quote!(#ident));
            }
        }
    }

    InstantiatedType {
        type_tokens: quote!(#ident < #( #segments ),* >),
        expr_tokens: quote!(#ident ::< #( #segments ),* >),
    }
}

impl InstantiatedType {
    fn ty(&self) -> &TokenStream2 {
        &self.type_tokens
    }

    fn expr(&self) -> &TokenStream2 {
        &self.expr_tokens
    }
}

fn build_impl_generics(generics: &Generics, privacy_param: &Ident, replacements: &[ModeReplacement]) -> Generics {
    let mut impl_generics = generics.clone();
    let mut filtered = Punctuated::new();
    for param in generics.params.iter() {
        let keep = match param {
            GenericParam::Type(ty_param) => ty_param.ident != *privacy_param,
            _ => true,
        };
        if keep {
            filtered.push(param.clone());
        }
    }
    impl_generics.params = filtered;
    if let Some(where_clause) = impl_generics.where_clause.as_mut() {
        let clause_clone = where_clause.clone();
        let mut replacer = WhereClauseReplacer { replacements };
        *where_clause = replacer.fold_where_clause(clause_clone);
    }
    impl_generics
}

struct WhereClauseReplacer<'a> {
    replacements: &'a [ModeReplacement],
}

impl<'a> Fold for WhereClauseReplacer<'a> {
    fn fold_type(&mut self, ty: Type) -> Type {
        if let Type::Path(type_path) = &ty {
            if type_path.qself.is_none() && type_path.path.segments.len() == 1 {
                let ident = &type_path.path.segments[0].ident;
                if let Some(replacement) = self.replacements.iter().find(|replacement| replacement.ident == *ident) {
                    return replacement.ty.clone();
                }
            }
        }
        syn::fold::fold_type(self, ty)
    }
}

fn type_uses_privacy_param(ty: &Type, privacy_param: &Ident) -> bool {
    let mut visitor = PrivacyTypeUsage {
        ident: privacy_param,
        found: false,
    };
    visitor.visit_type(ty);
    visitor.found
}

struct PrivacyTypeUsage<'a> {
    ident: &'a Ident,
    found: bool,
}

impl<'a, 'ast> Visit<'ast> for PrivacyTypeUsage<'a> {
    fn visit_type_path(&mut self, type_path: &'ast syn::TypePath) {
        if type_path.qself.is_none() && type_path.path.segments.len() == 1 && type_path.path.segments[0].ident == *self.ident {
            self.found = true;
            return;
        }
        syn::visit::visit_type_path(self, type_path);
    }
}

fn find_privacy_param(input: &DeriveInput) -> Result<Ident> {
    let mut found = None;
    for param in input.generics.params.iter() {
        if let GenericParam::Type(type_param) = param {
            let has_privacy_mode = type_param.bounds.iter().any(|bound| matches_privacy_mode(bound));
            if has_privacy_mode {
                if found.is_some() {
                    return Err(syn::Error::new(
                        type_param.ident.span(),
                        "derive(PrivateParts) supports exactly one PrivacyMode parameter",
                    ));
                }
                found = Some(type_param.ident.clone());
            }
        }
    }
    found.ok_or_else(|| syn::Error::new(input.ident.span(), "derive(PrivateParts) requires a generic parameter bound by PrivacyMode"))
}

fn matches_privacy_mode(bound: &TypeParamBound) -> bool {
    if let TypeParamBound::Trait(trait_bound) = bound {
        if let Some(segment) = trait_bound.path.segments.last() {
            return segment.ident == "PrivacyMode";
        }
    }
    false
}

struct PartsAttr {
    private_mode: Type,
    public_mode: Type,
    private_data_ty: Type,
}

impl PartsAttr {
    fn from_attrs(attrs: &[Attribute], crate_path: &TokenStream2) -> Result<Self> {
        let mut found = None;
        for attr in attrs {
            if attr.path().is_ident("parts") {
                if found.is_some() {
                    return Err(syn::Error::new(attr.span(), "duplicate #[parts] attribute"));
                }
                let parsed = attr.parse_args_with(PartsAttrArgs::parse)?;
                found = Some(parsed);
            }
        }
        let parsed =
            found.ok_or_else(|| syn::Error::new(Span::call_site(), "#[derive(PrivateParts)] requires a #[parts(...)] attribute"))?;
        let default_private = syn::parse2::<Type>(quote!(#crate_path::Full)).expect("Full type");
        let default_public = syn::parse2::<Type>(quote!(#crate_path::Public)).expect("Public type");
        Ok(Self {
            private_mode: parsed.private_mode.unwrap_or(default_private),
            public_mode: parsed.public_mode.unwrap_or(default_public),
            private_data_ty: parsed
                .private_data_ty
                .ok_or_else(|| syn::Error::new(Span::call_site(), "missing private_data type"))?,
        })
    }
}

struct PartsAttrArgs {
    private_mode: Option<Type>,
    public_mode: Option<Type>,
    private_data_ty: Option<Type>,
}

impl PartsAttrArgs {
    fn parse(input: ParseStream<'_>) -> Result<Self> {
        let mut private_mode = None;
        let mut public_mode = None;
        let mut private_data_ty = None;

        while !input.is_empty() {
            let ident: Ident = input.parse()?;
            input.parse::<syn::Token![=]>()?;
            let lit: LitStr = input.parse()?;
            let ty: Type = syn::parse_str(&lit.value()).map_err(|err| syn::Error::new(lit.span(), err))?;

            match ident.to_string().as_str() {
                "private" => {
                    if private_mode.is_some() {
                        return Err(syn::Error::new(ident.span(), "duplicate private entry"));
                    }
                    private_mode = Some(ty);
                }
                "public" => {
                    if public_mode.is_some() {
                        return Err(syn::Error::new(ident.span(), "duplicate public entry"));
                    }
                    public_mode = Some(ty);
                }
                "private_data" => {
                    if private_data_ty.is_some() {
                        return Err(syn::Error::new(ident.span(), "duplicate private_data entry"));
                    }
                    private_data_ty = Some(ty);
                }
                _ => return Err(syn::Error::new(ident.span(), "expected keys: private, public, private_data")),
            }

            if input.peek(syn::Token![,]) {
                input.parse::<syn::Token![,]>()?;
            }
        }

        Ok(Self {
            private_mode,
            public_mode,
            private_data_ty,
        })
    }
}

fn crate_path() -> TokenStream2 {
    let found = crate_name("private-parts").or_else(|_| crate_name("private_parts"));
    match found {
        Ok(FoundCrate::Itself) => quote!(crate),
        Ok(FoundCrate::Name(name)) => {
            let ident = Ident::new(&name, Span::call_site());
            quote!(::#ident)
        }
        Err(_) => quote!(::private_parts),
    }
}
