use convert_case::{Case, Casing};
use proc_macro::TokenStream;
use proc_macro2::{Literal, TokenStream as TokenStream2};
use quote::{quote, quote_spanned};
use std::{fs, path::Path};
use syn::{parse_macro_input, spanned::Spanned, Data, DeriveInput, Expr, Fields, Ident, Lit, Type};

// example:
// #[derive(CtfEventClass)]
// #[event_name = "TRACE_START"]
// pub struct TraceStart<'a> {
//     pub task_handle: i64,
//     pub task: &'a CStr,
// }
#[proc_macro_derive(CtfEventClass, attributes(event_name, event_name_from_event_type))]
pub fn derive_ctf_event_class(input: TokenStream) -> TokenStream {
    // TODO generic enum handling, TaskState is an enum
    let supported_types = ["i64", "u64", "CStr", "TaskState"];

    let input = parse_macro_input!(input as DeriveInput);

    let type_name = input.ident;

    let attr_event_name = input.attrs.iter().find_map(|a| {
        if let Ok(val) = a.meta.require_name_value() {
            if val.path.is_ident("event_name") {
                if let Expr::Lit(lit) = &val.value {
                    if let Lit::Str(s) = &lit.lit {
                        let name = s.value();
                        return Some(Ident::new(&name, val.path.span()));
                    }
                }
            }
        }
        None
    });
    let name_from_event_type = input
        .attrs
        .iter()
        .any(|a| a.meta.path().is_ident("event_name_from_event_type"));

    let event_name = if let Some(n) = attr_event_name {
        n
    } else {
        Ident::new(
            &type_name.to_string().to_case(Case::Snake),
            type_name.span(),
        )
    };
    let event_name_bytes = format!("{}\0", event_name);
    let event_name_raw_str = Literal::byte_string(event_name_bytes.as_bytes());

    let struct_fields = if let Data::Struct(s) = input.data {
        s.fields
    } else {
        return quote_spanned! {
            type_name.span() => compile_error!(
                "Can only derive CtfEventClass on structs."
            );
        }
        .into();
    };

    let mut field_class_impls = Vec::new();
    let mut field_impls = Vec::new();
    match struct_fields {
        Fields::Named(fields) => {
            for (field_index, field) in fields.named.into_iter().enumerate() {
                let field_name = field
                    .ident
                    .as_ref()
                    .expect("Failed to get struct field identifier.");
                match field.ty {
                    Type::Path(t) => {
                        let typ = t
                            .path
                            .get_ident()
                            .expect("Failed to get struct field type.")
                            .to_string();
                        if !supported_types.contains(&typ.as_str()) {
                            return quote_spanned! {
                                type_name.span() => compile_error!(
                                    "Deriving CtfEventClass for the type is not supported."
                                );
                            }
                            .into();
                        }
                        field_class_impls.push(event_class_field_class(field_name, &typ));
                        field_impls.push(event_field(field_index, field_name, &typ));
                    }
                    Type::Reference(t) => {
                        let typ = if let Type::Path(t) = t.elem.as_ref() {
                            t.path
                                .get_ident()
                                .expect("Failed to get struct field type.")
                                .to_string()
                        } else {
                            return quote_spanned! {
                                type_name.span() => compile_error!(
                                    "Deriving CtfEventClass for the type is not supported."
                                );
                            }
                            .into();
                        };
                        if !supported_types.contains(&typ.as_str()) {
                            return quote_spanned! {
                                type_name.span() => compile_error!(
                                    "Deriving CtfEventClass for the type is not supported."
                                );
                            }
                            .into();
                        }
                        field_class_impls.push(event_class_field_class(field_name, &typ));
                        field_impls.push(event_field(field_index, field_name, &typ));
                    }
                    _ => {
                        return quote_spanned! {
                            type_name.span() => compile_error!(
                                "Deriving CtfEventClass for the type is not supported."
                            );
                        }
                        .into()
                    }
                }
            }
        }
        _ => {
            return quote_spanned! {
                type_name.span() => compile_error!(
                    "Deriving CtfEventClass for the type is not supported."
                );
            }
            .into()
        }
    }

    let has_payload_field = !field_class_impls.is_empty();
    let mut field_classes = TokenStream2::new();
    field_classes.extend(field_class_impls);
    let mut field_setters = TokenStream2::new();
    field_setters.extend(field_impls);

    let payload_fc_begin = has_payload_field.then(|| {
        quote! {
            let payload_fc = ffi::bt_field_class_structure_create(trace_class);
        }
    });
    let payload_fc_end = has_payload_field.then(|| {
        quote! {
            let ret = ffi::bt_event_class_set_payload_field_class(event_class, payload_fc);
            ret.capi_result()?;
            ffi::bt_field_class_put_ref(payload_fc);
        }
    });

    let payload_f_begin = has_payload_field.then(|| {
        quote! {
            let payload_f = ffi::bt_event_borrow_payload_field(ctf_event);
        }
    });

    let event_class_impl = if name_from_event_type {
        quote! {
            pub(crate) fn event_class(event_type: trace_recorder_parser::streaming::event::EventType, stream_class: *mut babeltrace2_sys::ffi::bt_stream_class) -> Result<*mut babeltrace2_sys::ffi::bt_event_class, babeltrace2_sys::Error> {
                use babeltrace2_sys::{ffi, BtResultExt};
                use std::ffi::CString;

                unsafe {
                    let trace_class = ffi::bt_stream_class_borrow_trace_class(stream_class);

                    let event_class = ffi::bt_event_class_create(stream_class);
                    let event_name = CString::new(event_type.to_string())?;
                    let ret = ffi::bt_event_class_set_name(event_class, event_name.as_c_str().as_ptr() as _);
                    ret.capi_result()?;

                    #payload_fc_begin

                    #field_classes

                    #payload_fc_end

                    Ok(event_class)
                }
            }
        }
    } else {
        quote! {
            pub(crate) fn event_class(stream_class: *mut babeltrace2_sys::ffi::bt_stream_class) -> Result<*mut babeltrace2_sys::ffi::bt_event_class, babeltrace2_sys::Error> {
                use babeltrace2_sys::{ffi, BtResultExt};

                unsafe {
                    let trace_class = ffi::bt_stream_class_borrow_trace_class(stream_class);

                    let event_class = ffi::bt_event_class_create(stream_class);
                    let ret = ffi::bt_event_class_set_name(event_class, #event_name_raw_str.as_ptr() as _);
                    ret.capi_result()?;

                    #payload_fc_begin

                    #field_classes

                    #payload_fc_end

                    Ok(event_class)
                }
            }
        }
    };

    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();
    let impl_block = quote! {
        impl #impl_generics #type_name #ty_generics #where_clause {
            #event_class_impl

            pub(crate) fn emit_event(&self, ctf_event: *mut babeltrace2_sys::ffi::bt_event) -> Result<(), babeltrace2_sys::Error> {
                use babeltrace2_sys::{ffi, BtResultExt};

                unsafe {
                    #payload_f_begin

                    #field_setters

                    Ok(())
                }
            }
        }
    };

    let ts = TokenStream::from(impl_block);

    let target_dir = Path::new("target");
    if target_dir.exists() {
        let out_dir = target_dir.join("ctf_events");
        if !out_dir.exists() {
            fs::create_dir_all(&out_dir).ok();
        }
        fs::write(
            format!(
                "{}/ctf_event_expansion__{}.rs",
                out_dir.display(),
                type_name
            ),
            ts.to_string(),
        )
        .ok();
    }
    ts
}

fn event_class_field_class(field_name: &Ident, typ: &str) -> TokenStream2 {
    let name_bytes = format!("{}\0", field_name);
    let byte_str = Literal::byte_string(name_bytes.as_bytes());
    let fc_create = match typ {
        "i64" => {
            quote! {
                let fc = ffi::bt_field_class_integer_signed_create(trace_class);
            }
        }
        "u64" => {
            quote! {
                let fc = ffi::bt_field_class_integer_unsigned_create(trace_class);
            }
        }
        "CStr" => {
            quote! {
                let fc = ffi::bt_field_class_string_create(trace_class);
            }
        }
        // enums
        "TaskState" => {
            quote! {
                let fc = ffi::bt_field_class_enumeration_signed_create(trace_class);
                let variants = enum_iterator::all::<TaskState>().collect::<Vec<_>>();
                for variant in variants.into_iter() {
                    let variant_rs = ffi::bt_integer_range_set_signed_create();
                    let ret = ffi::bt_integer_range_set_signed_add_range(
                        variant_rs,
                        variant.as_i64(),
                        variant.as_i64(),
                    );
                    ret.capi_result()?;
                    let ret = ffi::bt_field_class_enumeration_signed_add_mapping(
                        fc,
                        variant.as_ffi(),
                        variant_rs,
                    );
                    ret.capi_result()?;
                    ffi::bt_integer_range_set_signed_put_ref(variant_rs);
                }
            }
        }
        // Checked by the caller
        _ => unreachable!(),
    };

    quote! {
        #fc_create
        let ret = ffi::bt_field_class_structure_append_member(
            payload_fc,
            #byte_str.as_ptr() as _,
            fc,
        );
        ret.capi_result()?;
        ffi::bt_field_class_put_ref(fc);
    }
}

fn event_field(field_index: usize, field_name: &Ident, typ: &str) -> TokenStream2 {
    let f_set = match typ {
        "i64" => {
            quote! {
                ffi::bt_field_integer_signed_set_value(f, self.#field_name);
            }
        }
        "u64" => {
            quote! {
                ffi::bt_field_integer_unsigned_set_value(f, self.#field_name);
            }
        }
        "CStr" => {
            quote! {
                let ret = ffi::bt_field_string_set_value(f, self.#field_name.as_ptr());
                ret.capi_result()?;
            }
        }
        // enums
        "TaskState" => {
            quote! {
                ffi::bt_field_integer_signed_set_value(f, self.#field_name.as_i64());
            }
        }
        // Checked by the caller
        _ => unreachable!(),
    };

    quote! {
        let f = ffi::bt_field_structure_borrow_member_field_by_index(payload_f, #field_index as u64);
        #f_set
    }
}
