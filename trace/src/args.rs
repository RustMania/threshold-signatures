use std::collections::{HashMap, HashSet};
use std::iter::FromIterator;
use syn::{self, spanned::Spanned};

#[derive(Clone)]
pub(crate) struct Args {
    pub(crate) prefix_enter: Prefix,
    pub(crate) prefix_exit: Prefix,
    pub(crate) filter: Filter,
    pub(crate) pause: bool,
    pub(crate) pretty: bool,
    pub(crate) args_format: HashMap<proc_macro2::Ident, String>,
}

#[derive(Clone)]
pub(crate) enum Filter {
    None,
    Enable(HashSet<proc_macro2::Ident>),
    Disable(HashSet<proc_macro2::Ident>),
}

#[derive(Clone)]
pub(crate) struct Prefix(Option<String>);

impl Prefix {
    const DEFAULT_ENTER: &'static str = ">>>";
    const DEFAULT_EXIT: &'static str = "<<<";

    pub(crate) fn enter(&self) -> String {
        format!(
            "{} {}",
            Self::DEFAULT_ENTER,
            self.0.as_deref().unwrap_or("")
        )
    }

    pub(crate) fn exit(&self) -> String {
        format!("{} {}", Self::DEFAULT_EXIT, self.0.as_deref().unwrap_or(""))
    }
}

impl<'a> FromIterator<&'a Prefix> for Prefix {
    fn from_iter<T: IntoIterator<Item = &'a Prefix>>(iter: T) -> Self {
        let mut segments = Vec::new();

        for item in iter {
            if let Some(value) = item.0.as_ref() {
                segments.push(value.clone());
            }
        }

        Prefix(if segments.is_empty() {
            None
        } else {
            Some(segments.join(""))
        })
    }
}

const DEFAULT_PAUSE: bool = false;
const DEFAULT_PRETTY: bool = false;

impl Args {
    pub(crate) fn from_raw_args(raw_args: syn::AttributeArgs) -> Result<Self, Vec<syn::Error>> {
        // Different types of arguments accepted by `#[trace]`;
        // spans are needed for friendly error reporting of duplicate arguments
        #[allow(clippy::enum_variant_names)]
        enum Arg {
            PrefixEnter(proc_macro2::Span, String),
            PrefixExit(proc_macro2::Span, String),
            Prefix(proc_macro2::Span, String),
            Enable(proc_macro2::Span, HashSet<proc_macro2::Ident>),
            Disable(proc_macro2::Span, HashSet<proc_macro2::Ident>),
            Pause(proc_macro2::Span, bool),
            Pretty(proc_macro2::Span, bool),
            ArgFormat(proc_macro2::Span, (proc_macro2::Ident, String)),
        }

        // Parse arguments
        let args_res = raw_args.into_iter().map(|nested_meta| match nested_meta {
            syn::NestedMeta::Meta(ref meta) => {
                enum ArgName {
                    PrefixEnter,
                    PrefixExit,
                    Prefix,
                    Enable,
                    Disable,
                    Pause,
                    Pretty,
                    ArgFormat,
                }

                let ident = meta.name();
                let arg_name = match ident.to_string().as_str() {
                    "prefix_enter" => ArgName::PrefixEnter,
                    "prefix_exit" => ArgName::PrefixExit,
                    "prefix" => ArgName::Prefix,
                    "enable" => ArgName::Enable,
                    "disable" => ArgName::Disable,
                    "pause" => ArgName::Pause,
                    "pretty" => ArgName::Pretty,
                    _ => ArgName::ArgFormat,
                };

                let prefix_enter_type_error = || {
                    vec![syn::Error::new_spanned(
                        ident.clone(),
                        "`prefix_enter` requires a string value",
                    )]
                };
                let prefix_exit_type_error = || {
                    vec![syn::Error::new_spanned(
                        ident.clone(),
                        "`prefix_exit` requires a string value",
                    )]
                };
                let prefix_type_error = || {
                    vec![syn::Error::new_spanned(
                        ident.clone(),
                        "`prefix` requires a string value",
                    )]
                };
                let enable_type_error = || {
                    vec![syn::Error::new_spanned(
                        ident.clone(),
                        "`enable` requires a list of meta words",
                    )]
                };
                let disable_type_error = || {
                    vec![syn::Error::new_spanned(
                        ident.clone(),
                        "`disable` requires a list of meta words",
                    )]
                };
                let pause_type_error = || {
                    vec![syn::Error::new_spanned(
                        ident.clone(),
                        "`pause` must be a meta word",
                    )]
                };
                let pretty_type_error = || {
                    vec![syn::Error::new_spanned(
                        ident.clone(),
                        "`pretty` must be a meta word",
                    )]
                };
                let arg_format_error = || {
                    vec![syn::Error::new_spanned(
                        ident.clone(),
                        "variable formatter requires a string value",
                    )]
                };

                match *meta {
                    syn::Meta::Word(_) => match arg_name {
                        ArgName::Pause => Ok(Arg::Pause(meta.span(), true)),
                        ArgName::Pretty => Ok(Arg::Pretty(meta.span(), true)),

                        ArgName::PrefixEnter => Err(prefix_enter_type_error()),
                        ArgName::PrefixExit => Err(prefix_exit_type_error()),
                        ArgName::Prefix => Err(prefix_type_error()),
                        ArgName::Enable => Err(enable_type_error()),
                        ArgName::Disable => Err(disable_type_error()),
                        ArgName::ArgFormat => Err(arg_format_error()),
                    },
                    syn::Meta::List(syn::MetaList { ref nested, .. }) => match arg_name {
                        ArgName::Enable => {
                            let mut idents = HashSet::new();
                            let mut other_nested_meta_errors = Vec::new();

                            nested.iter().for_each(|nested_meta| match *nested_meta {
                                syn::NestedMeta::Meta(syn::Meta::Word(ref word)) => {
                                    idents.insert(word.clone());
                                }
                                _ => other_nested_meta_errors.push(syn::Error::new_spanned(
                                    nested_meta,
                                    "`enable` must contain words only",
                                )),
                            });

                            if other_nested_meta_errors.is_empty() {
                                Ok(Arg::Enable(meta.span(), idents))
                            } else {
                                Err(other_nested_meta_errors)
                            }
                        }
                        ArgName::Disable => {
                            let mut idents = HashSet::new();
                            let mut other_nested_meta_errors = Vec::new();

                            nested.iter().for_each(|nested_meta| match *nested_meta {
                                syn::NestedMeta::Meta(syn::Meta::Word(ref word)) => {
                                    idents.insert(word.clone());
                                }
                                _ => other_nested_meta_errors.push(syn::Error::new_spanned(
                                    nested_meta,
                                    "`disable` must contain words only",
                                )),
                            });

                            if other_nested_meta_errors.is_empty() {
                                Ok(Arg::Disable(meta.span(), idents))
                            } else {
                                Err(other_nested_meta_errors)
                            }
                        }

                        ArgName::PrefixEnter => Err(prefix_enter_type_error()),
                        ArgName::PrefixExit => Err(prefix_exit_type_error()),
                        ArgName::Prefix => Err(prefix_type_error()),
                        ArgName::ArgFormat => Err(arg_format_error()),
                        ArgName::Pause => Err(pause_type_error()),
                        ArgName::Pretty => Err(pretty_type_error()),
                    },
                    syn::Meta::NameValue(syn::MetaNameValue {
                        ref ident, ref lit, ..
                    }) => match arg_name {
                        ArgName::PrefixEnter => match *lit {
                            syn::Lit::Str(ref lit_str) => {
                                Ok(Arg::PrefixEnter(meta.span(), lit_str.value()))
                            }
                            _ => Err(vec![syn::Error::new_spanned(
                                lit,
                                "`prefix_enter` must have a string value",
                            )]),
                        },
                        ArgName::PrefixExit => match *lit {
                            syn::Lit::Str(ref lit_str) => {
                                Ok(Arg::PrefixExit(meta.span(), lit_str.value()))
                            }
                            _ => Err(vec![syn::Error::new_spanned(
                                lit,
                                "`prefix_exit` must have a string value",
                            )]),
                        },
                        ArgName::Prefix => match *lit {
                            syn::Lit::Str(ref lit_str) => {
                                Ok(Arg::Prefix(meta.span(), lit_str.value()))
                            }
                            _ => Err(vec![syn::Error::new_spanned(
                                lit,
                                "`prefix` must have a string value",
                            )]),
                        },
                        ArgName::ArgFormat => match *lit {
                            syn::Lit::Str(ref lit_str) => Ok(Arg::ArgFormat(
                                meta.span(),
                                (ident.clone(), lit_str.value()),
                            )),
                            _ => Err(vec![syn::Error::new_spanned(
                                lit,
                                "value formatter must have a string value",
                            )]),
                        },

                        ArgName::Enable => Err(enable_type_error()),
                        ArgName::Disable => Err(disable_type_error()),
                        ArgName::Pause => Err(pause_type_error()),
                        ArgName::Pretty => Err(pretty_type_error()),
                    },
                }
            }
            syn::NestedMeta::Literal(_) => Err(vec![syn::Error::new_spanned(
                nested_meta,
                "literal attribute not allowed",
            )]),
        });

        let mut prefix_enter_args = Vec::new();
        let mut prefix_exit_args = Vec::new();
        let mut prefix_args = Vec::new();
        let mut enable_args = Vec::new();
        let mut disable_args = Vec::new();
        let mut pause_args = Vec::new();
        let mut pretty_args = Vec::new();
        let mut arg_format_args = HashMap::new();
        let mut errors = Vec::new();

        // Group arguments of the same type and errors
        for arg_res in args_res {
            match arg_res {
                Ok(arg) => match arg {
                    Arg::PrefixEnter(span, s) => prefix_enter_args.push((span, s)),
                    Arg::PrefixExit(span, s) => prefix_exit_args.push((span, s)),
                    Arg::Prefix(span, s) => prefix_args.push((span, s)),
                    Arg::Enable(span, idents) => enable_args.push((span, idents)),
                    Arg::Disable(span, idents) => disable_args.push((span, idents)),
                    Arg::Pause(span, b) => pause_args.push((span, b)),
                    Arg::Pretty(span, b) => pretty_args.push((span, b)),
                    Arg::ArgFormat(span, (ident, format)) => {
                        #[allow(clippy::map_entry)]
                        if !arg_format_args.contains_key(&ident) {
                            arg_format_args.insert(ident, format);
                        } else {
                            errors.push(syn::Error::new(
                                span,
                                &format!("duplicate formatting for `{}`", ident.to_string()),
                            ))
                        }
                    }
                },
                Err(es) => errors.extend(es),
            }
        }

        // Report duplicates
        if prefix_enter_args.len() >= 2 {
            errors.extend(
                prefix_enter_args
                    .iter()
                    .map(|(span, _)| syn::Error::new(*span, "duplicate `prefix_enter`")),
            );
        }
        if prefix_exit_args.len() >= 2 {
            errors.extend(
                prefix_exit_args
                    .iter()
                    .map(|(span, _)| syn::Error::new(*span, "duplicate `prefix_exit`")),
            );
        }
        if prefix_args.len() >= 2 {
            errors.extend(
                prefix_args
                    .iter()
                    .map(|(span, _)| syn::Error::new(*span, "duplicate `prefix`")),
            );
        }
        if enable_args.len() >= 2 {
            errors.extend(
                enable_args
                    .iter()
                    .map(|(span, _)| syn::Error::new(*span, "duplicate `enable`")),
            );
        }
        if disable_args.len() >= 2 {
            errors.extend(
                disable_args
                    .iter()
                    .map(|(span, _)| syn::Error::new(*span, "duplicate `disable`")),
            );
        }
        if pause_args.len() >= 2 {
            errors.extend(
                pause_args
                    .iter()
                    .map(|(span, _)| syn::Error::new(*span, "duplicate `pause`")),
            );
        }
        if pretty_args.len() >= 2 {
            errors.extend(
                pretty_args
                    .iter()
                    .map(|(span, _)| syn::Error::new(*span, "duplicate `pretty`")),
            );
        }

        // Report the presence of mutually exclusive arguments
        if !enable_args.is_empty() && !disable_args.is_empty() {
            errors.push(syn::Error::new(
                enable_args[0].0,
                "cannot have both `enable` and `disable`",
            ));
            errors.push(syn::Error::new(
                disable_args[0].0,
                "cannot have both `enable` and `disable`",
            ));
        }

        // No other prefixes are allowed if `prefix` is set.
        if !prefix_args.is_empty() && !prefix_enter_args.is_empty() {
            errors.push(syn::Error::new(
                prefix_args[0].0,
                "cannot have both `prefix` and `prefix_enter`",
            ));
            errors.push(syn::Error::new(
                prefix_enter_args[0].0,
                "cannot have both `prefix` and `prefix_enter`",
            ));
        }

        if !prefix_args.is_empty() && !prefix_exit_args.is_empty() {
            errors.push(syn::Error::new(
                prefix_args[0].0,
                "cannot have both `prefix` and `prefix_exit`",
            ));
            errors.push(syn::Error::new(
                prefix_exit_args[0].0,
                "cannot have both `prefix` and `prefix_exit`",
            ));
        }

        if errors.is_empty() {
            macro_rules! first_no_span {
                ($iterable:expr) => {
                    $iterable.into_iter().next().map(|(_, elem)| elem)
                };
            }

            let (prefix_enter, prefix_exit) = if prefix_args.is_empty() {
                (
                    first_no_span!(prefix_enter_args),
                    first_no_span!(prefix_exit_args),
                )
            } else {
                let common_prefix = first_no_span!(prefix_args);
                (common_prefix.clone(), common_prefix)
            };
            let prefix_enter = prefix_enter
                .map(|prefix| Prefix(Some(prefix)))
                .unwrap_or_else(|| Prefix(None));
            let prefix_exit = prefix_exit
                .map(|prefix| Prefix(Some(prefix)))
                .unwrap_or_else(|| Prefix(None));

            let filter = match (first_no_span!(enable_args), first_no_span!(disable_args)) {
                (None, None) => Filter::None,
                (Some(idents), None) => Filter::Enable(idents),
                (None, Some(idents)) => Filter::Disable(idents),
                (Some(_), Some(_)) => unreachable!(),
            };
            let pause = first_no_span!(pause_args).unwrap_or(DEFAULT_PAUSE);
            let pretty = first_no_span!(pretty_args).unwrap_or(DEFAULT_PRETTY);

            Ok(Self {
                prefix_enter,
                prefix_exit,
                filter,
                pause,
                pretty,
                args_format: arg_format_args,
            })
        } else {
            Err(errors)
        }
    }
}
