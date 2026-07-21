macro_rules! ppk_const {
    ($name:ident, $key:expr) => {
        #[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
        pub struct $name;

        impl std::str::FromStr for $name {
            type Err = $crate::putty::key_value::PpkValueParsingError;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                if s == $key {
                    Ok(Self)
                } else {
                    Err($crate::putty::key_value::PpkValueParsingError {
                        expected: $key,
                        actual: s.to_string(),
                    })
                }
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str($key)
            }
        }

        impl PpkLiteral for $name {
            fn context() -> &'static str {
                stringify!($name)
            }

            fn as_static_str(&self) -> &'static str {
                $key
            }
        }
    };
}

macro_rules! impl_ppk_enum_expected_str {
    ($first:expr, $($keys:expr),+) => {
        concat!($first, ", ", $($keys),+)
    };
    ($first:expr) => {
        $first
    };
}

macro_rules! ppk_enum {
    ($name:ident, $($variant:ident => $key:expr),+) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub enum $name {
            $($variant),+
        }

        impl std::str::FromStr for $name {
            type Err = $crate::putty::key_value::PpkValueParsingError;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                match s {
                    $($key => Ok(Self::$variant),)+
                    _ => Err($crate::putty::key_value::PpkValueParsingError {
                        expected: concat!("[", impl_ppk_enum_expected_str!($($key),+), "]"),
                        actual: s.to_string()
                    })
                }
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                match self {
                    $(Self::$variant => f.write_str($key),)+
                }
            }
        }

        impl PpkLiteral for $name {
            fn context() -> &'static str {
                stringify!($name)
            }

            fn as_static_str(&self) -> &'static str {
                match self {
                    $(Self::$variant => $key,)+
                }
            }
        }
    };
}

macro_rules! ppk_generic_value {
    ($name:ident, $type:ident) => {
        pub struct $name($type);

        impl std::str::FromStr for $name {
            type Err = $crate::putty::key_value::PpkValueParsingError;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                s.parse()
                    .map(Self)
                    .map_err(|_| $crate::putty::key_value::PpkValueParsingError {
                        expected: concat!("<valid ", stringify!($type), " value>"),
                        actual: s.to_string(),
                    })
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                self.0.fmt(f)
            }
        }

        impl From<$type> for $name {
            fn from(value: $type) -> Self {
                Self(value)
            }
        }

        impl From<$name> for $type {
            fn from(value: $name) -> Self {
                value.0
            }
        }
    };
}

macro_rules! ppk_key_value {
    ($name:ident, $key:ident, $value:ident) => {
        pub struct $name;

        impl $crate::putty::key_value::PpkKeyValue for $name {
            type Key = $key;
            type Value = $value;
        }
    };
}

macro_rules! ppk_multiline_key_value {
    ($name:ident, $key:ident, $value:ident) => {
        pub struct $name;

        impl $crate::putty::key_value::PpkMultilineKeyValue for $name {
            type Key = $key;
            type Value = $value;
        }
    };
}

pub(crate) use {
    impl_ppk_enum_expected_str, ppk_const, ppk_enum, ppk_generic_value, ppk_key_value, ppk_multiline_key_value,
};
