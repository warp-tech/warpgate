//! Helper macros for PDU encoding and decoding
//!
//! Some are exported and available to external crates

#[macro_export]
macro_rules! decode_err {
    ($source:expr $(,)? ) => {
        <$crate::PduError as $crate::PduErrorExt>::decode($crate::ironrdp_core::function!(), $source)
    };
}

#[macro_export]
macro_rules! encode_err {
    ($source:expr $(,)? ) => {
        <$crate::PduError as $crate::PduErrorExt>::encode($crate::ironrdp_core::function!(), $source)
    };
}

#[macro_export]
macro_rules! pdu_other_err {
    ( $description:expr, source: $source:expr $(,)? ) => {{
        $crate::PduError::new($description, $crate::PduErrorKind::Other { description: $description }).with_source($source)
    }};
    ( $context:expr, $description:expr $(,)? ) => {{
        $crate::PduError::new($context, $crate::PduErrorKind::Other { description: $description })
    }};
    ( source: $source:expr $(,)? ) => {{
        $crate::pdu_other_err!($crate::ironrdp_core::function!(), "", source: $source)
    }};
    ( $description:expr $(,)? ) => {{
        $crate::pdu_other_err!($crate::ironrdp_core::function!(), $description)
    }};
}

// FIXME: some of these macros should be in ironrdp_core, and some should be private to ironrdp_pdu.

/// Asserts that constant expressions evaluate to `true`.
///
/// From <https://docs.rs/static_assertions/1.1.0/src/static_assertions/const_assert.rs.html#51-57>
#[macro_export]
macro_rules! const_assert {
    ($x:expr $(,)?) => {
        #[allow(unknown_lints, eq_op)]
        const _: [(); 0 - !{
            const ASSERT: bool = $x;
            ASSERT
        } as usize] = [];
    };
}

// TODO: move to ironrdp-core crate.
/// Implements additional traits for a plain old data structure (POD).
#[macro_export]
macro_rules! impl_pdu_pod {
    ($pdu_ty:ty) => {
        impl $crate::ironrdp_core::IntoOwned for $pdu_ty {
            type Owned = Self;

            fn into_owned(self) -> Self::Owned {
                self
            }
        }

        impl $crate::ironrdp_core::DecodeOwned for $pdu_ty {
            fn decode_owned(src: &mut ReadCursor<'_>) -> DecodeResult<Self> {
                <Self as $crate::ironrdp_core::Decode>::decode(src)
            }
        }
    };
}

/// Implements additional traits for a plain old data structure (POD).
#[macro_export]
macro_rules! impl_x224_pdu_pod {
    ($pdu_ty:ty) => {
        impl $crate::ironrdp_core::IntoOwned for $pdu_ty {
            type Owned = Self;

            fn into_owned(self) -> Self::Owned {
                self
            }
        }

        impl $crate::ironrdp_core::DecodeOwned for $pdu_ty {
            fn decode_owned(src: &mut ReadCursor<'_>) -> DecodeResult<Self> {
                <$crate::x224::X224<Self> as $crate::ironrdp_core::Decode>::decode(src).map(|p| p.0)
            }
        }
    };
}

// TODO: move to ironrdp-core crate.
/// Implements additional traits for a borrowing PDU and defines a static-bounded owned version.
#[macro_export]
macro_rules! impl_pdu_borrowing {
    ($pdu_ty:ident $(<$($lt:lifetime),+>)?, $owned_ty:ident) => {
        pub type $owned_ty = $pdu_ty<'static>;

        impl $crate::ironrdp_core::DecodeOwned for $owned_ty {
            fn decode_owned(src: &mut ReadCursor<'_>) -> DecodeResult<Self> {
                let pdu = <$pdu_ty $(<$($lt),+>)? as $crate::ironrdp_core::Decode>::decode(src)?;
                Ok($crate::ironrdp_core::IntoOwned::into_owned(pdu))
            }
        }
    };
}

/// Implements additional traits for a borrowing PDU and defines a static-bounded owned version.
#[macro_export]
macro_rules! impl_x224_pdu_borrowing {
    ($pdu_ty:ident $(<$($lt:lifetime),+>)?, $owned_ty:ident) => {
        pub type $owned_ty = $pdu_ty<'static>;

        impl $crate::ironrdp_core::DecodeOwned for $owned_ty {
            fn decode_owned(src: &mut ReadCursor<'_>) -> DecodeResult<Self> {
                let pdu = <$crate::x224::X224<$pdu_ty $(<$($lt),+>)?> as $crate::ironrdp_core::Decode>::decode(src).map(|r| r.0)?;
                Ok($crate::ironrdp_core::IntoOwned::into_owned(pdu))
            }
        }
    };
}

// FIXME: legacy macros below

#[macro_export]
macro_rules! try_read_optional {
    ($e:expr, $ret:expr) => {
        match $e {
            Ok(v) => v,
            Err(ref e) if e.kind() == io::ErrorKind::UnexpectedEof => {
                return Ok($ret);
            }
            Err(e) => return Err(From::from(e)),
        }
    };
}

#[macro_export]
macro_rules! try_write_optional {
    ($val:expr, $f:expr) => {
        if let Some(ref val) = $val {
            // This is a workaround for clippy false positive because
            // of macro expansion.
            #[expect(clippy::redundant_closure_call)]
            $f(val)?
        } else {
            return Ok(());
        }
    };
}
