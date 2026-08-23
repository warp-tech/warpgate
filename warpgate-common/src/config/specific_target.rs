use super::target::{
    Target, TargetHTTPOptions, TargetKubernetesOptions, TargetMySqlOptions, TargetOptions,
    TargetPostgresOptions, TargetRdpOptions, TargetSSHOptions, TargetVncOptions,
};
use crate::{Protocol, WarpgateError};

/// One protocol's variant of [`TargetOptions`], extractable from the enum.
pub trait TargetOptionsVariant: Clone {
    /// The protocol this variant belongs to.
    const PROTOCOL: Protocol;
    fn extract(options: &TargetOptions) -> Option<&Self>;
}

macro_rules! target_options_variant {
    ($variant:ident, $options:ty, $protocol:expr) => {
        impl TargetOptionsVariant for $options {
            const PROTOCOL: Protocol = $protocol;
            fn extract(options: &TargetOptions) -> Option<&Self> {
                match options {
                    TargetOptions::$variant(options) => Some(options),
                    _ => None,
                }
            }
        }
    };
}

target_options_variant!(Ssh, TargetSSHOptions, Protocol::Ssh);
target_options_variant!(Http, TargetHTTPOptions, Protocol::Http);
target_options_variant!(Kubernetes, TargetKubernetesOptions, Protocol::Kubernetes);
target_options_variant!(MySql, TargetMySqlOptions, Protocol::MySql);
target_options_variant!(Postgres, TargetPostgresOptions, Protocol::Postgres);
target_options_variant!(Vnc, TargetVncOptions, Protocol::Vnc);
target_options_variant!(Rdp, TargetRdpOptions, Protocol::Rdp);

/// A [`Target`] whose options kind is carried in the type:
/// `SpecificTarget<TargetSSHOptions>` can only hold an SSH target, so
/// `options()` needs no pattern check. Derefs to the target for everything
/// else. The default parameter, `SpecificTarget<TargetOptions>`, is the
/// un-narrowed form that [`SpecificTarget::narrow`] narrows.
#[derive(Debug, Clone)]
pub struct SpecificTarget<O = TargetOptions> {
    target: Target,
    /// A copy of the matching variant, so `options()` is direct field access.
    options: O,
}

impl<O> SpecificTarget<O> {
    pub const fn options(&self) -> &O {
        &self.options
    }

    pub fn into_parts(self) -> (Target, O) {
        (self.target, self.options)
    }
}

impl<O: TargetOptionsVariant> SpecificTarget<O> {
    /// Narrows a freshly resolved target; fails when it is of another kind.
    pub fn new(target: Target) -> Result<Self, WarpgateError> {
        SpecificTarget::any(target).narrow()
    }

    pub const fn protocol(&self) -> Protocol {
        O::PROTOCOL
    }
}

impl SpecificTarget<TargetOptions> {
    pub fn any(target: Target) -> Self {
        let options = target.options.clone();
        Self { target, options }
    }

    pub fn narrow<O: TargetOptionsVariant>(self) -> Result<SpecificTarget<O>, WarpgateError> {
        match O::extract(&self.target.options) {
            Some(options) => {
                let options = options.clone();
                Ok(SpecificTarget {
                    target: self.target,
                    options,
                })
            }
            None => Err(WarpgateError::InvalidTarget),
        }
    }
}

impl<O> std::ops::Deref for SpecificTarget<O> {
    type Target = Target;
    fn deref(&self) -> &Target {
        &self.target
    }
}
