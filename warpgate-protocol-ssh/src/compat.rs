use std::fmt::Display;

pub trait ContextExt<T, C> {
    fn context(self, context: C) -> anyhow::Result<T>;
}

impl<T, C> ContextExt<T, C> for Result<T, ()>
where
    C: Display + Send + Sync + 'static,
{
    fn context(self, context: C) -> anyhow::Result<T> {
        self.map_err(|_| anyhow::anyhow!("unspecified error").context(context))
    }
}
