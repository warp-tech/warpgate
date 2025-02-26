pub trait Encode<'en, Context = ()> {
    fn encode(&self, buf: &mut Vec<u8>)
    where
        Self: Encode<'en, ()>,
    {
        self.encode_with(buf, ());
    }

    fn encode_with(&self, buf: &mut Vec<u8>, context: Context);
}

impl<C> Encode<'_, C> for &'_ [u8] {
    fn encode_with(&self, buf: &mut Vec<u8>, _: C) {
        buf.extend_from_slice(self);
    }
}
