use std::io::Write;

use crate::UUID;

impl<B: Backend> FromSql<Binary, B> for UUID
where
    Vec<u8>: FromSql<Binary, B>,
{
    fn from_sql(bytes: Option<&B::RawValue>) -> diesel::deserialize::Result<Self> {
        let value = <Vec<u8>>::from_sql(bytes)?;
        Ok(UUID::from_bytes(&value)?)
    }
}

impl<B: Backend> ToSql<Binary, B> for UUID
where
    [u8]: ToSql<Binary, B>,
{
    fn to_sql<W: Write>(
        &self,
        out: &mut diesel::serialize::Output<W, B>,
    ) -> diesel::serialize::Result {
        let bytes = self.0.as_bytes();
        <[u8] as ToSql<Binary, B>>::to_sql(bytes, out)
    }
}

impl AsExpression<Binary> for UUID {
    type Expression = Bound<Binary, UUID>;

    fn as_expression(self) -> Self::Expression {
        Bound::new(self)
    }
}

impl<'a> AsExpression<Binary> for &'a UUID {
    type Expression = Bound<Binary, &'a UUID>;

    fn as_expression(self) -> Self::Expression {
        Bound::new(self)
    }
}
// impl Expression for UUID {
//     type SqlType = diesel::sql_types::Binary;
// }
