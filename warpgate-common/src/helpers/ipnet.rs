use std::ops::Deref;

use ::ipnet::IpNet;
use poem_openapi::types::{ParseError, ParseFromJSON, ParseResult, ToJSON, Type};

#[derive(Debug, Clone)]
pub struct WarpgateIpNet(IpNet, String);

impl Deref for WarpgateIpNet {
    type Target = IpNet;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<IpNet> for WarpgateIpNet {
    fn from(value: IpNet) -> Self {
        let string = value.to_string();
        Self(value, string)
    }
}

impl Type for WarpgateIpNet {
    fn schema_ref() -> poem_openapi::registry::MetaSchemaRef {
        String::schema_ref()
    }

    const IS_REQUIRED: bool = true;

    type RawValueType = String;

    type RawElementValueType = String;

    fn name() -> std::borrow::Cow<'static, str> {
        <String as Type>::name()
    }

    fn as_raw_value(&self) -> Option<&Self::RawValueType> {
        Some(&self.1)
    }

    fn raw_element_iter<'a>(
        &'a self,
    ) -> Box<dyn Iterator<Item = &'a Self::RawElementValueType> + 'a> {
        Box::new(self.as_raw_value().into_iter())
    }
}

impl ParseFromJSON for WarpgateIpNet {
    fn parse_from_json(value: Option<serde_json::Value>) -> ParseResult<Self> {
        let string = String::parse_from_json(value)
            .map_err(|e| ParseError::custom(format!("string: {e:?}")))?;
        let ipnet = string
            .parse()
            .map_err(|e| ParseError::custom(format!("could not parse network address: {e:?}")))?;
        Ok(WarpgateIpNet(ipnet, string))
    }
}

impl ToJSON for WarpgateIpNet {
    fn to_json(&self) -> Option<serde_json::Value> {
        self.1.to_json()
    }
}
