use std::collections::HashMap;
use std::fmt::Debug;
use std::ops::DerefMut;
use tracing::field::Visit;
use tracing_core::Field;

pub type SerializedRecordValuesInner = HashMap<&'static str, String>;
pub struct SerializedRecordValues(SerializedRecordValuesInner);

impl SerializedRecordValues {
    pub fn new() -> Self {
        Self(HashMap::new())
    }

    pub fn into_values(self) -> SerializedRecordValuesInner {
        self.0
    }
}

impl std::ops::Deref for SerializedRecordValues {
    type Target = SerializedRecordValuesInner;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for SerializedRecordValues {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

pub struct RecordVisitor<'a> {
    values: &'a mut SerializedRecordValues,
}

impl<'a> RecordVisitor<'a> {
    pub fn new(values: &'a mut SerializedRecordValues) -> Self {
        Self { values }
    }
}

impl<'a> Visit for RecordVisitor<'a> {
    fn record_str(&mut self, field: &Field, value: &str) {
        self.values.insert(field.name(), value.to_string());
    }

    fn record_debug(&mut self, field: &Field, value: &dyn Debug) {
        self.values.insert(field.name(), format!("{:?}", value));
    }
}
