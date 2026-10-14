pub mod diagnostic;
pub mod parse;
pub mod types;
pub mod validate;

pub fn json_schema() -> schemars::Schema {
    schemars::schema_for!(types::Resource)
}
