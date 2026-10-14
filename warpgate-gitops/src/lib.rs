pub mod parse;
pub mod types;

pub fn json_schema() -> schemars::Schema {
    schemars::schema_for!(types::Resource)
}
