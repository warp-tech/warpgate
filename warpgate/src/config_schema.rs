use schemars::schema_for;

#[allow(clippy:unwrap_used)]
fn main() {
    let schema = schema_for!(warpgate_common::WarpgateConfigStore);
    println!("{}", serde_json::to_string_pretty(&schema).unwrap());
}
