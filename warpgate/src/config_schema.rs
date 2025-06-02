use schemars::schema_for;

fn main() {
    let schema = schema_for!(warpgate_common::WarpgateConfigStore);
    println!("{}", serde_json::to_string_pretty(&schema).unwrap());
}
