#[allow(clippy::unwrap_used)]
fn main() {
    let schema = warpgate_gitops::json_schema();
    println!("{}", serde_json::to_string_pretty(&schema).unwrap());
}
