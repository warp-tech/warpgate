use anyhow::Result;
use std::io::stdin;
use warpgate_common::hash::hash_password;

pub(crate) async fn command() -> Result<()> {
    let mut input = String::new();

    if console::user_attended() {
        input = dialoguer::Password::new()
            .with_prompt("Password to be hashed")
            .interact()?;
    } else {
        stdin().read_line(&mut input)?;
    }

    let hash = hash_password(&input);
    println!("{}", hash);
    Ok(())
}
