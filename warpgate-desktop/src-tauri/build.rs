fn main() {
    // Declaring the commands explicitly means they are only callable where a
    // capability grants them (the local setup page), never from the remote Warpgate UI.
    tauri_build::try_build(tauri_build::Attributes::new().app_manifest(
        tauri_build::AppManifest::new().commands(&["connect", "current_server"]),
    ))
    .expect("failed to run tauri-build");
}
