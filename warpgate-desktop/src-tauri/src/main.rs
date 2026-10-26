#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::fs;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use tauri::menu::{Menu, MenuItem, PredefinedMenuItem, Submenu};
use tauri::{AppHandle, Manager, Runtime, Url, WebviewUrl, WebviewWindowBuilder};

const MAIN_WINDOW: &str = "main";
const SETUP_PAGE: &str = "index.html";
/// Where the Warpgate web UI is mounted on the server.
const UI_PATH: &str = "/@warpgate";

#[derive(Serialize, Deserialize)]
struct Settings {
    server_url: Url,
}

fn settings_path<R: Runtime>(app: &AppHandle<R>) -> Result<PathBuf, String> {
    app.path()
        .app_config_dir()
        .map(|dir| dir.join("settings.json"))
        .map_err(|e| e.to_string())
}

fn load_server_url<R: Runtime>(app: &AppHandle<R>) -> Option<Url> {
    let raw = fs::read_to_string(settings_path(app).ok()?).ok()?;
    serde_json::from_str::<Settings>(&raw).ok().map(|s| s.server_url)
}

fn save_server_url<R: Runtime>(app: &AppHandle<R>, server_url: &Url) -> Result<(), String> {
    let path = settings_path(app)?;
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    }
    let settings = Settings {
        server_url: server_url.clone(),
    };
    let json = serde_json::to_string_pretty(&settings).map_err(|e| e.to_string())?;
    fs::write(path, json).map_err(|e| e.to_string())
}

/// Accepts `warpgate.example.com`, `https://warpgate.example.com`, or a full
/// `.../@warpgate` link, and returns the URL of the web UI.
fn normalize_server_url(input: &str) -> Result<Url, String> {
    let input = input.trim();
    if input.is_empty() {
        return Err("Enter your Warpgate server address.".into());
    }
    let with_scheme = if input.contains("://") {
        input.to_string()
    } else {
        format!("https://{input}")
    };
    let mut url = Url::parse(&with_scheme).map_err(|e| format!("Not a valid URL: {e}"))?;
    if !matches!(url.scheme(), "https" | "http") {
        return Err("The address must start with https:// or http://".into());
    }
    if url.host_str().is_none() {
        return Err("The address is missing a host name.".into());
    }
    if url.path().is_empty() || url.path() == "/" {
        url.set_path(UI_PATH);
    }
    url.set_query(None);
    url.set_fragment(None);
    Ok(url)
}

/// URL of the bundled setup page, for navigating back to it from the remote UI.
fn setup_page_url<R: Runtime>(app: &AppHandle<R>) -> Url {
    if tauri::is_dev() {
        if let Some(dev_url) = &app.config().build.dev_url {
            if let Ok(url) = dev_url.join(SETUP_PAGE) {
                return url;
            }
        }
    }
    let base = if cfg!(windows) {
        "http://tauri.localhost/"
    } else {
        "tauri://localhost/"
    };
    Url::parse(base)
        .and_then(|u| u.join(SETUP_PAGE))
        .expect("static setup URL is valid")
}

#[tauri::command]
fn current_server(app: AppHandle) -> Option<String> {
    load_server_url(&app).map(|u| u.to_string())
}

#[tauri::command]
fn connect(app: AppHandle, url: String) -> Result<String, String> {
    let url = normalize_server_url(&url)?;
    save_server_url(&app, &url)?;
    let window = app
        .get_webview_window(MAIN_WINDOW)
        .ok_or("Main window is not open.")?;
    window.navigate(url.clone()).map_err(|e| e.to_string())?;
    Ok(url.to_string())
}

fn build_menu<R: Runtime>(app: &AppHandle<R>) -> tauri::Result<Menu<R>> {
    let menu = Menu::default(app)?;
    let server = Submenu::with_items(
        app,
        "Server",
        true,
        &[
            &MenuItem::with_id(app, "back", "Back", true, Some("CmdOrCtrl+["))?,
            &MenuItem::with_id(app, "forward", "Forward", true, Some("CmdOrCtrl+]"))?,
            &MenuItem::with_id(app, "reload", "Reload", true, Some("CmdOrCtrl+R"))?,
            &MenuItem::with_id(app, "home", "Warpgate Home", true, Some("CmdOrCtrl+Shift+H"))?,
            &PredefinedMenuItem::separator(app)?,
            &MenuItem::with_id(
                app,
                "change-server",
                "Change Server…",
                true,
                Some("CmdOrCtrl+Shift+K"),
            )?,
        ],
    )?;
    menu.append(&server)?;
    Ok(menu)
}

fn handle_menu<R: Runtime>(app: &AppHandle<R>, id: &str) {
    let Some(window) = app.get_webview_window(MAIN_WINDOW) else {
        return;
    };
    let result = match id {
        "back" => window.eval("history.back()"),
        "forward" => window.eval("history.forward()"),
        "reload" => window.eval("location.reload()"),
        "home" => match load_server_url(app) {
            Some(url) => window.navigate(url),
            None => Ok(()),
        },
        "change-server" => window.navigate(setup_page_url(app)),
        _ => Ok(()),
    };
    if let Err(e) = result {
        eprintln!("menu action {id} failed: {e}");
    }
}

fn main() {
    tauri::Builder::default()
        .menu(build_menu)
        .on_menu_event(|app, event| handle_menu(app, event.id().as_ref()))
        .invoke_handler(tauri::generate_handler![connect, current_server])
        .setup(|app| {
            let start = match load_server_url(app.handle()) {
                Some(url) => WebviewUrl::External(url),
                None => WebviewUrl::App(SETUP_PAGE.into()),
            };
            WebviewWindowBuilder::new(app, MAIN_WINDOW, start)
                .title("Warpgate")
                .inner_size(1280.0, 820.0)
                .min_inner_size(800.0, 560.0)
                .build()?;
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running Warpgate desktop");
}
