# Warpgate Desktop (macOS)

A small native window around the Warpgate web UI, so you don't have to keep a browser tab open.
It contains no server code. On first launch it asks for your Warpgate server address, saves it, and opens `https://<server>/@warpgate`.

## Building the DMG

One-time setup:

```sh
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh   # Rust (stable)
xcode-select --install                                             # if Xcode CLI tools are missing
```

Then:

```sh
cd warpgate-desktop
npm install
npm run dmg              # → src-tauri/target/release/bundle/dmg/Warpgate_0.1.0_aarch64.dmg
npm run dmg:universal    # Apple Silicon + Intel in one DMG
                         # (first: rustup target add aarch64-apple-darwin x86_64-apple-darwin)
```

`npm run dev` runs the app without packaging.

## Using it

- **First run:** enter `warpgate.example.com` (or a full `https://…` URL). `https://` and `/@warpgate` are added if you leave them out.
- **Server menu:** Back `⌘[`, Forward `⌘]`, Reload `⌘R`, Warpgate Home `⇧⌘H`, Change Server… `⇧⌘K`.
- The saved address is in `~/Library/Application Support/com.example.warpgate.desktop/settings.json`.
  Delete that file to get the first-run screen again.

## Distributing to the team

Without an Apple signature, macOS blocks the app on first launch. Pick one of these:

- **Unsigned (internal only):** tell users to right-click `Warpgate.app` → **Open** the first time,
  or to run `xattr -dr com.apple.quarantine /Applications/Warpgate.app`.
- **Signed and notarized:** set these before `npm run dmg`:
  `APPLE_SIGNING_IDENTITY="Developer ID Application: <Company> (<TEAMID>)"`, `APPLE_ID`, `APPLE_PASSWORD`
  (app-specific password) and `APPLE_TEAM_ID`. See https://v2.tauri.app/distribute/sign/macos/.

Before you share it, change `identifier` in `src-tauri/tauri.conf.json` to your company's reverse-DNS name
(e.g. `com.acme.warpgate`).

## Notes

- The Warpgate server needs a certificate the Mac trusts. Self-signed certificates fail, just as they do in Safari.
  Add your internal CA to the Keychain if you use one.
- SSO logins (OIDC) happen inside the app window. Sessions persist between launches.
- The remote Warpgate page has no access to the app's native commands. Only the bundled setup page
  can call them (`src-tauri/capabilities/default.json`).
- The icons come from `warpgate-web/public/assets/favicon.svg`. To regenerate them, run `npm run icon`.
