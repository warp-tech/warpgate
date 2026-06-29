# Drafts for the external docs site (warpgate.null.page)

These are ready-to-paste Markdown snippets for the documentation site, which lives in a separate
repository. They cover the new RDP/VNC desktop protocols and their session recording.

---

## Session recording → add a "Desktop (RDP/VNC) recordings" section

Desktop sessions — both in-browser (RDP and VNC through the web portal) and **native VNC** (a desktop
VNC viewer connecting to Warpgate's VeNCrypt port) — are recorded the same way as SSH and database
sessions, when recording is enabled:

```yaml
recordings:
  enable: true
  path: ./data/recordings
```

What is captured:

- The full **framebuffer event stream** of the session — resolution changes, image/region updates and
  copy-rect operations — stored as newline-delimited JSON, the same normalized stream the browser
  renders. This reconstructs exactly what the user saw.
- Keyboard/mouse input is **not** stored in the recording.

Viewing:

- Open the session in the admin UI → **Recordings** → pick the desktop recording. The built-in player
  replays the desktop on a canvas with play/pause, a seek slider and fullscreen.
- **Live viewing:** while a desktop session is in progress, the same player tails it live (the **LIVE**
  badge). Live viewing requires recording to be enabled.

Retention: desktop recordings honour the same `log.retention` window and are pruned automatically along
with their files.

Limitations:

- When recording is **disabled**, the native VNC proxy stays a transparent passthrough (no decoding,
  no added latency). When recording is **enabled**, native VNC sessions are decoded and re-encoded so
  the framebuffer can be captured; this trades a little bandwidth (frames are sent as uncompressed
  regions) for the recording, and only affects recorded sessions.
- Seeking replays from the start of the recording.

---

## Protocols / overview → add RDP and VNC

Warpgate can expose remote desktops in addition to SSH/HTTP/MySQL/PostgreSQL/Kubernetes:

- **VNC** — reachable both in the browser (through the web portal) and via a native VNC viewer
  (VeNCrypt + TLS, authenticating with a `user:target` username and the Warpgate password).
- **RDP** — reachable **in the browser** through the web portal. RDP is rendered server-side via a
  bundled helper and streamed to a canvas.

Both appear as target types in the admin UI and are governed by the same role-based access control,
tickets and session auditing as other protocols.

---

## Configuration reference → add `vnc:` and `rdp:` sections

```yaml
# Native VNC listener (VeNCrypt + TLS). Optional.
vnc:
  enable: true
  listen: "0.0.0.0:5900"
  certificate: /path/to/tls.crt   # required for VeNCrypt X.509
  key: /path/to/tls.key

# RDP targets are accessed in the browser; no native RDP listener is exposed yet.
rdp:
  enable: false
```

Target options:

- **VNC target:** `host`, `port` (default 5900), `auth` (`none` or `password`).
- **RDP target:** `host`, `port` (default 3389), `username`, optional `domain`, `auth` (`password`).
