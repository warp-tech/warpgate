# Warpgate UI redesign — implementation notes

Running log of decisions, deviations from the mockups, and open questions for
the design-system migration. [DESIGN.md](./DESIGN.md) is the authoritative
design system; this file records where the implementation departs from it and
why.

Newest entries at the top of each section.

---

## Phase log

| Phase | Status | Notes |
|---|---|---|
| 0 — Reconnaissance | ✅ done | Stack, serving model, API surface, routing map, theming, primitives. |
| 0.5 — Baseline | ✅ done | `DESIGN.md` moved to `design/`, this file seeded, bundle baseline captured. |
| 1 — Token layer | not started | |
| 2 — Primitives | not started | |
| 3 — Shell | not started | |
| 4 — Screen migration | not started | |
| 5 — Accessibility | not started | |
| 6 — Verification | **blocked** | Needs cargo, just, docker — none installed on the current machine. |

---

## Bundle baseline (Phase 0.5)

Captured from a clean `npm ci` + `npm run build` at `b9b8528`, the commit
before any redesign work. Every later phase reports its delta against these
two numbers.

### A. Shipped to browser — excludes source maps

|  | raw | gzip | files |
|---|---:|---:|---:|
| JS | 1608.0 KB | 446.2 KB | 95 |
| CSS | 28.7 KB | 11.5 KB | 44 |
| Fonts | 328.1 KB | 241.4 KB | 10 |
| Other | 49.7 KB | 8.2 KB | 5 |
| **Total** | **2014.5 KB** | **707.2 KB** | **154** |

Per-entry eager load (first paint, lazy route chunks excluded):

| Entry | raw | gzip | chunks |
|---|---:|---:|---:|
| `src/admin/index.html` | 340.0 KB | 91.4 KB | 14 |
| `src/embed/index.ts` | 102.8 KB | 32.6 KB | 6 |
| `src/gateway/index.html` | 70.4 KB | 27.0 KB | 4 |

### B. Embedded in the Rust binary

`rust-embed` takes all of `warpgate-web/dist` with no include/exclude filter
([warpgate-web/src/lib.rs](../warpgate-web/src/lib.rs)), so source maps ship
inside the binary.

| | size |
|---|---:|
| `.map` | 5917.0 KB |
| `.js` | 1608.0 KB |
| `.otf` | 218.8 KB |
| `.woff` | 62.4 KB |
| `.woff2` | 46.9 KB |
| `.json` | 39.9 KB |
| `.css` | 28.7 KB |
| `.svg` | 7.3 KB |
| `.html` | 2.6 KB |
| **Total** | **7931.5 KB (7.75 MB)** |

**Source maps are 75% of embedded weight.** `sourcemap: true` stays untouched
per decision #3 — noted here as an observation, not a proposal.

### Fonts today

| Family | size | files | fate |
|---|---:|---:|---|
| CaskaydiaCove (OTF) | 218.8 KB | 2 | **keep** — carries the Powerline glyphs xterm.js needs |
| Work Sans | 91.5 KB | 6 | drop in Phase 1 |
| Poppins | 17.8 KB | 2 | drop in Phase 1 |

### Two costs worth knowing before Phase 1

- `theme.dark` + `theme.light` are **356.7 KB raw / 52.3 KB gzip of
  JavaScript** — 22% of all shipped JS. They are two complete Bootstrap
  builds, imported with `?inline` so the CSS arrives as a JS string and is
  swapped into a `<style>` tag at runtime. A CSS-custom-property token layer
  replaces both with one real stylesheet.
- `import '@fontsource/work-sans'` is a bare full-package import; the package
  holds 109 files and the build emits 6 (latin / latin-ext / vietnamese in
  woff2 + woff). Phase 1 should use per-subset imports
  (`@fontsource/ibm-plex-sans/latin-400.css`) so only requested weights ship.

Projected Phase 1 font delta, from measured `@fontsource` latin-woff2 sizes
(~20 KB per weight):

| Variant | Plex Sans 400/500/600/700 | Plex Mono 400/500 | Drop Work Sans + Poppins | Net |
|---|---:|---:|---:|---:|
| With Plex Mono | +80 KB | +40 KB | −109.3 KB | **≈ +11 KB** |
| Caskaydia as UI mono | +80 KB | 0 | −109.3 KB | **≈ −29 KB** |

Decision deferred to Phase 1 on measured numbers per decision #7. The ~40 KB
spread is the whole question; see [Open questions](#open-questions) for the
non-size factors.

---

## Decisions

### D1 — Frontmatter palette is authoritative, not the prose palette
*Phase 0.5. Deviation from DESIGN.md.*

[DESIGN.md](./DESIGN.md) carries two incompatible palettes: the YAML
frontmatter (Material 3 tonal) and the prose "System Palette" section. A count
of every hex literal across the 14 Stitch exports settles which one the
mockups were built on:

```
 39  #e0e3e8  frontmatter text        39  #a9c7ff  frontmatter primary
 39  #101418  frontmatter canvas      26  #ffb94e  frontmatter amber
 26  #69dc9d  frontmatter success     26  #31353a  frontmatter surface-variant
 17  #0b0f13  frontmatter lowest      16  #7ba7f0  prose primary  <- only prose survivor
```

**The frontmatter palette wins.** The prose colour values
(`#0F1317` / `#1A2028` / `#2A323C` / `#7BA7F0` / `#F0A830` / `#3FB57A` /
`#E05C5C` / `#E9EDF2` / `#A3AEBA` / `#6B7785`) are **not implemented** and
should be treated as superseded.

The prose section's **rules** are implemented as written, because they are
palette-independent:

- state is always geometry + label + colour, never colour alone
- `font-variant-numeric: tabular-nums` on all numeric readouts
- sentence case everywhere; **no all-caps**
- no drop shadows, no gradients, no glassmorphism — depth is tonal + 1px hairlines
- `0px` radius on tables, data rows and sunken code blocks
- 8px base grid, 4px sub-grid
- centre-ellipsis truncation for IDs, fingerprints and hashes

### D2 — Error re-hued to a true red; M3 pair structure kept
*Phase 0.5. Deviation from DESIGN.md frontmatter.*

M3's `error: #ffb4ab` is a salmon pink that reads as a warning tone, not a
danger tone, next to `#ffb94e` amber. Re-hued to a true red.

Measured against the substrates an error-coloured element can land on:

| | `#101418` canvas | `#1c2024` surface | `#31353a` highest |
|---|---:|---:|---:|
| `#FF6B6B` | 6.67 AA | 5.91 AA | **4.45 FAIL** |
| `#FF7B7B` | 7.37 AAA | 6.53 AA | 4.92 AA |
| amber `#ffb94e` | 10.84 AAA | 9.60 AAA | 7.23 AAA |
| success `#69dc9d` | 10.86 AAA | 9.62 AAA | 7.25 AAA |
| primary `#a9c7ff` | 10.83 AAA | 9.60 AAA | 7.23 AAA |

`#FF6B6B` clears AA on both substrates named in the brief. It falls to 4.45 on
`surface-container-highest` (`#31353a`) — the hover/selected row tone — which
is below the 4.5 needed for normal text. **Open question Q1.**

Container pair, unchanged from M3:

| token | value | check |
|---|---|---|
| `error` | `#FF6B6B` *(pending Q1)* | see above |
| `on-error` | `#4A0003` | 5.85 on `#FF6B6B` — AA. M3's `#690005` gives 4.72, also AA but thinner |
| `error-container` | `#93000a` | solid destructive fill |
| `on-error-container` | `#ffdad6` | 7.24 on `#93000a` — AAA |

**Solid destructive buttons get a 1px `error` border.** The `#93000a` fill is
1.98:1 against canvas, which fails WCAG 1.4.11 (3:1 for UI component
boundaries) — the button is nearly invisible as a shape. A 1px `error` hairline
raises the boundary to 6.67:1 and matches DESIGN.md's convention that every
button carries a 1px border.

Amber `#ffb94e` and success `#69dc9d` are unchanged.

### D3 — Light theme derived from M3 tonal ramps, provisional
*Phase 0.5.*

DESIGN.md specifies dark only. Light is derived in Phase 1 and marked
provisional. **Phase 4 is not gated on light-theme review; Phase 5 is.**

Screens must be theme-agnostic. If a screen needs a light-specific fix, that
is a bug in the token layer, not in the screen — record it here and fix the
tokens.

### D4 — Roles matrix renders the real authorisation model
*Phase 0.5. Deviation from the mockup.*

`warpgate_roles_access_matrix` draws four capability columns — Connect,
Record, Copy/Paste, File Transfer. No such model exists: `Role` is
`{id, name, description, is_default}` and role↔target is a plain many-to-many
join with no per-capability granularity.

Implemented as: **rows = targets, columns = roles, one two-state toggle per
cell.** Matrix layout preserved, capability columns removed. Unenforced
toggles in an access-control UI are worse than no toggles.

### D5 — Fonts: IBM Plex Sans + IBM Plex Mono, self-hosted
*Phase 0.5. Deviation from DESIGN.md typography block.*

DESIGN.md's `typography:` frontmatter specifies **JetBrains Mono** for
`code-md`/`code-sm`, and the mockups reference it 26 times. The prose hedges —
"JetBrains Mono / IBM Plex Mono". Implemented as **IBM Plex Mono**: one
type family instead of two, and it matches the brief's air-gap requirement
directly.

All faces self-hosted via `@fontsource`. **No runtime requests to Google Fonts
or any other origin** — Warpgate is deployed in air-gapped and DMZ networks and
must render offline. The Stitch exports' `fonts.googleapis.com` and
`cdn.tailwindcss.com` links are reference-only artifacts and are never carried
into the implementation.

The CaskaydiaCove OTFs stay: they are the `monospace-fallback` family and carry
the Powerline glyphs xterm.js renders in terminal sessions.

### D6 — Scope boundaries
*Phase 0.5.*

- **SSO** = the OIDC section of `/config/parameters`. Folded into the
  Parameters sub-phase, not a screen of its own.
- **LDAP servers** gets its own screen, derived from the Targets list pattern.
- **Known hosts** = the whole `/config/ssh` page (Warpgate's own keys *and*
  known hosts), not a fragment.
- **Cluster: dropped.** No route, no component, and no endpoint in either
  OpenAPI schema. `UserSessionSnapshot` carries `node_id`/`node_hostname` and
  `tests/test_cluster_failover.py` exists, so clustering is real in the
  backend — but surfacing it needs new API surface, which this redesign
  forbids.
- **Overview** stays early in Phase 4. It is a **new route** (admin `/` is
  currently a bare redirect to `/status/sessions`), composed from existing
  `/sessions`, `/logs` and `/login-protection/status` endpoints.
- **Logo / brand: out of scope**, pending a fork-vs-upstream decision.
  `warpgate_aperture_logo` is not implemented.

### D7 — API gaps: omit rather than fake
*Phase 0.5. Deviations from the mockups.*

**Rule: if a derived column survives, it is named after what was actually
measured.**

| Mockup column | Reality | Resolution |
|---|---|---|
| Login protection → *Attempts* | `BlockedIpInfo.block_count` is times-blocked, not failed attempts | **rename** → "Times blocked" |
| Tickets → *Uses* | only `uses_left` is stored; consumed count is not | **rename** → "N uses left", no progress bar |
| Targets → *TLS* | exists, but per-protocol inside the `TargetOptions` union — not a uniform column | **move** → target drawer, with protocol context |
| Tickets → *Created by* | `Ticket.username` is the subject, not the creator | **drop** |
| Audit log → *Decision* | `LogEntry` has no decision field | **drop** |
| Targets → *Health* | no health field, no probe endpoint | **drop** |
| Targets → *Last used* | not on `Target`; derivable only by scanning paginated `/sessions` | **drop** |
| Targets → *Sessions* (count) | same | **drop** |
| Target drawer → *Test connection* | no probe endpoint exists | **drop** |

### D8 — DESIGN.md relocated
*Phase 0.5.*

Moved `design/warpgate_mission_console/DESIGN.md` → `design/DESIGN.md`. The
now-empty `warpgate_mission_console/` directory was removed. The Stitch exports
keep their `design/<screen>/{code.html,screen.png}` layout.

---

## Open questions

### Q1 — `#FF6B6B` fails AA on the hover-row substrate
*Raised Phase 0.5. Blocks the Phase 1 token layer.*

`#FF6B6B` gives 4.45:1 on `surface-container-highest` (`#31353a`), just under
the 4.5 AA threshold for normal text. Three ways out:

1. **Shift to `#FF7B7B`** — 4.92:1 there, AA on every step of the ramp, still
   within the brief's "~#FF6B6B" latitude. *Recommended.*
2. Keep `#FF6B6B` and add a rule that error-coloured text never sits on
   `surface-container-highest` — which means hovering a row containing an error
   status would have to suppress the hover tone. Fragile.
3. Keep `#FF6B6B` and drop the hover tone to `surface-container-high`
   (`#262a2f`, 5.20:1). Changes hover feel for every table in the product.

### Q2 — Can CaskaydiaCove serve as the UI mono?
*Raised Phase 0.5. Decided in Phase 1 on measured numbers, per decision #7.*

Worth ≈40 KB raw (≈2% of shipped bytes). Caskaydia already ships and cannot be
dropped, so reusing it for UI mono costs nothing extra.

Non-size factors to weigh alongside the measurement:

- Caskaydia Cove is a Nerd-Font-patched Cascadia Code — a *terminal* face. Its
  wide advance widths and large x-height are tuned for 14px+ terminal grids and
  may read heavy in dense table chrome at 12–13px.
- It ships as **OTF**, which compresses far worse than WOFF2: 218.8 KB raw →
  132 KB gzip for two weights. Plex Mono in WOFF2 is ~20 KB per weight.
- Only Regular and Bold are present — **no 500 weight.** DESIGN.md's `code-md`
  and `code-sm` are both 400, so this only matters if mono ever needs a medium.

Phase 1 will build both variants and put them side by side at 12px and 13px.

### Q3 — Per-phase branch convention
*Raised Phase 0.5.*

The brief asks for one phase per PR, each independently revertable. Phase 0.5
is committed to `redesign/design-system` (the branch that already existed at
`main` with no commits). Confirm whether later phases should branch off that,
or off `main` directly.

---

## Environment notes

Recorded because they cost time to diagnose and will recur on a fresh checkout.

- **Oracle's `javapath` shim is broken on this machine.**
  `C:\Program Files\Common Files\Oracle\Java\javapath\java.exe` segfaults
  (exit `-1073741819` / `0xC0000005`). A working JDK 26 is installed at
  `C:\Program Files\Java\jdk-26.0.1`. `openapi-generator-cli` needs Java, so
  `npm ci`'s postinstall fails until `JAVA_HOME` is set and the shim is
  removed from `PATH`. openapi-generator 7.7.0 runs fine under JDK 26.
- **The SDK scripts need a POSIX shell.** `openapi:client:*` ends in
  `rm -rf src tsconfig.json`, which cmd.exe cannot run — the client generates
  and compiles, then the script exits 1 on cleanup. Run npm with
  `npm_config_script_shell` pointed at Git Bash. No repo change needed.
- **cargo, just and docker are not installed here.** Phases 1–5 are node-only
  and unaffected. Phase 6 (release binary + `docker/local-testing`) is blocked
  until they are. `just openapi-all` is likewise unavailable — but a
  presentation-layer change should never need it, since regenerating schemas
  from Rust implies Rust changed.
- `just npm <args>` is a thin `cd warpgate-web && npm <args>` wrapper, so plain
  `npm` works identically while `just` is missing.
