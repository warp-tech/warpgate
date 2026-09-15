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
| 1 — Token layer | ✅ done | Tokens, both themes, fonts, `/styleguide`. +28.5 KB raw (+1.4%). |
| 2 — Primitives | not started | |
| 3 — Shell | not started | |
| 4 — Screen migration | not started | |
| 5 — Accessibility | not started | |
| 6 — Verification | **blocked** | Needs cargo, just, docker — none installed on the current machine. |

### Branching

Phases stack: each branches off its predecessor, all merging into
`redesign/design-system`, `main` untouched until the whole thing lands.
`VITE_NEW_UI` is the rollback mechanism, not git — it reverts the entire
user-visible redesign with an env var and no git operation.

| Phase | Branch |
|---|---|
| 0.5 | `redesign/design-system` |
| 1 | `redesign/phase-1-tokens` |

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

## Phase 1 — bundle delta

Measured against the Phase 0.5 baseline. Both numbers reported separately
because `rust-embed` takes all of `dist/`, source maps included.

### Shipped to browser

| | baseline | Phase 1 | delta |
|---|---:|---:|---:|
| JS | 1608.0 KB | 1607.7 KB | −0.3 KB |
| CSS | 28.7 KB | 35.5 KB | **+6.8 KB** |
| Fonts | 328.1 KB | 350.3 KB | **+22.2 KB** |
| Other | 49.7 KB | 49.6 KB | −0.1 KB |
| **Raw total** | **2014.5 KB** | **2043.0 KB** | **+28.5 KB (+1.4%)** |
| **Gzip total** | **707.2 KB** | **730.7 KB** | **+23.5 KB (+3.3%)** |

### Embedded in binary

| | baseline | Phase 1 | delta |
|---|---:|---:|---:|
| Total | 7931.5 KB | 7961.1 KB | **+29.6 KB (+0.4%)** |

Both well inside the ±10% band (1813–2216 KB raw / 7138–8725 KB embedded).

### The theme.dark / theme.light line item

**Not yet reclassified. This is Phase 4's payoff, not Phase 1's.**

| | baseline | Phase 1 | change |
|---|---:|---:|---:|
| `theme.dark` + `theme.light`, counted as **JS** | 356.7 KB raw / 52.3 KB gz | 356.3 KB raw / 51.9 KB gz | unchanged |

These two chunks are complete Bootstrap builds imported with `?inline`, so
their CSS is carried as JavaScript string literals — 22% of all shipped JS is
stylesheet wearing a JS extension. Removing them would break every screen that
still renders through Bootstrap, which in Phase 1 is all of them, so the token
layer is purely additive here.

The reclassification lands when the last screen migrates at the end of Phase 4
and the Bootstrap theme bundles are deleted. Projected at that point:

- **−356 KB raw / −52 KB gz** leaves the JS column
- **+~25-35 KB raw** enters the CSS column as one real stylesheet (tokens plus
  primitive styles, gzipping far better than string-literal CSS and cacheable
  as a separate file rather than parsed as JS on every load)
- net **≈ −320 KB raw / −45 KB gz**, and the part that remains stops blocking
  the JS parse

That single change is larger than every other bundle movement in this project
combined, which is why it is tracked on its own line rather than inside a net
total.

### Fonts

| | baseline | Phase 1 |
|---|---:|---:|
| CaskaydiaCove (OTF, 2 files) | 218.8 KB | 218.8 KB — kept |
| Work Sans (6 files, woff+woff2) | 91.5 KB | removed |
| Poppins (2 files, woff+woff2) | 17.8 KB | removed |
| IBM Plex Sans (6 files, woff2) | — | 117.1 KB |
| IBM Plex Mono (1 file, woff2) | — | 14.4 KB |
| **Total** | **328.1 KB** | **350.3 KB (+22.2 KB)** |

Plex ships woff2 only. The outgoing packages shipped woff *and* woff2; every
browser that can run Svelte 5 supports woff2, so the duplicate was pure weight.

Weights shipped are the ones DESIGN.md's type roles actually use — 400, 500,
600. There is no 700 role, so 700 is not shipped; the three places that asked
for Poppins 700 (`EmptyState`, `GettingStarted`, `_theme.scss`'s page summary
bar) now ask for 600, which avoids synthetic bolding.

Subsets: latin + latin-ext for the UI face, since usernames and target
descriptions carry Central and Eastern European diacritics. Mono is latin only
— it renders hostnames, IPs, CIDRs, ports, fingerprints and UUIDs, which are
ASCII by definition.

---

## Decisions

### D9 — IBM Plex Mono is the UI mono; Caskaydia Cove stays terminal-only
*Phase 1. Resolves Q2.*

**The deciding fact was not letterform harmony — it was that Caskaydia is not
actually free.**

`monospace-fallback` is applied in exactly one place in the codebase:
`WebSshTab.svelte`, the xterm.js font config. The `@font-face` declaration is
on the eager path (it lands in the shared `wrap` chunk's CSS, loaded by both
the admin and gateway entries), but a browser does not fetch a font file until
the family is matched to rendered text. So today those 218.8 KB of OTF are
downloaded **only when someone opens an in-browser SSH session** — never on any
admin screen, never on the portal.

Making Caskaydia the UI mono would move that download onto every route that
renders a hostname, IP or fingerprint, which after Phase 4 is nearly all of
them:

| | bytes over the wire, per route that renders mono |
|---|---:|
| Caskaydia Cove (2× OTF) | 218.8 KB raw → **132 KB gzipped** |
| IBM Plex Mono (1× woff2) | 14.4 KB raw → **14.4 KB** (woff2 is already compressed) |

Plex Mono is **roughly 9× cheaper** on every admin route. The framing in the
Phase 0.5 baseline — "+11 KB with Plex Mono vs −29 KB reusing Caskaydia" — was
measuring `dist/` totals, where Caskaydia counts as already-sunk. That is true
of the directory and false of what any given user downloads. Correcting it
reverses the conclusion.

The letterform comparison agreed independently. Rendered side by side at 13px
in a table row against Plex Sans (see `/styleguide`):

- Caskaydia sits visibly heavier at the same nominal 400 weight, so mono
  columns shout relative to the sans columns beside them — bad in a dense table
  where every column should read at one volume.
- Caskaydia is wider per character, costing horizontal room in exactly the
  columns that are already longest (fingerprints, session UUIDs).
- Plex Mono shares Plex Sans's skeleton, so a row reads as one line of text set
  in two faces rather than two competing families.
- Both disambiguate `0/O` and `1/l/I` well; neither wins on legibility alone.

Caskaydia stays exactly as it is — `monospace-fallback`, applied only by
xterm.js, carrying the Powerline glyphs that terminal sessions need.

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

### Q5 — Third ink tier and the two border tiers diverge from DESIGN.md
*Raised Phase 1. Implemented as described; flagged for review.*

The live contrast audit on `/styleguide` caught two token-layer bugs before any
primitive was built. Both are places where DESIGN.md's stated values fail AA
and the implementation takes AA instead.

**1. `--wg-text-subtle` is not `--wg-outline`.** DESIGN.md has three ink tiers,
the third being "inactive timestamps, non-critical units, disabled actions,
protocol markers". Aliasing that to M3's `outline` — a *border* role — measured
3.92:1 dark and 4.25:1 light on the hover-row substrate, failing 1.4.3 for the
timestamps and protocol markers it renders. Disabled controls are exempt from
1.4.3; inactive timestamps are not. Given its own value per theme:

| | value | canvas | container | highest |
|---|---|---:|---:|---:|
| dark | `#9da0ac` | 7.10 AAA | 6.29 AA | 4.74 AA |
| light | `#60636d` | 5.71 AA | 5.15 AA | 4.64 AA |

**2. Borders split into two tiers.** `outline-variant` measures 1.98:1 dark and
1.62:1 light against the canvas — below even 1.4.11's 3:1. That is correct for
what M3 intends it to be (a decorative divider, which 1.4.11 exempts) and wrong
for what DESIGN.md's prose asks of it, which is the border of every input and
select. The split:

| token | value | role | vs canvas |
|---|---|---|---:|
| `--wg-border` | `outline-variant` | decorative dividers only — row rules, cell hairlines | 1.98 / 1.62 — exempt |
| `--wg-border-strong` | `outline` | interactive component boundaries — inputs, selects, buttons, focusable cards | 5.87 / 4.25 — passes 3:1 |

**The rule: if a border is the only thing telling an operator where a control
begins, it is `border-strong`.** This makes inputs read slightly louder than
the mockups draw them. Deliberate, and the alternative is failing AA on every
form in the product.

### Q6 — Light theme is unreviewed
*Raised Phase 1. Gates Phase 5, not Phase 4, per decision #2.*

The light palette is derived and passes AA across every role and substrate, but
no human has looked at it for taste. It is marked provisional in `tokens.css`.

Screens must stay theme-agnostic. **If a screen needs a light-specific fix, the
token layer is wrong — record it here rather than patching the screen.**

---

## Resolved

### Q1 — error hue ✅ `#FF7B7B`
*Raised Phase 0.5, resolved Phase 1.*

`#FF6B6B` measured 4.45:1 on `surface-container-highest`, under AA for normal
text. Resolved in favour of AA across the full ramp over a higher number on two
substrates: the failure case was a hovered table row, which is exactly when an
operator is targeting that row. `#FF7B7B` measures 7.37 / 6.53 / 4.92. See D2.

### Q2 — UI mono ✅ IBM Plex Mono
*Raised Phase 0.5, resolved Phase 1.* See D9.

### Q3 — branching ✅ stacked
*Raised Phase 0.5, resolved Phase 1.* Phase N branches off Phase N−1; see the
branching table at the top. The "independently revertable" requirement is met
by `VITE_NEW_UI`, not by git history — Phase 2 cannot exist without Phase 1.

### Q4 — tracking `.md` ✅ gitignore negation
*Raised Phase 0.5, resolved Phase 1.* `!design/**/*.md` added to `.gitignore`
rather than force-adding each file, since `-f` silently loses anything someone
forgets to force-add.

---

## Environment notes

Recorded because they cost time to diagnose and will recur on a fresh checkout.

### Windows: two failures that will cost you an afternoon

Both bite on a fresh checkout, and the second one in particular fails in a way
that looks like success.

**1. Oracle's `javapath` shim segfaults.**

`openapi-generator-cli` runs the generator through `java`. On this machine
`C:\Program Files\Common Files\Oracle\Java\javapath\java.exe` — a stub Oracle
installs onto `PATH` — crashes with exit `-1073741819` (`0xC0000005`, access
violation) and **prints nothing at all**. A real JDK is installed at
`C:\Program Files\Java\jdk-26.0.1` and works fine; the stub just shadows it.

The symptom is `npm ci` failing in postinstall with an `Error` whose message is
blank. Fix, in whatever shell you run npm from:

```bash
export JAVA_HOME="/c/Program Files/Java/jdk-26.0.1"
export PATH="$JAVA_HOME/bin:$(echo "$PATH" | tr ':' '\n' | grep -v 'Oracle/Java/javapath' | paste -sd:)"
```

openapi-generator 7.7.0 runs correctly under JDK 26.

**2. `openapi:client:*` needs a POSIX shell, and half-succeeds without one.**

This is the confusing one. The scripts end in:

```
… && npx tsc --target esnext --module esnext && rm -rf src tsconfig.json
```

`rm -rf` is not a cmd.exe command. So on Windows the generator **succeeds**,
`npm i` **succeeds**, `tsc` **succeeds** and emits `dist/` — and then the
script dies on the cleanup step with `'rm' is not recognized`, exits 1, and
leaves `src/` and `tsconfig.json` sitting in `api-client/`. You get a working
client and a failed command, which reads like a broken generator.

`npm run devbuild` fails the same way for the same reason — it opens with the
POSIX env-var prefix `NODE_ENV=development`.

Fix — point npm at Git Bash, then run the project's documented commands
unmodified:

```bash
export npm_config_script_shell="C:\\Users\\<you>\\AppData\\Local\\Programs\\Git\\usr\\bin\\bash.exe"
```

**3. Pipe your build commands through `set -o pipefail`.** `npm ci 2>&1 | tail`
reports tail's exit code, not npm's, so a failed install looks clean. This is
how failure 1 above was initially missed.

### Missing toolchain

- **cargo, just and docker are not installed here.** Phases 1–5 are node-only
  and unaffected. Phase 6 (release binary + `docker/local-testing`) is blocked
  until they are. `just openapi-all` is likewise unavailable — but a
  presentation-layer change should never need it, since regenerating schemas
  from Rust implies Rust changed.
- `just npm <args>` is a thin `cd warpgate-web && npm <args>` wrapper, so plain
  `npm` works identically while `just` is missing.

### Viewing the styleguide without a backend

`/styleguide` is registered in `gateway/Root.svelte` outside the auth gate, so
it renders against a static server — no running Warpgate needed:

```bash
npm run devbuild      # production build strips the route
# then serve warpgate-web/dist/ with /@warpgate/* mapped to dist/*
# and open  http://localhost:<port>/#/styleguide
```
