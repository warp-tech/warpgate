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
| 2 — Primitives | ✅ done | 18 primitives + styleguide entries + primitive contrast audit. +0.4 KB raw. |
| 3 — Shell | ✅ done | Sidebar, top bar, breadcrumbs, command palette, fuzzy matcher, action registry. |
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
| 2 | `redesign/phase-2-primitives` |
| 3 | `redesign/phase-3-shell` |

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

## Phase 2 — bundle delta

| | Phase 1 | Phase 2 | delta |
|---|---:|---:|---:|
| Shipped raw | 2043.0 KB | 2043.4 KB | **+0.4 KB** |
| Shipped gzip | 730.7 KB | 730.8 KB | +0.1 KB |
| Embedded | 7961.1 KB | 7961.9 KB | +0.8 KB |

**Effectively zero, and that is expected.** No shipping code imports the
primitives yet — they exist only in `/styleguide`, which is stripped from
production by `import.meta.env.DEV`. The real cost arrives in Phase 4 as
screens migrate onto them, offset by Bootstrap components leaving at the same
rate.

Cumulative against the Phase 0.5 baseline: **+28.9 KB raw (+1.4%)**.

`theme.dark` + `theme.light` unchanged at **356 KB raw / 52 KB gz of JS that is
really CSS**. Still Phase 4's payoff; see the Phase 1 section for the
projection and the parse-blocking argument.

---

## Decisions

### D18 — Phase 5 completion criterion replaced
*Phase 3.*

The original criterion — "remove the three `svelte-check` a11y suppressions
and pass clean" — measured nothing. Svelte 5 renamed its warning codes from
hyphens to underscores and the flags were never updated, so
`a11y-no-static-element-interactions:ignore` never matched
`a11y_no_static_element_interactions`. Verified three ways: the rule fired on
a new component despite being listed; removing all three flags changed
nothing (0 warnings either way); and the underscore spellings changed nothing
either, because there was nothing left to suppress.

**The flags were deleted in Phase 3** rather than at Phase 5. A dead flag
tells the next reader that three categories of a11y warning are deliberately
tolerated, which was never true.

Replacement criterion:

- **axe-core reports zero violations** on every route, in both themes
- **a keyboard-only walk of every flow in the preserve-behaviour list** —
  session recording playback, live session streaming, in-browser SSH, RDP and
  VNC, TOTP enrolment, SSO redirect

### D15 — Typed-name confirmation is a new pattern, not an existing one
*Phase 3. Corrects a premise.*

The Phase 3 brief asked that destructive actions invoked from the palette get
"the same typed-name confirmation as everywhere else". **There is no
typed-name confirmation anywhere in the product.** All nine destructive flows
use native `window.confirm()`:

```
AccessRole.svelte  AdminRole.svelte  LdapServer.svelte  TargetGroup.svelte
Target.svelte      User.svelte       CredentialEditor.svelte
LoginProtection.svelte (×2)          CredentialManager.svelte
```

Every one is a single Enter away from committing.

`ui/ConfirmDialog.svelte` establishes the pattern. Two modes: a plain
confirm/cancel of the same weight as the `confirm()` it replaces, and — when
`confirmText` is set — a mode requiring the operator to type an exact string
before the destructive button enables. The typed mode is reserved for actions
reached *without deliberate navigation*, which today means the command
palette.

Comparison is exact rather than case-insensitive: the point is to make the
operator read the identifier of the thing they are about to destroy, and a
forgiving comparison defeats that. Leading and trailing whitespace is
forgiven because it comes from paste, not from misreading.

**Phase 4 migrates the nine `confirm()` call sites onto this.** Until then the
palette is the only thing using it.

### D16 — Sidebar labels are clipped, not removed
*Phase 3.*

In the 56px rail every item is icon-only. Rather than an `aria-label` on each
link, the visible label stays in the DOM and is clipped by CSS. The link's
accessible name is therefore always the same string a sighted user reads, and
cannot drift from it when someone renames an item — the failure mode of
parallel labels. A tooltip shows the same text on hover, which is
supplementary: it describes, it does not name.

Section headings collapse to a 1px rule rather than disappearing, so the
grouping survives, and are marked `aria-hidden` in that state since each link
already carries its own name.

The active item is marked with an inset 2px primary edge as well as a
background tone, so it stays identifiable in the rail where the label is gone.

### D17 — One permission list, gating three surfaces
*Phase 3.*

The sidebar (`shell/navItems.ts`), the action registry (`shell/actions.ts`)
and the palette's entity loader (`shell/entities.ts`) all gate on
`ADMIN_PERMISSIONS` keys from `admin/lib/store`. There is no second list, and
`requires` is typed as `AdminPermissionKey`, so a renamed permission is a
compile error rather than an item that silently never appears.

**Items are filtered, not disabled.** A greyed-out "Manage admin roles" still
tells the operator that the capability exists and that someone holds it.

In the entity loader the gate is on the *request*, not the rendering — the
palette must not fetch a list the operator has no right to see.

### D12 — Table wraps ItemList through two new snippet props
*Phase 2.*

`ui/Table.svelte` owns none of the data behaviour. ItemList keeps the RxJS
search debounce, pagination, adjacency grouping, persisted group collapse, the
search-force-expand rule, and the empty/loading states. Table adds exactly
five things: sticky header, sortable headers, density toggle, keyboard row
navigation, and row selection.

Making that possible needed two small additions to `common/ItemList.svelte`,
both optional and both backwards compatible:

- **`container?: Snippet<[Snippet, T[]]>`** — wraps the rendered rows, so a
  caller can supply real `<table><tbody>` markup instead of the default
  list-group div. Receives the items as well as the rows snippet, because the
  select-all checkbox in `<thead>` sits outside the row loop and still has to
  reflect them. Defaults to the existing div when omitted.
- **`searchInput?: Snippet<[string, (v: string) => void]>`** — replaces the
  built-in sveltestrap `Input` with the caller's own, without reaching into
  the debounce pipeline.

**Sorting is surfaced, not applied.** ItemList owns row order because grouping
is adjacency-based — sorting inside Table would silently break groups. `sort`
is a bindable prop; the caller feeds it into its own `load`. Third click on a
sorted header clears the sort rather than cycling back to ascending, so an
operator who sorted by mistake does not have to guess the original order.

**The roving tab stop is keyed, not indexed.** ItemList can reorder or regroup
rows underneath Table, and a captured integer index would quietly move the tab
stop to a different record. An effect re-seats it on the first row whenever the
row it was on disappears — a page change, a filter, a collapsed group.

### D19 — focusTrap: an ancestor bug with a symptom, and a sibling bug without one
*Phase 3, recording work done in Phase 2. Worth reading as a pair.*

**First half — found by driving it.** `focusTrap` marked every child of
`<body>` inert except the dialog node. That is correct only when the dialog is
a direct child of body. These dialogs are **not portalled** — they render
inline at their component's position in the tree, inside `#app`. So the action
was marking the dialog's own ancestor inert, which makes the dialog inert too.

The consequence was total and silent: focus never entered the dialog, Tab was
never trapped, and Escape restored focus to `<body>`. Nothing threw, nothing
looked wrong in a screenshot, and clicking still worked — so a visual review
would have passed it. It surfaced only because the Phase 2 verification script
asserted `dialog.contains(document.activeElement)` after opening a Drawer, and
got `false`.

Fixed by walking the ancestor chain from the dialog to `<body>` and marking
each ancestor's *siblings*, which is the true complement of the dialog.

**Second half — found by reasoning, with no symptom at all.** The scrim is a
sibling of the dialog inside the same parent, so the corrected walk would have
marked *it* inert too. `inert` does not only remove an element from the
accessibility tree and the tab order — **it also removes it from hit-testing**.
An inert scrim silently stops receiving clicks, so click-outside-to-close
would have broken.

No test caught this and no test would have, because the Phase 2 harness drove
the dialogs by keyboard. It was caught by asking what `inert` actually does
before shipping the ancestor fix. Elements that are part of the overlay rather
than the page behind it are now marked `data-wg-overlay` and skipped.

The pairing is the point: the first bug was found by driving the thing, the
second by understanding the primitive being used. Neither method would have
found the other.

### D13 — StatusMarker makes shape structurally inescapable
*Phase 2.*

`ui/StatusMarker.svelte` has **no `colour` prop and no `shape` prop**. A call
site picks a `kind` from a closed union and the geometry, colour and default
label come with it, from a frozen map.

This is enforcement, not convention. A component that accepted `colour` would
eventually be handed one without a shape — not through carelessness but
because at 3am the fastest way to say "this row is bad" is to make it red.
Removing the prop removes the option. Adding a state means adding a row to the
map, which is the review point.

`label` is customisable, because timestamps belong in it ("Ended 12:04:31"),
but it cannot be blanked — every kind carries a default and the label always
renders as visible text. The text is the accessible name, so the shape is
`aria-hidden`.

**One addition to DESIGN.md's five-state matrix: `pending`** (diamond, amber).
Approvals and ticket requests are a real state in this product — `/status/requests`,
`/session-approvals`, `/ticket-requests` — and were not in the mockups.

**Third DESIGN.md divergence: `ended` is a hollow ring, not a filled circle.**
DESIGN.md draws `live` and `ended` as identical solid 6px circles, separated
only by colour and the pulse. Those are the two most common states in the
product and they appear in the same column on adjacent rows constantly, so the
geometry was carrying nothing precisely where it is needed most — which
defeats the system's own geometry+label+colour rule at its most load-bearing
point.

`ended` sharing the ring with `online` is safe: a session's state and a
target's health never appear in the same column.

### D14 — AsyncButton's state machine extracted verbatim
*Phase 2.*

Lifted into `ui/asyncAction.svelte.ts` unchanged: the 500ms delay before the
spinner appears, the 1000ms hold on done/failed, the re-entrancy guard, the
form-validation handshake, and the width **and** height pinning from pre-click
measurements. Only the chrome around it is new.

`common/AsyncButton.svelte` is untouched and keeps working; Phase 4 migrates
its call sites and can then collapse the two.

One addition: the state machine sets `wg-validated` alongside Bootstrap's
`was-validated` on the parent form, so a form built from either generation
styles correctly while the migration is in flight.

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

### Q7 — Three Biome a11y rules disabled for all `.svelte` files
*Raised Phase 2. Broader than intended; flagged for review.*

`src/ui` implements raw ARIA patterns that three Biome rules mis-model:

| rule | why it is wrong here |
|---|---|
| `noNoninteractiveElementToInteractiveRole` | ARIA in HTML explicitly permits `role="grid"` on `<table>`, and `ui/Table` **is** an interactive grid — roving tabindex, Space to select, `aria-selected` per row. Dropping the role would make `aria-selected` invalid. |
| `noNoninteractiveTabindex` | The APG tabs pattern calls for a focusable tabpanel so a panel with no focusable content of its own stays reachable and scrollable by keyboard. |
| `noStaticElementInteractions` | `ui/Tooltip`'s wrapper is a positioning context around arbitrary children. ARIA has no role for "element that reveals a tooltip about its child", and inventing one would be worse for a screen reader than the lint it silences. |

**The scope is wider than it should be.** These are disabled for every
`.svelte` file rather than just `src/ui/**`, because:

1. Biome's HTML-comment suppressions **do not attach to Svelte template
   nodes** — a `<!-- biome-ignore -->` above an element is reported as
   `suppressions/unused` while the diagnostic still fires, so there is no
   per-site way to express these.
2. A scoped `"includes": ["src/ui/**"]` override **resets inherited formatter
   and linter settings** for matched files rather than merging with them —
   it reformatted 28 files to tabs and semicolons and re-enabled rules the
   top-level config turns off.

A fourth was added in Phase 3: **useKeyWithClickEvents**, the Biome twin of
the svelte-check rule already suppressed inline at the same site — the command
palette's listbox options, whose keyboard handling lives on the input because
the ARIA combobox pattern forbids focusable options.

Narrow these if a later Biome release fixes either limitation. Phase 5's
runtime axe-core audit covers all four and is the stronger check — nothing
here is exempt from it.

### Q8 — Switch vs checkbox behind a save bar
*Raised Phase 3 for Phase 4. Nothing changed yet.*

`ui/Toggle.svelte` is `role="switch"`, which announces "this is on now". That
is right for a setting applied immediately, and **wrong for one sitting behind
a save bar**, where the honest announcement is "this will be true when you
save" — a checkbox.

`/config/parameters` is the screen where this bites: it is a large form behind
`SectionedForm`/`autosave`, and most of its booleans are deferred, not live.
Decide per-control during the Parameters sub-phase; both primitives exist.

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

### `//` comments in `biome.json` silently disable it

Biome's config is **not** JSONC. A `//` line comment inside `biome.json` does
not raise an error — Biome falls back to its built-in defaults and formats
everything with **tabs, double quotes and semicolons**, against both
`.editorconfig` and the project's own `javascript.formatter` settings. A
`"//"` key *does* error loudly (`unknown key`), which makes the silent case
easy to walk into after ruling the loud one out.

Symptom: `biome format --write` reformats files to tabs and the diff looks
like the formatter changed its mind. Check `biome.json` for comments first.
This cost a 28-file reformat during Phase 2.

### `npm run lint` does not run Biome

`"lint": "npm run biome && svelte-check"` and `"biome": "biome"` — invoking
Biome with no arguments prints help and exits 0. So `npm run lint` only ever
runs `svelte-check`. The real Biome gate is CI's `biome ci`
(`.github/workflows/biome.yml`), which is not reproduced by any npm script.

Separately, `biome ci` reports thousands of findings against this checkout,
overwhelmingly in untouched code (`src/admin` 2447, `src/gateway` 958,
`src/common` 144) plus `dist/assets` 1290 when a build is present. Pre-existing;
not investigated further.

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

### Two primitives the fork check found, not the design (screen 6c)

The mechanical fork check (grep the new-UI screens for repeated patterns before
each screen commit; two matches in different files = stop) earned its keep
twice in one commit.

**`ui/CopyButton.svelte`.** `common/CopyButton.svelte` is built on sveltestrap's
`Button` and `svelte-fa`, and **two already-written new-UI screens imported it** —
`CreateOtpModal` (landed in 6b) and the new `CertificateCredentialModal`. That
would have kept sveltestrap alive past the deletion commit, and it would have
surfaced as a build failure at the worst possible moment rather than here.

It keeps the `copy-text-to-clipboard` dependency deliberately.
`navigator.clipboard.writeText` only exists in a **secure context**, and this
admin UI is reachable over plain HTTP on internal addresses, where that API is
`undefined`. The package falls back to the `execCommand` textarea trick, which
works there. Swapping it for the modern API would break copying in exactly the
air-gapped and DMZ deployments this fork targets.

**`ui/Textarea.svelte`.** Byte-identical hand-rolled textarea CSS in
`kubernetes/Options.svelte` (screen 4f, already committed) and
`PublicKeyCredentialModal.svelte`, each with its own label-wrapper div. Same
shape of omission as Callout: the Phase 2 primitive set has no multi-line
field, so every screen that needs one invents it. The API mirrors `Input` field
for field so the two are interchangeable at a call site. `mono` defaults to
**on** — every multi-line field in Warpgate holds machine text (PEM, OpenSSH
keys, YAML) and proportional type makes those materially harder to proofread.

`ui/forms.css` came out of the same pass: three byte-identical `.fields` blocks
across the credential modals. Same consolidation as `markers.css`, layout only.

### `ui/Input` swallowed `data-autofocus`

`focusTrap` moves focus on open by `node.querySelector('[data-autofocus]')`,
which needs the attribute on a **real DOM element**. `ui/Input` had no such
prop, so `<Input data-autofocus />` was a type error in the four credential
modals — and in a plain `.svelte` file with looser typing it would have been
silently dropped onto nothing, leaving focus to fall back to the first tabbable
element with no visible symptom. Added an explicit `autofocus` prop that
forwards `data-autofocus` onto the `<input>`; `ui/Textarea` has the same.

### A local `confirm()` shadowed `window.confirm`

`ui/ConfirmDialog.svelte` named its own handler `confirm()`. Harmless at
runtime (it is a declaration, not an assignment, so Biome's `noGlobalAssign`
stays quiet) but it put the replacement for `window.confirm` into the grep that
audits for remaining `window.confirm` call sites. Renamed to `runConfirm`. Same
family as the earlier `open` / `status` / `close` shadowing.

### Biome's import sorter walks docblocks down the import list

A `/** ... */` block placed directly above the first `import` is treated as
that import's leading comment and **travels with it** when the sorter reorders.
The file-header docblocks in three files ended up parked in the middle of the
import list. Separating the docblock from the first import with a blank line
detaches it; verified stable across a second `biome check --fix` pass.

### The theme bundles are `.js`, not `.css`

`theme.dark` and `theme.light` are emitted as **JavaScript** chunks
(177.7 + 178.6 = 356.3 KB), not stylesheets — they are the Bootstrap SCSS
imported through JS. Any measurement that greps `dist/assets/*.css` for them
finds nothing and silently reports a 356 KB shortfall. This is the
reclassification the Bootstrap deletion is expected to realise: those bytes
move from the JS column to the CSS column rather than simply disappearing.

### Screen 8: what the Tickets mockup shows that the API does not have

The `Ticket` model is `id, userId, username, description, targetId, target,
usesLeft?, selfService, expiry?, created`. Measured against
`warpgate_access_tickets/screen.png`, these were omitted rather than faked:

- **Role column** — a ticket carries no role; access is granted via the target.
- **Created By column** — `username` is the ticket's *subject*, not its issuer.
  There is no issuer field at all. The column is relabelled "User", which is
  what the field actually means.
- **"1 of 3" uses** — only `usesLeft` is returned. The original `numberOfUses`
  is accepted on create and never read back, so the denominator does not exist.
  Shown as uses left alone.
- **Revoked status** — not a state. `deleteTicket` removes the row; there is no
  tombstone. The filter offers Active / Expiring / Used / Expired, all derived.
- **Historical quota, Velocity (24h)** — need deleted tickets and a time series.
- **Issuer filter, Export** — no backing field, no endpoint.
- **"Ticket Payload Scaffolding (Live Bastion Wire)"** with TOKEN_AUTH,
  FINGERPRINT and POLICY_EVAL lines — invented wholesale. No such API exists,
  and the values shown (a root CA signature, an IP-pinning bypass) describe
  features Warpgate does not have.

Ticket state is derived on load, once, into a Map keyed by id — not recomputed
per cell. Two `Date.now()` readings in one render pass can put a ticket in
"active" for the stat cards and "expiring" for the table row.

### A third sveltestrap component reaching into the new UI

`common/RelativeDate.svelte` wraps its text in sveltestrap's `Tooltip`, and
**Sessions and Session — screens 1 and 2, both committed — imported it**. After
`common/CopyButton.svelte` this is the second such find, which makes the
pattern worth stating: a shared component under `common/` is not automatically
safe for the new UI. Before the deletion commit, every `common/` import from
`admin/screens/` needs checking, not just the ones that look like widgets.

`ui/RelativeDate.svelte` drops the styled tooltip for a native `title`, which
is a deliberate divergence. ui/Tooltip reveals on hover *and* focus, but it
observes `focusin` from its children, and a `<time>` element is not focusable —
so the styled tooltip could never reach a keyboard user in a table cell.
Making every date focusable to fix that would put a tab stop on every date in
every table. `title` is announced as the accessible description, needs no JS,
and `datetime` carries the unambiguous machine value that neither the relative
text nor a locale string does.

### `ConnectionInstructions` is deferred to screen 13

529 lines, sveltestrap-based, and imported by six callers — including
`admin/screens/target-detail/Target.svelte`, which is already committed. It is
a screen-sized migration in its own right and it is most central to the portal,
so it moves at screen 13 rather than being absorbed piecemeal into screen 8.
Same treatment the credential modals got in 6c.

### The full `common/` blast radius for the Bootstrap deletion

`common/CopyButton` and `common/RelativeDate` were not isolated cases. A
complete audit of what migrated code imports from `common/`, separating
runtime imports from type-only ones (which Rollup erases and which therefore
cost nothing):

| Component | sveltestrap | Runtime call sites in migrated code |
|---|---|---|
| `Loadable` | yes | target-detail/Target, CredentialEditor, SsoCredentialModal, user-detail/User |
| `ItemList` | yes | Targets, **ui/Table** — deliberate, Table wraps it by design |
| `RateLimitInput` | yes | target-detail/Target, user-detail/User |
| `ConnectionInstructions` | yes | target-detail/Target, tickets/CreateTicket |
| `GettingStarted` | yes | Sessions |
| `CredentialUsedStateBadge` | yes | CredentialEditor |
| `CopyableTextArea` | yes | target-detail/ssh/KeyCheckerResult |

Type-only imports of `common/ItemList.svelte` (Sessions, Users, Tickets) pull
in nothing at runtime and are fine as they are.

`ui/SkeletonRow` mentions `DelayedSpinner` in a docblock but does not import
it; the primitive layer's only `common/` dependency is `ui/Table` → `ItemList`,
which is the approved arrangement.

So "the new UI has no sveltestrap" is true only of *direct* imports. Seven
shared components have to migrate before the deletion commit can build, and
they are not on the numbered screen list. `ConnectionInstructions` is booked
for screen 13; the rest need a home.

### "Remove the corpse" does not apply until both UIs stop referencing it

`common/StatCard.svelte` had exactly one importer, `admin/status/LoginProtection.svelte`,
which screen 9 replaces — so it looked dead and was deleted. It is not dead:
the **old** `App.svelte` still routes `/status/*` to `admin/status/Status.svelte`,
which still lazy-imports the old LoginProtection, which still imports
`common/StatCard`. Deleting it breaks the `VITE_NEW_UI=false` build, which is
the rollback path.

Caught by building the old UI, not by svelte-check — the old screen type-checks
fine right up until the import cannot resolve. Shared components can only be
removed in the deletion commit, once the old screens go with them. The
old-UI build is the test that proves it, and it stayed byte-identical
(1620.6 / 1264.3 / 356.3 / 36.4 / 2014.6 / 733.6) after restoring the file.

### In-place migration changes the OLD-UI bundle too

Screen 10 migrated `admin/log-viewer/LogViewer.svelte` and its badges **in
place**, because the sveltestrap surface was one Alert and two Tooltips inside
907 lines of virtualizer and pagination logic. Copying it would have duplicated
900 lines to restyle 30.

The consequence is that the old-UI build is no longer byte-identical to
baseline: the old `Log.svelte` and `admin/status/Session.svelte` render the
same migrated components, so `VITE_NEW_UI=false` now pulls in ui/Button,
ui/Callout, ui/Input, ui/Tooltip and ui/Badge.

  old-ui before  JS 1620.6 | CSS 36.4 | total 2014.6 | gz 733.6
  old-ui after   JS 1629.2 | CSS 45.1 | total 2031.8 | gz 737.8

This is fine, and it is worth being precise about why: `admin/index.ts` — the
shared entry carrying the `VITE_NEW_UI` test — imports `'../theme'`, so
`theme/tokens.css` is loaded under **both** flags. The migrated components
render with correct tokens in the old UI rather than unstyled. Verified in the
old-UI output: `LogViewer-*.css` contains both `--wg-*` token references and
the `wg-badge` / `wg-tip` classes.

So the rollback invariant changes from "old-UI build is byte-identical" to
"old-UI build still builds and still renders correctly". The first phrasing
only ever held while every migration was a copy. Any future in-place migration
moves the old-UI number, and the check that matters is the build plus a visual
pass, not the byte count.

### The portal had no rollback flag

`gateway/index.ts` mounted `Root.svelte` unconditionally — `VITE_NEW_UI`
existed only on the admin side. Migrating any portal screen in place would
have changed the live sign-in page with no way back, against the rule that the
flag *is* the rollback mechanism.

Screen 12 adds the same gate to the portal: `gateway/index.ts` chooses between
`Root.svelte` and `RootNew.svelte`, with the test written **inline** for the
same reason as the admin side — Rollup only eliminates the losing branch when
`import.meta.env.VITE_NEW_UI` is a literal in that module. Importing `NEW_UI`
from `flags.ts` ships both shells; that cost +111 KB when it happened in
Phase 1.

Verified by the two-build probe:

  VITE_NEW_UI=false   App- 6 chunks, Root- 2   AppNew 0, RootNew 0
  VITE_NEW_UI=true    App- 0 chunks, Root- 0   AppNew 6, RootNew 2

### `'\d{6,8}'` is not the pattern you think it is

The sign-in OTP field carries `pattern="\d{6,8}"` — 6 digits for TOTP, up to 8
for recovery codes. Writing that as a Svelte expression `pattern={'\d{6,8}'}`
produces the string `"d{6,8}"`, because `\d` is not a recognised JS string
escape and collapses to a bare `d`. The attribute then matches literal `d`
characters, so **every valid code is rejected** — and the source still reads
correctly at a glance.

Biome's `noUselessEscapeInString` caught it, which is worth noting because its
message ("the character doesn't need to be escaped") sounds cosmetic and is
not: the suggested fix is correct precisely because the escape was already
doing nothing.

The screen now uses `/\d{6,8}/.source`, a regex literal, which cannot go wrong
this way. Verified against the original's accept/reject set: 6, 7 and 8 digits
accepted; 5 digits, 9 digits and non-digits rejected — and confirmed that the
string-literal form rejected all three valid lengths.

The portal mockup's six separate digit boxes are omitted for the same reason
the pattern matters: the field has to accept 6 **to 8** characters, which a
fixed six-box control cannot express. A single field also pastes correctly
from a password manager.

### Screen 13: the portal target card has almost no data to put in it

`TargetSnapshot` — what the **portal** sees — is `id, name, description,
kind, externalHost?, group?, defaultDatabaseName?`. That is the whole model.

The mockup's cards show a hostname and port, a role list, and an
Online/Unreachable status, none of which exist here. The missing host and port
look like an oversight and are not: the portal deliberately does not publish
internal addresses to users, which is most of the point of a bastion. So the
card keeps the mockup's *shape* — roomier than an admin table, right for a
dozen items — with the fields that exist, and drops the rest along with
"11 operational / 1 degraded", the RECENTLY USED strip, the ZONE label and
the per-card copy button (whose only sensible payload is the address that
does not exist).

The protocol filter chips are kept: `kind` is real, and the chips are derived
from what the search returned rather than from what the chip filter then
narrows it to — otherwise choosing one chip makes the others disappear.

### Two accessibility defects found by migrating, not by auditing

**The certificate rows in ConnectionInstructions were fake buttons.** Each was
`<a href="#" onclick={e => { e.preventDefault(); select(...) }}>`. It announced
as a link, offered a meaningless open-in-new-tab, and gave no indication of
which certificate was selected — the selected state was a background colour
only. They are real `<button aria-pressed>` now.

**The portal's "open targets in a new tab" preference announced as nothing.**
It was a switch nested inside a sveltestrap `DropdownItem`, so it was neither
a menu item nor a checkbox to assistive tech, and the reason it was disabled
under administrator policy was carried by a hover-only tooltip. It is now a
`menuitemcheckbox` with `aria-checked`, and the policy reason is a visible
hint. `ui/Menu` grew checkable items for this, and a checkable item keeps the
menu open so the tick can be seen to change.

Biome's `useAriaPropsSupportedByRole` initially flagged `aria-checked` because
the `role` was a ternary it could not resolve statically. Splitting it into two
branches with literal roles fixed the warning and is clearer — each element is
now statically verifiable rather than only correct at runtime.

## The migration is complete

The redesigned UI is the only UI. `VITE_NEW_UI` is gone, both old shells are
deleted, and Bootstrap and sveltestrap are out of `package.json`.

### Final state

```
svelte-check   1081 files (was 1304), 0 errors, 0 warnings
ui/ primitives 26
.svelte files  147
routes         36 admin, 8 portal
native dialogs 0 window.confirm, 0 alert()
sveltestrap    0 imports anywhere in src/
```

Bundle, against the Phase 0.5 baseline:

```
baseline  JS 1620.6 | theme 356.3 | CSS  36.4 | total 2014.6 | gz 733.6
final     JS 1231.2 | theme   0.0 | CSS 118.6 | total 1707.3 | gz 703.2
                                                -15.3% raw, -4.2% gzipped
```

The 10% budget was a ceiling and the result comes in under the original. The
356 KB of compiled Bootstrap JS is gone outright, partly offset by +82 KB of
token CSS — the JS-to-CSS reclassification predicted in Phase 1, realised.

### Deleting the old UI was computed, not guessed

A reachability walk over static **and** lazy imports from the four real entry
points (admin, gateway, embed, styleguide) produced the delete list: 45 files
that nothing reaches. Four unreachable files were kept deliberately —
`vite-env.d.ts` and `gateway/zmodem.js.d.ts` are ambient type declarations that
no import mentions, and `ui/index.ts` / `shell/index.ts` are the primitive
barrels.

Doing this by inspection would have deleted at least two of those four.

### Two audit corrections worth remembering

**The first audit script under-reported by half.** It followed only top-level
`import` statements, and `AppNew` reaches every screen through
`asyncComponent: () => import(...)`. It cheerfully reported ZERO sveltestrap
reachable while 32 files were still live. Any reachability check on this
codebase has to follow dynamic imports.

**Seeding the audit with the entry points inflates it instead.** `admin/index.ts`
and `gateway/index.ts` referenced *both* shells while the flag existed — that
is what a flag is. Seeding them made the figure jump to 35. The meaningful
seeds were the two new shells plus `RootNew`.

Both mistakes were mine, in the same tool, in opposite directions.

### `sass` stays

Removed with Bootstrap, then put back. It is a build-time preprocessor, not a
UI framework, and 17 files still use `<style lang="scss">` for nesting. It never
reaches the browser. "Delete Bootstrap" and "delete the SCSS toolchain" are
different jobs and only the first one was asked for.

### A fresh clone cannot build without `just openapi`

The generated OpenAPI clients are gitignored and produced by `postinstall`,
which needs Java and a POSIX shell. A fresh clone therefore has no
`src/*/lib/api-client` until that runs — `npm ci` alone is not enough. The
Dockerfile already accounts for this; a human cloning the repo on Windows will
hit the `rm -rf` failure documented earlier unless `npm_config_script_shell`
points at Git Bash.

Verified by cloning to a clean directory at the flip commit: no old-UI file is
present, `package.json` has no Bootstrap or sveltestrap, and with the API
clients supplied the build produces byte-equivalent output (1705.7 KB against
1705.5 in the working tree).

### Route shadowing: `/config/targets/create` was parsed as a target id

Reported from a running instance:

```
ERROR HTTP: Request failed method=GET
  url=.../@warpgate/admin/api/targets/create
  error=ParsePathError { name: "param0",
    reason: "failed to parse \"string_uuid\": invalid character: found r at 1" }
```

Clicking **Add a target** produced a 500. The `r` at position 1 is the second
letter of `create`.

**Cause.** svelte-spa-router keeps routes in declaration order and returns the
FIRST pattern that matches. `AppNew.svelte` declared `/config/targets/:id` in a
"migrated" block at the top of the routes object while `/config/targets/create`
stayed in the "not yet migrated" block eleven entries below it. So `create`
matched `:id`, the target-detail screen mounted with `id = "create"`, and its
`getTarget({ id })` asked the server for a target whose UUID is the word
`create`.

This was mine, introduced when AppNew was written: splitting the table by
migration status separated a route family, and `create`/`:id` only work if they
stay adjacent and in that order. Every other family (users, access roles, admin
roles, target groups, LDAP) happened to keep both halves in the lower block and
was unaffected — which is why nothing else broke.

**Fix.** The migration-status split is gone (everything is migrated). Routes are
grouped by family, and within a family every literal path precedes any `:param`
path. The rule is stated in the file, with this failure as the example.

**Checks added to the scratchpad tooling** — worth re-running after any routing
change:

- *shadowing*: compile each route with `regexparam`, exactly as the router
  does, and report any literal route an earlier pattern already matches. It
  reproduced this bug and found no others; both portal tables were clean.
- *resolution*: assert that eleven representative paths reach the intended
  component, including every `…/create` in the app.
- *dangling links*: collect every `push`, `replace` and in-app `href`, and
  check each against the route tables. 51 distinct links, all resolve.

The route SET was diffed against the previous commit to confirm the regroup
added, removed and renamed nothing.

## Deleting Bootstrap left ~25 screens unstyled

Found while hunting for further runtime defects after the routing fix, by
asking a question the migration never asked: *which CSS classes does the markup
still use that nothing defines any more?*

The screens 15-23 sweep replaced sveltestrap **components**. It did not replace
Bootstrap **utility classes**, because nothing forced it to — `class="d-flex
mt-3"` compiles fine with no stylesheet behind it and fails silently in the
browser. Deleting Bootstrap also took `theme/_theme.scss`, which had imported
it and had itself defined `.container-max-md`, `.page-summary-bar` and
`.modal-button`.

**299 class usages across 25 files, 122 distinct classes.** The worst affected
were Parameters, TicketRequests, LdapServer, LdapUserBrowser, AdminRole,
AccessRole, ConnectionInstructions and SSHKeys — rendering with browser-default
inputs, no flex rows, no max width and unstyled buttons.

### The checker was wrong twice before it was right

The first version asked "is this class defined anywhere in `src/`?" That is the
wrong question. **A Svelte `<style>` block is scoped to its component**, so the
`.btn` rule in `PlayerToolbar.svelte` never reached the `.btn` in
`LdapServer.svelte`. Only three things are actually global: a plain `.css`
file, a rule inside `:global(...)`, and a `<style global>` block. Asking the
scoped question moved `btn` (11 files), `list-group-item` (6), `list-group` (5)
and `row` (3) from "fine" to "orphaned".

The second version over-reported, because a Svelte class attribute has four
shapes at once — `class="a b"`, `class={expr}`, `class="a {expr}"` and
`class:name={expr}` — and a naive regex turned `class={props.class ?? ''}` into
three "classes" named `{props.class`, `??` and `''}`. Names a template splices
into (`wg-marker-{shape}`) are not statically checkable at all and are now
dropped rather than reported.

Both mistakes were in my own tool, and in opposite directions — the same
failure as the sveltestrap reachability audit earlier. A checker that has not
been made to report a known-bad case is not evidence.

### The fix: `ui/compat.css`

One global stylesheet, imported from `theme/index.ts` (which both entry points
already import, so both bundles get it — verified in both built HTML files).

It is written **in terms of the design tokens**, not as a Bootstrap imitation.
`.btn.btn-primary` is the same object `ui/Button` draws; `.form-control` is the
same shell `ui/Input` draws. The consequence is that the affected screens look
like the redesign *now*, and converting their markup to the primitives later is
a cleanup with no visual change, rather than a second migration. The file is
meant to shrink to nothing and says so at the top.

Bootstrap's spacing steps land exactly on the token scale — 1=xs (0.25rem),
2=sm (0.5), 3=lg (1), 4=xl (1.5), 5=3xl (3) — so the rhythm the old markup was
laid out to is preserved rather than re-guessed.

Two deliberate judgements:

- **The spacing scale is generated in full**, not limited to the steps in use.
  Everything else in the file is strictly what the markup references. A missing
  `.mt-2` is invisible until someone opens that screen, and that asymmetry is
  worth ~1 KB.
- **`.form-switch` is redrawn as a toggle** rather than left as a checkbox, so
  the LDAP screen reads the way it did. The control stays a native checkbox
  underneath, so its keyboard and assistive-tech behaviour is unchanged, and
  the transition is disabled under `prefers-reduced-motion`.

Specificity is not a risk here: Svelte's scoped selectors compile to `(0,2,0)`
and these are `(0,1,0)`, so any component rule still wins. The generic names
(`.row`, `.table`, `.nav`) cannot reach a proxied HTTP target either — that is
a different document.

```
122 orphaned classes / 299 usages  ->  29 / 31
bundle  1707.3 -> 1719.1 raw (+11.8 KB), 703.2 -> 705.3 gz (+2.1 KB)
        still -14.7% raw / -3.9% gz against the 2014.6 / 733.6 baseline
```

### What the remaining 29 are

None are Bootstrap. They split three ways:

- **False positives** — string literals inside an expression that feed a
  dynamic name or are not classes at all: `diamond`, `dot`, `warning`
  (`wg-marker-{shape}`), `certificate`, `oidc` (a `kubeconfigMode` value),
  `kind`, `session`, `username`.
- **Hooks that need no rule** — a wrapper element whose children carry the
  styling, or a class passed to a child component so callers can target it:
  `wg-tabs`, `wg-skeleton`, `wg-check-label`, `wg-status-label`,
  `wg-table-search`, `wg-table-density`.
- **Genuinely missing rules, in my own new code** — `panel` (3 files),
  `head-actions`, `head-titles`, `notice`, `tl-field`, `help-text`, `hostkey`,
  `hostkey-lead`, `probe-label`, `sg-type`, `sg-spacing` and the four
  `a-callout-*`. Fixed separately; a compatibility stylesheet is the wrong
  place for them.

## …and sixteen dangling `var()` references, which a class checker cannot see

Found immediately after, while reading `HelpText.svelte` for an unrelated
reason. The orphaned-class audit asks about **classes**. Deleting Bootstrap
also removed its **custom properties**, and a dangling `var()` is invisible to
a class-based check, to the compiler, and to `svelte-check`.

CSS makes this worse than a missing class. An undefined custom property in a
`var()` with no fallback is **invalid at computed-value time**: the whole
declaration is discarded and the property resolves to inherit (inherited
properties) or initial (everything else). The failure is not "no style", it is
"a different style", and nothing reports it.

### Ten `--bs-*` references, in four files

| site | what it did |
|---|---|
| `StickyActionBar` | `background: var(--bs-body-bg)` → **transparent**. A sticky bar that content scrolls under had no background: page text showed through the save bar on Parameters. `border-top` was dropped entirely. |
| `LogViewer` header | `var(--bs-body-bg, #fff)` → the fallback fired, giving a **white bar in the dark theme**. Its separator was `rgba(0,0,0,.12)` — black on dark, invisible. |
| `LogViewer` auth-failed rows | Bootstrap's danger palette via fallback hex; now `--wg-error` / `--wg-error-container`, with `--wg-on-error-container` for the text so the pairing carries its own contrast. |
| `HelpText` | `color` → inherit, so help text rendered at full body colour; the `border-left` shorthand was dropped, leaving the `border-left-style: dotted` on the next line to draw a 3px rule in the current colour. |
| `DesktopRecordingPlayer` | `var(--bs-font-monospace, monospace)` — harmless, the fallback fired. |

Plus two dead `:global(.spinner-border)` rules. **sveltestrap's `Spinner`
emitted that class; `ui/Spinner` does not.** Replacing the component silently
un-centred both recording players' loading spinners, because the rule that
positioned them stopped matching. A real `.loading` element now carries the
same absolute centring.

### Six references to tokens that never existed

`--wg-text-headline-sm` (5 files) and `--wg-text-display-sm` (1) are mine, and
are defined nowhere. DESIGN.md's type scale has headline-lg, headline-lg-mobile
and headline-md, then goes to body — there is no headline-sm and no display
step at all.

Every site already carried a fallback, so every site already rendered the
fallback; the references were an elaborate way of writing it. **Adding the two
tokens would have been inventing a step the design system deliberately does not
have**, so they are collapsed to what they already rendered instead: no visual
change, six fewer phantom tokens. It is worth noting they were not even
consistent — four fell back to `headline-md`, one to `body-lg`, one to
`headline-lg`.

### The checker was wrong once more, in the same way

Its first run reported `--marker`, `--size` and `--wg-stat-ink` as broken. All
three are set from the markup, as `style="--size: {n}px"` or the
`style:--name={…}` directive, and all three work. Scanning only `<style>`
blocks for definitions is the same scoping mistake as before, one namespace
over. Fixed; the audit now reports **0 dangling `var()`**.

### Why this survived a migration, a deletion commit and a clean svelte-check

Removing a dependency breaks **references**, not **imports**, and references
live in four namespaces:

1. class names — `svelte-check` says nothing; caught by the scoped orphan audit
2. custom properties — silent, and *changes* style rather than removing it;
   now caught by the same tool
3. class names a deleted component used to *emit* — `.spinner-border`; silent,
   and only findable by reading the rules that target them
4. SCSS variables — the one that is safe: sass errors on an undefined `$var`,
   so a green build already proves there are none

Three of the four fail silently. Bundle unchanged at 1719.2 KB / 705.3 gz.

## The last of it: eleven classes in the new screens with no rule behind them

With Bootstrap's classes bridged and the dangling `var()`s gone, the audit was
left with 29 orphans, none of them Bootstrap's. Reading each one rather than
trusting the count split them three ways.

**Intentional hooks — no rule wanted.** A wrapper element whose children carry
the styling (`wg-tabs`, `wg-skeleton`, `wg-status-label`, `wg-check-label`), a
class passed to a child component so a caller can target it (`wg-table-search`,
`wg-table-density`), and — the one worth naming — `a-callout-info` and its
three siblings in the styleguide, which are **selectors the contrast audit
looks elements up by**. A class can be an address rather than a style.

**False positives.** String literals inside an expression that feed a spliced
name or are not classes at all: `diamond`, `dot`, `warning` (they become
`wg-marker-{shape}`), `certificate`, `oidc` (a `kubeconfigMode` value).

**Genuinely missing rules — eleven, all mine.** These render as bare markup:

- **`panel`, in three delete dialogs.** `<p class="panel">` carrying the
  consequence text, defined nowhere, in AccessRole, AdminRole and LdapServer.
  The fix is not a `.panel` rule in three files — that is the fork this repo
  keeps producing — but `ConfirmDialog` styling its own body, once. It now
  wraps `{@render children()}` in an element it owns and reaches the caller's
  paragraphs through `.wg-confirm-body :global(p)`, which is the only way:
  snippet content carries the **caller's** scope hash, not the component's.
  The three call sites drop the class entirely.
- **`hostkey` and `hostkey-lead`, in the SSH host-key prompt.** The one that
  matters. The dialog asks the user to compare a fingerprint out of band, and
  the key is a single unbroken base64 run — with no rule it overflowed the
  modal, so the thing being verified was partly off-screen. Now a sunken code
  block with `overflow-wrap: anywhere`.
- `head-actions` (Roles), `head-titles` (User, needs `min-width: 0` or a long
  username pushes the actions off the edge), `notice` (Parameters — which
  turned out to have **no `<style>` block at all**, which is why it resolved to
  nothing), `tl-field` (Session), `help-text` (HelpText hung its styling on the
  bare `small` element, leaving the class it names meaningless; the class now
  carries it).

### One more theme bug, from a different angle

Hardcoded black and white in CSS is wrong by construction — it can be right in
at most one of the two palettes. A sweep found 24 declarations, 23 of them
legitimate: the token layer itself, the players' and terminal's black chrome,
the modal scrim, `EmbeddedUI` (injected into third-party pages), and the QR
code's white ground, which is documented in place because a QR inverted by a
dark palette is unreadable to most scanners.

The 24th was `.log-row`'s `border-bottom: 1px solid rgba(0, 0, 0, 0.06)` —
6% black on a dark surface, i.e. no row separators in the audit log at all. The
same defect as the sticky header's, one rule below it, missed on the first pass
because I was grepping for `--bs-` rather than reading the block.

```
orphaned classes  29 -> 21, all 21 classified as hooks or false positives
bundle            1720.0 KB raw / 705.5 gz
```

## 37 form controls with no accessible name

The screens 15-23 sweep unwrapped sveltestrap's `<FormGroup floating>` into a
`<div class="wg-field-group">` holding a `<span class="wg-field-label">` and a
raw control. **A `<span>` is not a `<label>`.** It has no `for`, so nothing
ties the text to the control: a screen reader announced 31 unnamed edit fields
on the global parameters screen, and the text was not clickable. `svelte-check`
has nothing to say about this, and neither does Biome — the markup is valid,
it just does not mean anything.

### The fix is the element, not an id

The obvious repair — give every control an `id` and every label a `for` — means
inventing 31 unique ids and keeping them unique forever. The HTML spec provides
exactly this shape instead: **implicit labelling**, `<label>text <input></label>`,
where containment does what `for` would. So `.wg-field-group` becomes the
`<label>` and nothing else moves.

Its precondition is one labelable control per group, so that was checked before
anything was rewritten: 33 groups, 32 with exactly one control, one with none
(it held a `Textarea` component). Two already had a real `<label for=>` and
were left alone — one of those was **double-labelled**, an explicit
`<label for="banner">` beside a `Textarea` already rendering its own hidden
label, so the field's accessible name was the same words twice. The component
now owns its label and shows it.

### It was not only Parameters

Running the check across every `.svelte` file found the same defect in the
deny-request dialog and in three fields of the portal's ticket request form,
plus two controls that never had a label at all: the LDAP user search box and
the recording player's seek slider. Those two get `aria-label` rather than
visible text, which is the idiomatic naming route for a search field and a
slider and does not change the design.

Two of the ticket-request fields also hold their own validation message inside
the group. There the `<label>` wraps **only** the text and the control, because
wrapping the whole group would splice the error text into the field's
accessible name — the field would announce itself as "Duration" plus whatever
the last error said.

### What the checker actually asserts

It asserts the **new** thing: every native control has an accessible name by
one of the four routes the spec allows — wrapped in a `<label>`, an `id`
matched by some `<label for=>`, `aria-label`, or `aria-labelledby`.

It was wrong twice, in the by-now familiar way. It missed Svelte's `{id}`
attribute shorthand, which is how every `ui/` primitive passes its id, and
reported four of them as broken. And it read the docblocks: this repo's
comments describe markup — "ui/Select is a real `<select>` over strings" — so
prose about a control was being counted as a control. Comment bodies are now
blanked with spaces of the same length, which keeps the reported line numbers
true.

```
58 native controls checked, all named   (was 37 unnamed)
```

Behaviour is unchanged, and that is asserted rather than assumed: the set of
`bind:value`, `bind:checked`, `onchange`, `oninput` and `onclick` expressions
in all three rewritten files hashes identically to `HEAD`. Only wrapping
elements moved. Bundle 1720.3 KB raw / 705.5 gz.

## A lost behaviour hiding behind a dead branch

I had this noted as "pre-existing dead config" and was about to delete it. It
was not. It was a regression I introduced.

`gateway/AppNew.svelte` passes `'on:navigation'` through svelte-spa-router's
`props`, and `redirecting` is never true, so the portal's "Opening your
session" spinner is unreachable. The easy reading is that nothing ever
dispatched it. Checking the history instead of assuming:

```
6342fcb3  HTTP targets support (fixes #116)
    <TargetList on:navigation={() => redirecting = true} />
    function loadURL (url) { dispatch('navigation'); location.href = url }
```

Upstream dispatched it **immediately before `location.href = url`**, so the
portal replaced the target list with a spinner for the gap between the click
and the browser leaving — which on a slow HTTP target is long enough to look
like the click did nothing. `screens/Targets.svelte` replaced `TargetList` and
dispatches nothing, and in Svelte 5 `'on:navigation'` is not an event listener
at all, just a prop whose name contains a colon. Two independent breaks, so
nothing complained.

Reconnected as an ordinary callback prop, which is what `on:` meant in Svelte
4. It fires only on the `location.href` branch: the new-tab branch leaves this
page where it is, and a spinner over a list that is still usable would be a
lie.

**The lesson is about the word "dead".** A branch that cannot be reached is
either configuration nobody needs or a feature whose wire was cut, and the two
are indistinguishable from the current tree. `git log -S` on the dead symbol
is what tells them apart, and it costs one command. I nearly deleted a feature
to make an audit come out clean.

## `docker compose up`, and the last of the two-UI scaffolding

Two requests, one underlying cause: the Docker setup still described a world
with two frontends behind a flag, and none of its entry points was a bare
`docker compose up`.

### What was actually still "old UI"

`docker/docker-compose.yml` pulled `ghcr.io/warp-tech/warpgate` — **the
published upstream image, which contains the old UI**. So the most obvious
command in the repo, `docker compose -f docker/docker-compose.yml up`, ran
exactly the thing this fork replaced. That is the old UI component worth
removing; deleted, superseded by the root `compose.yaml`.

`VITE_NEW_UI` was worse than inert. `admin/index.ts` and `gateway/index.ts`
read no flag any more, so the ARG selected nothing — but its default was
`false`, which meant every image built without an explicit build arg was
stamped `org.warpgate.new-ui="false"` while containing the new UI. A label that
answers the question **wrongly** is worse than no label. Removed from the
Dockerfile along with the value-normalisation block, and from
`dev-entrypoint.sh`, where `ui-new` / `ui-old` collapse into one `ui` task
(both old names kept as aliases so existing notes still work).

`docker-compose.build.yml` existed only to layer a build onto the published
image and pick a UI. Both reasons are gone; deleted.

Four source docblocks still said "behind VITE_NEW_UI", and two of them were not
merely dated but false: `shell/AppShell.svelte` and `shell/index.ts` both
claimed the shell was "not wired into the app yet" while
`admin/AppNew.svelte:222` renders it around every admin route.

### One command

`compose.yaml` at the repository root, because that is where `docker compose`
looks with no `-f`. It builds from the working tree with `context: .`, which is
what `docker/Dockerfile` needs (`COPY . /opt/warpgate` plus `COPY .git/`) and
what `.github/workflows/docker.yml` already uses.

The interesting part is first-run setup. The image's ENTRYPOINT is `warpgate`
itself, so a compose `command:` can only pass it arguments — it cannot express
"set up first, but only once". Rather than add a wrapper script to the
production image, which upstream does not have and which would make this fork's
image differ from the published one, the entrypoint is overridden with a shell
that runs `unattended-setup` when `/data/warpgate.yaml` is absent and then
`exec warpgate run`.

**The admin password is generated, not defaulted.** A known password in a
compose file is fine right up until someone runs it on a reachable host, and
this is a gateway to other machines — so if `WARPGATE_ADMIN_PASSWORD` is unset,
24 random characters are drawn from `/dev/urandom` and printed once. Setting it
in `.env` still works; `.env` is already gitignored.

`WARPGATE_EXTERNAL_HOST` is exposed for the same reason the deployment at
10.13.14.56 would otherwise be subtly wrong: it is baked into the URLs Warpgate
generates for HTTP targets and tickets, so a gateway set up as `localhost` and
reached at an IP hands out links pointing back at the visitor's own machine.

### The `$$` that had to be checked rather than assumed

Compose interpolates `$VAR` before the container sees it, so the entrypoint
script escapes every shell variable as `$$VAR`. `docker compose config` prints
those back as `$$` too, which proves nothing either way — its output is meant
to be re-consumable, so a literal `$` must be re-escaped on the way out.

Settled with a two-line throwaway compose file: `$HOME` rendered as
`C:\Users\AA3777371` (substituted by Compose), `$$HOME` rendered as `$$HOME`
(preserved as an escape). So the container receives a literal `$`, which is
what the script needs.
