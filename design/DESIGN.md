---
name: Warpgate Mission Console
colors:
  surface: '#101418'
  surface-dim: '#101418'
  surface-bright: '#363a3e'
  surface-container-lowest: '#0b0f13'
  surface-container-low: '#181c20'
  surface-container: '#1c2024'
  surface-container-high: '#262a2f'
  surface-container-highest: '#31353a'
  on-surface: '#e0e3e8'
  on-surface-variant: '#c3c6d2'
  inverse-surface: '#e0e3e8'
  inverse-on-surface: '#2d3135'
  outline: '#8d919c'
  outline-variant: '#424750'
  surface-tint: '#a9c7ff'
  primary: '#a9c7ff'
  on-primary: '#003063'
  primary-container: '#7ba7f0'
  on-primary-container: '#003b77'
  inverse-primary: '#2e5ea2'
  secondary: '#ffb94e'
  on-secondary: '#452b00'
  secondary-container: '#c88601'
  on-secondary-container: '#3f2700'
  tertiary: '#69dc9d'
  on-tertiary: '#003920'
  tertiary-container: '#46bb7f'
  on-tertiary-container: '#004629'
  error: '#ffb4ab'
  on-error: '#690005'
  error-container: '#93000a'
  on-error-container: '#ffdad6'
  primary-fixed: '#d6e3ff'
  primary-fixed-dim: '#a9c7ff'
  on-primary-fixed: '#001b3d'
  on-primary-fixed-variant: '#084689'
  secondary-fixed: '#ffddb2'
  secondary-fixed-dim: '#ffb94e'
  on-secondary-fixed: '#291800'
  on-secondary-fixed-variant: '#624000'
  tertiary-fixed: '#86f9b8'
  tertiary-fixed-dim: '#69dc9d'
  on-tertiary-fixed: '#002111'
  on-tertiary-fixed-variant: '#005231'
  background: '#101418'
  on-background: '#e0e3e8'
  surface-variant: '#31353a'
typography:
  headline-lg:
    fontFamily: IBM Plex Sans
    fontSize: 32px
    fontWeight: '600'
    lineHeight: 38px
  headline-lg-mobile:
    fontFamily: IBM Plex Sans
    fontSize: 24px
    fontWeight: '600'
    lineHeight: 32px
  headline-md:
    fontFamily: IBM Plex Sans
    fontSize: 20px
    fontWeight: '600'
    lineHeight: 28px
  body-lg:
    fontFamily: IBM Plex Sans
    fontSize: 16px
    fontWeight: '400'
    lineHeight: 24px
  body-md:
    fontFamily: IBM Plex Sans
    fontSize: 14px
    fontWeight: '400'
    lineHeight: 20px
  label-md:
    fontFamily: IBM Plex Sans
    fontSize: 13px
    fontWeight: '500'
    lineHeight: 18px
  label-sm:
    fontFamily: IBM Plex Sans
    fontSize: 12px
    fontWeight: '400'
    lineHeight: 16px
  code-md:
    fontFamily: JetBrains Mono
    fontSize: 13px
    fontWeight: '400'
    lineHeight: 18px
  code-sm:
    fontFamily: JetBrains Mono
    fontSize: 12px
    fontWeight: '400'
    lineHeight: 16px
rounded:
  sm: 0.125rem
  DEFAULT: 0.25rem
  md: 0.375rem
  lg: 0.5rem
  xl: 0.75rem
  full: 9999px
spacing:
  gutter: 1rem
  gutter-compact: 0.5rem
  margin: 1.5rem
  margin-mobile: 1rem
  space-xs: 0.25rem
  space-sm: 0.5rem
  space-md: 0.75rem
  space-lg: 1rem
  space-xl: 1.5rem
---

## Brand & Style

This design system is built around the ethos of an **instrument panel, not a dashboard**. Designed specifically for Site Reliability Engineers, security operations teams, and systems administrators navigating high-stress, real-time scenarios, the interface treats information density as an essential operational asset rather than a design liability.

### Visual Character
- **Brutalist-Engineered Precision:** Unyielding adherence to structural boundaries, technical legibility, and physical clarity.
- **Zero Decorative Overhead:** Eliminates decorative gradients, atmospheric glows, and ornamental drop shadows. Every visual unit communicates system telemetry or operational state.
- **Quiet Dark Substrates:** High-contrast neutral ink resting on deep, low-luminance substrates ensures eye fatigue remains minimal across continuous 12-hour operational shifts.
- **Technical Rigor:** Machine identifiers (fingerprints, IPs, ports, tokens, cryptographic hashes) exist as first-class visual citizens with dedicated mono-spaced scaffolding.

## Colors

The color architecture is built specifically for low-light, high-vigilance monitoring. Chromatic accents are reserved strictly for status signals and deliberate interactive targets.

### System Palette
- **Canvas (`#0F1317`):** Primary root application substrate.
- **Surface (`#1A2028`):** Raised panels, inspector drawers, control bars, table headers, and container envelopes.
- **Surface Sunken (`#090C0F`):** Recessed telemetry viewports, terminal session viewports, payload dumps, and audit log blocks.
- **Hairline Border (`#2A323C`):** Strict 1px structural separator across all panels, tables, structural cells, and input borders.
- **Primary Interactive (`#7BA7F0`):** Action targets, selected filters, active pagination, and keyboard focus halos.
- **Signal Amber (`#F0A830`):** Active real-time connections, live session monitors, and warning-tier state flags.
- **Success Green (`#3FB57A`):** Verified authorizations, healthy nodes, nominal heartbeat statuses, and active routes.
- **Danger Red (`#E05C5C`):** Blocked targets, terminated access, revoked SSH keys, authentication failures, and destructive triggers.

### Typography Ink Palette
- **Text Primary (`#E9EDF2`):** Key headlines, table identifiers, active parameters, and interactive states.
- **Text Secondary (`#A3AEBA`):** Column definitions, secondary table attributes, payload metadata, and system metrics.
- **Text Muted (`#6B7785`):** Inactive timestamps, non-critical units, disabled actions, and protocol markers.

### State & Telemetry Matrix
State must always combine **geometry + label + color** to ensure absolute accessibility and unambiguous scanning speed:
- **LIVE Connection:** Filled `#F0A830` circle (6px) with a soft pulsing cadence + text label `"Live"`.
- **Healthy Node:** Hollow `#3FB57A` ring (1.5px border, 7px outer diameter) + text label `"Online"`.
- **Blocked Target:** Solid `#E05C5C` square (6x6px) + text label `"Blocked"`.
- **Terminated Session:** Solid `#6B7785` circle (6px) + text label `"Ended [timestamp]"`.
- **Failed Verification:** Solid `#E05C5C` upward triangle (7px base) + text label `"Failed"`.

## Typography

Typography establishes an uncompromising hierarchy of human-readable direction and precise machine output. Sentence case is universally enforced across all labels, headers, and badges. **All-caps formatting is strictly prohibited**, eliminating cognitive strain and visual jitter.

### Type Roles
- **System Interface (`IBM Plex Sans`):** Delivers clean geometry, distinct letterforms, and unambiguous numeral shapes across body copy, labels, actions, and administrative navigation.
- **Machine Data (`JetBrains Mono` / `IBM Plex Mono`):** Applied to technical outputs: hostnames, IPv4/IPv6 addresses, CIDR blocks, TCP ports, SSH key fingerprints, session UUIDs, ticket tokens, user roles, and shell audit records.

### Usage Rules
- Numerical readouts, network timestamps, and data telemetry must always render with tabular figures (`font-variant-numeric: tabular-nums;`).
- Session IDs, fingerprints, and hashes must not break mid-word; truncation occurs using central ellipsis (`truncate-middle`) to preserve both prefix and checksum integrity.

## Layout & Spacing

The layout operates on a strict **8px base grid** with a sub-grid of 4px for fine alignments (badge paddings, icon alignments, hairline separators).

### Structural Architecture
- **Admin Shell Structure:**
  - **Left Rail (Sidebar):** Fixed `240px` expanded width; collapes down to a `56px` persistent icon rail on dense workspaces.
  - **Top Bar:** Fixed `56px` height, spanning the screen with a bottom 1px `#2A323C` border.
  - **Content Canvas:** Fluid viewport with a maximum constraint of `1600px` to prevent ultra-wide scan latency.
  - **Global Padding:** Constant `24px` (`space-xl`) inside the content canvas.
- **Grid Systems:**
  - 12-column dynamic fluid grid for operational overviews and node configuration panels.
  - Full-width dense column format for target catalogs, access request queues, and continuous audit trails.
- **Responsive Adaptations:**
  - **Desktop (>1280px):** Permanent 240px sidebar, simultaneous inspector split-panes.
  - **Compact Viewport (768px - 1279px):** Sidebar collapses to 56px icon rail; auxiliary detail panes convert to sliding drawer overlays.
  - **Terminal / Single View (<768px):** Navigation tucks into a global dropdown drawer; tables degrade into card-based key-value stacks.

## Elevation & Depth

This design system explicitly rejects soft dropshadows, atmospheric blurs, and glassmorphism. Structural depth is expressed purely through **tonal transitions** and **1px crisp structural hairlines**.

### Surface Depth Stack
1. **Recessed Tier (`#090C0F`):** Lowest visual elevation. Applied to terminal emulators, interactive consoles, keystroke logs, and code diff blocks. Inset 1px `#2A323C` border.
2. **Base Canvas (`#0F1317`):** Primary background substrate for viewports and content areas.
3. **Elevated Surface (`#1A2028`):** Cards, table header rows, side panels, slide-out configuration shelves, and action bars. Framed with a 1px `#2A323C` stroke.
4. **Overlay Planes (Modals, Popovers, Dropdowns):** Built with Surface `#1A2028`, encircled by a 1px `#2A323C` border, accompanied by an intentional operational drop shadow: `0 4px 16px rgba(0, 0, 0, 0.6)`.

## Shapes

The design system employs an industrial, clipped corner radius matrix that reinforces utilitarian precision:

- **Buttons, Text Inputs, and Filter Bars:** `6px` corner radius.
- **Badges, Inline Tags, and Metadata Chips:** `4px` corner radius.
- **Panels, Flyouts, Cards, and Modal Enclosures:** `4px` corner radius.
- **Table Structures, Data Rows, and Sunken Code Boxes:** `0px` corner radius. Visual separation relies exclusively on adjacent borders and zebra row-striping.

## Components

### The border rule

**If a border is the only thing telling an operator where a control begins, it is border-strong.**

Borders come in two tiers and the split is a requirement, not a preference:

- **Divider tier** (`--wg-border`, the `outline-variant` hairline): decorative separation only — table row rules, cell hairlines, panel separators. Exempt from contrast rules because nothing depends on seeing it.
- **Component tier** (`--wg-border-strong`, the `outline` value): anything that delimits an interactive control — inputs, selects, buttons, checkboxes, focusable cards. Must clear WCAG 1.4.11's 3:1 against its background.

The rule is stated in terms of the border's *job* rather than its appearance so that it stays decidable at a call site nobody has written yet. When in doubt, ask what happens if the operator cannot see the border: if the answer is "they cannot tell where to click or type", it is component tier.

This supersedes the `1px solid #2A323C` figure quoted under **Input Fields & Selects** below, which measures 1.98:1 against the canvas and fails 1.4.11. A mockup can afford an invisible input border; a form filled in at 3am on an ops-room monitor cannot.

### Buttons
- **Primary:** Background `#7BA7F0`, text `#0F1317` (bold weight), border `1px solid transparent`. Hover: `#94B9F5`. Active: `#6392DE`. Radius: `6px`.
- **Secondary (Default):** Background `#1A2028`, text `#E9EDF2`, border `1px solid #2A323C`. Hover: `#222A35`.
- **Destructive:** Background transparent, text `#E05C5C`, border `1px solid #E05C5C`. Hover: `#E05C5C` fill with `#0F1317` text.
- **Sizes:** Standard input row height `32px` with `8px 12px` padding; compact toolbar height `28px` with `6px 10px` padding.

### Status Badges & Chips
- **Geometry:** Height `20px`, padding `0 6px`, radius `4px`.
- **Base Style:** Border `1px solid #2A323C`, background `#1A2028`, text typography `label-sm`.
- **State Markers:** Includes a geometric prefix (circle, square, or ring) sized at `6px` positioned with `4px` spacing before the label. Color accents applied to border and marker glyph only; backgrounds remain subdued to protect visual balance.

### Data Tables
- **Header:** Background `#1A2028`, bottom border `1px solid #2A323C`, typography `label-md`, text `#A3AEBA`.
- **Row:** Height `40px` (dense: `32px`), bottom border `1px solid #2A323C`, zero border-radius. Hover: background `#222A35`.
- **Cells:** Machine attributes render in `JetBrains Mono` at `13px`. Action cell anchors strictly on the far right.

### Input Fields & Selects
- **Base State:** Height `32px`, background `#090C0F`, border `1px solid` **border-strong** (see *The border rule* above — the `#2A323C` originally specified here fails 1.4.11), text `#E9EDF2`, radius `6px`, padding `0 8px`.
- **Focus State:** Border `1px solid #7BA7F0`, no outer ring glow.
- **Labels:** Typography `body-md` (`14px`), text `#A3AEBA`, positioned strictly above input with `4px` vertical separation.

### Terminal & Log Stream Viewer
- Recessed `#090C0F` viewport, inner padding `12px 16px`, typography `code-sm`.
- Interactive cursor: blinking `#7BA7F0` solid block (2px width).
- Ansi color outputs mapped to design system system colors (`#E05C5C`, `#3FB57A`, `#F0A830`, `#7BA7F0`).

### Session Recording Viewport
- Player scrub-bar: height `4px`, background `#2A323C`, active playback fill `#7BA7F0`.
- Keystroke activity markers: vertical hash-marks across the scrub bar in `#F0A830`.