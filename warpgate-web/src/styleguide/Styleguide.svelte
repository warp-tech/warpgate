<script lang="ts">
    /**
     * Dev-only token reference. Registered behind `import.meta.env.DEV` in
     * gateway/Root.svelte, so the chunk is never emitted in a production build.
     *
     * Deliberately styled from tokens alone — no Bootstrap, no sveltestrap.
     * If something here looks wrong, the token layer is wrong, which is the
     * whole point of having this page before any primitives exist.
     */
    import { onMount } from 'svelte'
    import { currentTheme, setCurrentTheme } from 'theme'
    import { contrast, grade, resolveToken } from './contrast'

    const SURFACES = [
        ['--wg-surface-container-lowest', 'Recessed — terminals, log dumps'],
        ['--wg-surface', 'Canvas — the root substrate'],
        ['--wg-surface-container-low', 'Zebra stripe'],
        ['--wg-surface-container', 'Panels, cards, table headers, drawers'],
        ['--wg-surface-container-high', 'Row hover'],
        ['--wg-surface-container-highest', 'Row selected'],
        ['--wg-surface-bright', 'Brightest tonal step'],
    ] as const

    const INK = [
        ['--wg-text', 'Headlines, identifiers, active parameters'],
        ['--wg-text-muted', 'Column labels, metadata, metrics'],
        ['--wg-text-subtle', 'Inactive timestamps, units, protocol markers'],
    ] as const

    const BORDERS = [
        [
            '--wg-border',
            'Decorative dividers only — row rules, cell hairlines',
            3,
        ],
        [
            '--wg-border-strong',
            'Interactive component boundaries — inputs, buttons',
            3,
        ],
    ] as const

    const ROLES = [
        ['primary', 'Action targets, selection, focus'],
        ['secondary', 'Live connections, warning tier'],
        ['tertiary', 'Healthy, verified, nominal'],
        ['error', 'Blocked, revoked, failed, destructive'],
    ] as const

    const TYPE_ROLES = [
        ['--wg-text-headline-lg', 'headline-lg', 'Sessions'],
        ['--wg-text-headline-lg-mobile', 'headline-lg-mobile', 'Sessions'],
        ['--wg-text-headline-md', 'headline-md', 'Currently blocked'],
        [
            '--wg-text-body-lg',
            'body-lg',
            'Destinations for users to connect to',
        ],
        [
            '--wg-text-body-md',
            'body-md',
            'Destinations for users to connect to',
        ],
        ['--wg-text-label-md', 'label-md', 'Source IP'],
        ['--wg-text-label-sm', 'label-sm', 'Ended 3 minutes ago'],
        ['--wg-text-code-md', 'code-md', 'prod-bastion-01.eu-west-1'],
        [
            '--wg-text-code-sm',
            'code-sm',
            'SHA256:qF3nP8xK2vL9mR4tW7yB1cE6hJ0dG5sA',
        ],
    ] as const

    const SPACING = ['xs', 'sm', 'md', 'lg', 'xl', '2xl', '3xl'] as const

    const RADII = [
        ['--wg-radius-sm', 'sm'],
        ['--wg-radius', 'DEFAULT — badges, panels'],
        ['--wg-radius-md', 'md — buttons, inputs'],
        ['--wg-radius-lg', 'lg'],
        ['--wg-radius-xl', 'xl'],
        ['--wg-radius-full', 'full'],
    ] as const

    // DESIGN.md's state matrix: geometry + label + colour, never colour alone.
    const STATES = [
        ['live', 'Live', '--wg-state-live'],
        ['online', 'Online', '--wg-state-online'],
        ['blocked', 'Blocked', '--wg-state-blocked'],
        ['ended', 'Ended 12:04:31', '--wg-state-ended'],
        ['failed', 'Failed', '--wg-state-failed'],
    ] as const

    let resolved: Record<string, string> = $state({})

    // Recomputed whenever the theme changes so the audit tracks what is
    // actually painted, not what was painted on mount.
    function readTokens() {
        const names = [
            ...SURFACES.map(s => s[0]),
            ...INK.map(s => s[0]),
            ...BORDERS.map(s => s[0]),
            ...ROLES.flatMap(r => [
                `--wg-${r[0]}`,
                `--wg-on-${r[0]}`,
                `--wg-${r[0]}-container`,
                `--wg-on-${r[0]}-container`,
            ]),
        ]
        const next: Record<string, string> = {}
        for (const n of names) {
            next[n] = resolveToken(n)
        }
        resolved = next
    }

    onMount(() => {
        readTokens()
        const observer = new MutationObserver(readTokens)
        observer.observe(document.documentElement, {
            attributes: true,
            attributeFilter: ['data-wg-theme'],
        })
        const mq = window.matchMedia('(prefers-color-scheme: dark)')
        mq.addEventListener('change', readTokens)
        return () => {
            observer.disconnect()
            mq.removeEventListener('change', readTokens)
        }
    })

    function ratio(fg: string, bg: string): string {
        const r = contrast(resolved[fg] ?? '', resolved[bg] ?? '')
        return r === null ? '—' : r.toFixed(2)
    }

    function ratioGrade(fg: string, bg: string): string {
        return grade(contrast(resolved[fg] ?? '', resolved[bg] ?? ''))
    }

    const THEMES = ['auto', 'dark', 'light'] as const
</script>

<svelte:head>
    <title>Warpgate styleguide</title>
</svelte:head>

<div class="sg">
    <header class="sg-header">
        <div>
            <h1>Warpgate design tokens</h1>
            <p class="sg-sub">
                Phase 1 — token layer. Primitives arrive in Phase 2. Contrast
                ratios are measured live from the painted values.
            </p>
        </div>
        <fieldset class="sg-theme">
            <legend class="sg-visually-hidden">Theme</legend>
            {#each THEMES as t (t)}
                <button
                    type="button"
                    class="sg-theme-btn"
                    aria-pressed={$currentTheme === t}
                    onclick={() => setCurrentTheme(t)}
                >
                    {t}
                </button>
            {/each}
        </fieldset>
    </header>

    <!-- ── Surfaces ─────────────────────────────────────────────── -->
    <section>
        <h2>Surfaces</h2>
        <p class="sg-note">
            Depth is tonal. No drop shadows, no blur, no gradients — the one
            sanctioned shadow is the overlay plane at the bottom of this page.
        </p>
        <div class="sg-surfaces">
            {#each SURFACES as [token, use] (token)}
                <div class="sg-surface-row">
                    <div class="sg-chip" style="background: var({token})"></div>
                    <code class="sg-token">{token}</code>
                    <code class="sg-value">{resolved[token] ?? ''}</code>
                    <span class="sg-use">{use}</span>
                    <span class="sg-ratio">
                        {ratio('--wg-on-surface', token)}
                        <span class="sg-grade"
                            >{ratioGrade('--wg-on-surface', token)}</span
                        >
                    </span>
                </div>
            {/each}
        </div>
        <p class="sg-note">
            Ratio column is <code>--wg-on-surface</code> against that surface.
        </p>
    </section>

    <!-- ── Ink ──────────────────────────────────────────────────── -->
    <section>
        <h2>Ink</h2>
        <div class="sg-surfaces">
            {#each INK as [token, use] (token)}
                <div class="sg-surface-row">
                    <div class="sg-chip" style="background: var({token})"></div>
                    <code class="sg-token">{token}</code>
                    <code class="sg-value">{resolved[token] ?? ''}</code>
                    <span class="sg-use">{use}</span>
                    <span class="sg-ratio">
                        {ratio(token, '--wg-surface')}
                        <span class="sg-grade"
                            >{ratioGrade(token, '--wg-surface')}</span
                        >
                    </span>
                </div>
            {/each}
        </div>
        <p class="sg-note">
            All three ink tiers are text and are held to 1.4.3's 4.5:1 on every
            substrate, including the hover row.
        </p>
    </section>

    <!-- ── Borders ──────────────────────────────────────────────── -->
    <section>
        <h2>Borders</h2>
        <p class="sg-note">
            Two tiers, and the split is a requirement rather than taste.
            Decorative dividers are exempt from contrast rules; anything that
            tells an operator where a control begins is not, and must clear
            1.4.11's 3:1. Ratios below are against the canvas.
        </p>
        <div class="sg-surfaces">
            {#each BORDERS as [token, use, threshold] (token)}
                {@const r = contrast(resolved[token] ?? '', resolved['--wg-surface'] ?? '')}
                <div class="sg-surface-row">
                    <div class="sg-chip" style="background: var({token})"></div>
                    <code class="sg-token">{token}</code>
                    <code class="sg-value">{resolved[token] ?? ''}</code>
                    <span class="sg-use">{use}</span>
                    <span class="sg-ratio">
                        {r === null ? '—' : r.toFixed(2)}
                        <span class="sg-grade">
                            {token === '--wg-border'
                                ? 'exempt'
                                : (r ?? 0) >= threshold
                                  ? 'passes 3:1'
                                  : 'FAILS 3:1'}
                        </span>
                    </span>
                </div>
            {/each}
        </div>
        <div class="sg-border-demo">
            <div class="sg-border-demo-box">
                Divider tier
                <div class="sg-divider"></div>
                <div class="sg-divider"></div>
            </div>
            <div class="sg-border-demo-box sg-strong">Component tier</div>
        </div>
    </section>

    <!-- ── Roles ────────────────────────────────────────────────── -->
    <section>
        <h2>Roles</h2>
        <p class="sg-note">
            Each role is audited on all three substrates an element can land on.
            The highest column is the row-hover tone, which is exactly when an
            operator is pointing at the row.
        </p>
        {#each ROLES as [role, use] (role)}
            <div class="sg-role">
                <div class="sg-role-head">
                    <code class="sg-token">--wg-{role}</code>
                    <span class="sg-use">{use}</span>
                </div>
                <div class="sg-role-grid">
                    <div class="sg-pair" style="background: var(--wg-surface)">
                        <span style="color: var(--wg-{role})">
                            On canvas — {ratio(`--wg-${role}`, '--wg-surface')}
                            {ratioGrade(`--wg-${role}`, '--wg-surface')}
                        </span>
                    </div>
                    <div
                        class="sg-pair"
                        style="background: var(--wg-surface-container)"
                    >
                        <span style="color: var(--wg-{role})">
                            On container —
                            {ratio(`--wg-${role}`, '--wg-surface-container')}
                            {ratioGrade(`--wg-${role}`, '--wg-surface-container')}
                        </span>
                    </div>
                    <div
                        class="sg-pair"
                        style="background: var(--wg-surface-container-highest)"
                    >
                        <span style="color: var(--wg-{role})">
                            On highest —
                            {ratio(`--wg-${role}`, '--wg-surface-container-highest')}
                            {ratioGrade(`--wg-${role}`, '--wg-surface-container-highest')}
                        </span>
                    </div>
                    <div
                        class="sg-pair"
                        style="background: var(--wg-{role}); color: var(--wg-on-{role})"
                    >
                        on-{role}
                        — {ratio(`--wg-on-${role}`, `--wg-${role}`)}
                        {ratioGrade(`--wg-on-${role}`, `--wg-${role}`)}
                    </div>
                    <div
                        class="sg-pair"
                        style="background: var(--wg-{role}-container); color: var(--wg-on-{role}-container)"
                    >
                        on-{role}-container —
                        {ratio(`--wg-on-${role}-container`, `--wg-${role}-container`)}
                        {ratioGrade(`--wg-on-${role}-container`, `--wg-${role}-container`)}
                    </div>
                </div>
            </div>
        {/each}
    </section>

    <!-- ── State markers ────────────────────────────────────────── -->
    <section>
        <h2>State — geometry + label + colour</h2>
        <p class="sg-note">
            Colour never carries state alone. These are the token-level shapes
            DESIGN.md specifies; the <code>StatusMarker</code> component that
            wraps them lands in Phase 2.
        </p>
        <div class="sg-states">
            {#each STATES as [kind, label, token] (kind)}
                <span class="sg-state">
                    <span
                        class="sg-marker sg-marker-{kind}"
                        style="--marker: var({token})"
                        aria-hidden="true"
                    ></span>
                    {label}
                </span>
            {/each}
        </div>
    </section>

    <!-- ── Type ─────────────────────────────────────────────────── -->
    <section>
        <h2>Type scale</h2>
        <p class="sg-note">
            Sentence case throughout. All-caps is prohibited by the system.
            Numeric readouts use tabular figures.
        </p>
        <div class="sg-type">
            {#each TYPE_ROLES as [token, name, sample] (token)}
                <div class="sg-type-row">
                    <code class="sg-token">{name}</code>
                    <div style="font: var({token})" class="wg-tabular">
                        {sample}
                    </div>
                </div>
            {/each}
        </div>
    </section>

    <!-- ── Mono comparison ──────────────────────────────────────── -->
    <section>
        <h2>Mono candidates at 13px</h2>
        <p class="sg-note">
            The question is letterform harmony with IBM Plex Sans in a real
            table row, not bundle size. Caskaydia Cove already ships for
            xterm.js; IBM Plex Mono costs about 14 KB more.
        </p>
        <table class="sg-table">
            <thead>
                <tr>
                    <th scope="col">Face</th>
                    <th scope="col">User</th>
                    <th scope="col">Target</th>
                    <th scope="col">Fingerprint</th>
                </tr>
            </thead>
            <tbody>
                <tr>
                    <td class="sg-face-label">IBM Plex Mono</td>
                    <td>Marta Kowalski</td>
                    <td style="font-family: var(--wg-font-mono)">
                        prod-bastion-01.eu-west-1:22
                    </td>
                    <td style="font-family: var(--wg-font-mono)">
                        SHA256:qF3nP8xK2vL9mR4tW7yB1cE6hJ0dG5sA
                    </td>
                </tr>
                <tr>
                    <td class="sg-face-label">Caskaydia Cove</td>
                    <td>Marta Kowalski</td>
                    <td style="font-family: 'monospace-fallback', monospace">
                        prod-bastion-01.eu-west-1:22
                    </td>
                    <td style="font-family: 'monospace-fallback', monospace">
                        SHA256:qF3nP8xK2vL9mR4tW7yB1cE6hJ0dG5sA
                    </td>
                </tr>
            </tbody>
        </table>
        <p class="sg-note">
            Digits and the <code>0/O</code>, <code>1/l/I</code> pairs are what
            matter — these columns are read under pressure.
        </p>
        <div class="sg-mono-compare">
            <div>
                <code class="sg-token">IBM Plex Mono</code>
                <div style="font: var(--wg-text-code-md)">
                    0O1lI 8B 5S 2Z 6G &amp; 0123456789
                </div>
            </div>
            <div>
                <code class="sg-token">Caskaydia Cove</code>
                <div
                    style="font-family: 'monospace-fallback', monospace; font-size: 0.8125rem; line-height: 1.125rem"
                >
                    0O1lI 8B 5S 2Z 6G &amp; 0123456789
                </div>
            </div>
        </div>
    </section>

    <!-- ── Spacing ──────────────────────────────────────────────── -->
    <section>
        <h2>Spacing — 8px grid, 4px sub-grid</h2>
        <div class="sg-spacing">
            {#each SPACING as s (s)}
                <div class="sg-space-row">
                    <code class="sg-token">--wg-space-{s}</code>
                    <div
                        class="sg-space-bar"
                        style="width: var(--wg-space-{s})"
                    ></div>
                </div>
            {/each}
        </div>
    </section>

    <!-- ── Radius ───────────────────────────────────────────────── -->
    <section>
        <h2>Radius</h2>
        <p class="sg-note">
            Tables, data rows and sunken code boxes are square. Separation there
            comes from borders and zebra striping, not corners.
        </p>
        <div class="sg-radii">
            {#each RADII as [token, label] (token)}
                <div class="sg-radius">
                    <div
                        class="sg-radius-box"
                        style="border-radius: var({token})"
                    ></div>
                    <code class="sg-token">{label}</code>
                </div>
            {/each}
        </div>
    </section>

    <!-- ── Focus ────────────────────────────────────────────────── -->
    <section>
        <h2>Focus</h2>
        <p class="sg-note">
            Tab through these. Every interactive element in the product needs a
            visible ring, an accessible name and keyboard operability.
        </p>
        <div class="sg-focus">
            <button type="button" class="sg-demo-btn">Button</button>
            <a class="sg-demo-link" href="#focus-demo">
                Link to the focus demo
            </a>
            <input
                class="sg-demo-input"
                aria-label="Demo input"
                placeholder="Input"
            >
        </div>
    </section>

    <!-- ── Elevation ────────────────────────────────────────────── -->
    <section>
        <h2>Elevation</h2>
        <div class="sg-elevation">
            <div class="sg-overlay">
                Overlay plane — the only sanctioned shadow
                <code class="sg-value">--wg-shadow-overlay</code>
            </div>
        </div>
    </section>
</div>

<style>
    .sg {
        max-width: var(--wg-content-max);
        margin: 0 auto;
        padding: var(--wg-content-padding);
        background: var(--wg-surface);
        color: var(--wg-text);
        font: var(--wg-text-body-md);
        min-height: 100vh;
    }

    .sg-header {
        display: flex;
        flex-wrap: wrap;
        gap: var(--wg-space-lg);
        align-items: flex-start;
        justify-content: space-between;
        padding-bottom: var(--wg-space-lg);
        border-bottom: var(--wg-border-width) solid var(--wg-border);
        margin-bottom: var(--wg-space-2xl);
    }

    h1 {
        font: var(--wg-text-headline-lg);
        margin: 0 0 var(--wg-space-xs);
    }

    h2 {
        font: var(--wg-text-headline-md);
        margin: 0 0 var(--wg-space-sm);
    }

    section {
        margin-bottom: var(--wg-space-3xl);
    }

    .sg-sub,
    .sg-note {
        color: var(--wg-text-muted);
        font: var(--wg-text-body-md);
        margin: 0 0 var(--wg-space-md);
        max-width: 68ch;
    }

    code {
        font: var(--wg-text-code-sm);
    }

    .sg-token {
        color: var(--wg-text-muted);
    }

    .sg-value {
        color: var(--wg-text-subtle);
    }

    .sg-visually-hidden {
        position: absolute;
        width: 1px;
        height: 1px;
        padding: 0;
        margin: -1px;
        overflow: hidden;
        clip-path: inset(50%);
        white-space: nowrap;
        border: 0;
    }

    /* Theme switcher */
    .sg-theme {
        display: flex;
        gap: 0;
        padding: 0;
        margin: 0;
        min-inline-size: 0; /* fieldset defaults to min-content */
        border: var(--wg-border-width) solid var(--wg-border-strong);
        border-radius: var(--wg-radius-control);
        overflow: hidden;
    }

    .sg-theme-btn {
        font: var(--wg-text-label-md);
        background: var(--wg-surface-container);
        color: var(--wg-text-muted);
        border: 0;
        padding: 0 var(--wg-control-padding-x);
        height: var(--wg-control-height);
        cursor: pointer;
    }

    .sg-theme-btn[aria-pressed="true"] {
        background: var(--wg-primary);
        color: var(--wg-on-primary);
    }

    .sg-theme-btn:focus-visible {
        outline: var(--wg-focus-ring);
        outline-offset: calc(-1 * var(--wg-focus-ring-width));
    }

    /* Surface + ink tables */
    .sg-surfaces {
        border: var(--wg-border-width) solid var(--wg-border);
        border-radius: var(--wg-radius-panel);
        overflow: hidden;
    }

    .sg-surface-row {
        display: grid;
        grid-template-columns: 2.5rem 15rem 6rem 1fr auto;
        gap: var(--wg-space-md);
        align-items: center;
        padding: var(--wg-space-sm) var(--wg-space-md);
        border-bottom: var(--wg-border-width) solid var(--wg-border);
    }

    .sg-surface-row:last-child {
        border-bottom: 0;
    }

    .sg-chip {
        width: 2.5rem;
        height: 1.5rem;
        border: var(--wg-border-width) solid var(--wg-border);
        border-radius: var(--wg-radius-sm);
    }

    .sg-use {
        color: var(--wg-text-muted);
    }

    .sg-ratio {
        font: var(--wg-text-code-sm);
        font-variant-numeric: tabular-nums;
        white-space: nowrap;
    }

    .sg-grade {
        color: var(--wg-text-muted);
        margin-left: var(--wg-space-xs);
    }

    /* Roles */
    .sg-role {
        margin-bottom: var(--wg-space-lg);
    }

    .sg-role-head {
        display: flex;
        gap: var(--wg-space-md);
        align-items: baseline;
        margin-bottom: var(--wg-space-xs);
    }

    .sg-role-grid {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(13rem, 1fr));
        gap: var(--wg-space-xs);
    }

    .sg-pair {
        padding: var(--wg-space-sm) var(--wg-space-md);
        border: var(--wg-border-width) solid var(--wg-border);
        border-radius: var(--wg-radius-panel);
        font: var(--wg-text-label-md);
        font-variant-numeric: tabular-nums;
    }

    /* State markers */
    .sg-states {
        display: flex;
        flex-wrap: wrap;
        gap: var(--wg-space-lg);
    }

    .sg-state {
        display: inline-flex;
        align-items: center;
        gap: var(--wg-space-xs);
        font: var(--wg-text-label-sm);
        height: var(--wg-badge-height);
        padding: 0 var(--wg-badge-padding-x);
        border: var(--wg-border-width) solid var(--wg-border);
        border-radius: var(--wg-radius-badge);
        background: var(--wg-surface-container);
    }

    .sg-marker {
        flex: none;
        width: var(--wg-marker-size);
        height: var(--wg-marker-size);
    }

    /* Filled circle, pulsing */
    .sg-marker-live {
        background: var(--marker);
        border-radius: var(--wg-radius-full);
        animation: sg-pulse 2s ease-in-out infinite;
    }

    /* Hollow ring */
    .sg-marker-online {
        width: 7px;
        height: 7px;
        border: 1.5px solid var(--marker);
        border-radius: var(--wg-radius-full);
    }

    /* Solid square */
    .sg-marker-blocked {
        background: var(--marker);
    }

    /* Solid circle, inert */
    .sg-marker-ended {
        background: var(--marker);
        border-radius: var(--wg-radius-full);
    }

    /* Upward triangle */
    .sg-marker-failed {
        width: 0;
        height: 0;
        background: none;
        border-left: 3.5px solid transparent;
        border-right: 3.5px solid transparent;
        border-bottom: 6px solid var(--marker);
    }

    @keyframes sg-pulse {
        0%,
        100% {
            opacity: 1;
        }
        50% {
            opacity: 0.4;
        }
    }

    @media (prefers-reduced-motion: reduce) {
        .sg-marker-live {
            animation: none;
        }
    }

    /* Type */
    .sg-type-row {
        display: grid;
        grid-template-columns: 14rem 1fr;
        gap: var(--wg-space-md);
        align-items: baseline;
        padding: var(--wg-space-sm) 0;
        border-bottom: var(--wg-border-width) solid var(--wg-border);
    }

    /* Mono comparison */
    .sg-table {
        width: 100%;
        border-collapse: collapse;
        font: var(--wg-text-body-md);
    }

    .sg-table th {
        text-align: left;
        font: var(--wg-text-label-md);
        color: var(--wg-text-muted);
        background: var(--wg-surface-container);
        padding: var(--wg-space-sm) var(--wg-space-md);
        border-bottom: var(--wg-border-width) solid var(--wg-border);
    }

    .sg-table td {
        padding: var(--wg-space-sm) var(--wg-space-md);
        border-bottom: var(--wg-border-width) solid var(--wg-border);
        height: var(--wg-row-height);
        font-variant-numeric: tabular-nums;
    }

    .sg-face-label {
        color: var(--wg-text-muted);
        font: var(--wg-text-label-md);
    }

    .sg-mono-compare {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(18rem, 1fr));
        gap: var(--wg-space-lg);
        margin-top: var(--wg-space-md);
        padding: var(--wg-space-md);
        background: var(--wg-surface-sunken);
        border: var(--wg-border-width) solid var(--wg-border);
    }

    /* Spacing */
    .sg-space-row {
        display: grid;
        grid-template-columns: 12rem 1fr;
        gap: var(--wg-space-md);
        align-items: center;
        padding: var(--wg-space-xs) 0;
    }

    .sg-space-bar {
        height: 1rem;
        background: var(--wg-primary);
        border-radius: var(--wg-radius-sm);
    }

    /* Radius */
    .sg-radii {
        display: flex;
        flex-wrap: wrap;
        gap: var(--wg-space-lg);
    }

    .sg-radius {
        display: flex;
        flex-direction: column;
        gap: var(--wg-space-xs);
        align-items: center;
    }

    .sg-radius-box {
        width: 4rem;
        height: 4rem;
        background: var(--wg-surface-container-high);
        border: var(--wg-border-width) solid var(--wg-border-strong);
    }

    /* Focus demos */
    .sg-focus {
        display: flex;
        flex-wrap: wrap;
        gap: var(--wg-space-lg);
        align-items: center;
    }

    /* border-strong, not border: these are interactive component boundaries */
    .sg-demo-btn,
    .sg-demo-input {
        height: var(--wg-control-height);
        padding: 0 var(--wg-control-padding-x);
        border-radius: var(--wg-radius-control);
        border: var(--wg-border-width) solid var(--wg-border-strong);
        font: var(--wg-text-label-md);
    }

    .sg-border-demo {
        display: flex;
        flex-wrap: wrap;
        gap: var(--wg-space-lg);
        margin-top: var(--wg-space-md);
    }

    .sg-border-demo-box {
        min-width: 12rem;
        padding: var(--wg-space-md);
        background: var(--wg-surface-container);
        border: var(--wg-border-width) solid var(--wg-border);
        border-radius: var(--wg-radius-panel);
        font: var(--wg-text-label-md);
    }

    .sg-border-demo-box.sg-strong {
        border-color: var(--wg-border-strong);
    }

    .sg-divider {
        height: var(--wg-border-width);
        background: var(--wg-border);
        margin-top: var(--wg-space-sm);
    }

    .sg-demo-btn {
        background: var(--wg-surface-container);
        color: var(--wg-text);
        cursor: pointer;
    }

    .sg-demo-input {
        background: var(--wg-surface-sunken);
        color: var(--wg-text);
    }

    .sg-demo-link {
        color: var(--wg-primary);
    }

    .sg-demo-btn:focus-visible,
    .sg-demo-input:focus-visible,
    .sg-demo-link:focus-visible {
        outline: var(--wg-focus-ring);
        outline-offset: var(--wg-focus-ring-offset);
    }

    /* Elevation */
    .sg-elevation {
        padding: var(--wg-space-2xl);
        background: var(--wg-surface-container-low);
        border-radius: var(--wg-radius-panel);
    }

    .sg-overlay {
        display: flex;
        flex-direction: column;
        gap: var(--wg-space-xs);
        max-width: 24rem;
        padding: var(--wg-space-lg);
        background: var(--wg-surface-container);
        border: var(--wg-border-width) solid var(--wg-border);
        border-radius: var(--wg-radius-panel);
        box-shadow: var(--wg-shadow-overlay);
    }

    @media (max-width: 720px) {
        .sg-surface-row,
        .sg-type-row,
        .sg-space-row {
            grid-template-columns: 1fr;
        }
    }
</style>
