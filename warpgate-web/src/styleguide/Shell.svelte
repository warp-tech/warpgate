<script lang="ts">
    import {
        ADMIN_PERMISSIONS,
        type AdminPermissionKey,
        emptyPermissions,
    } from 'admin/lib/store'
    /**
     * Phase 3 styleguide: the shell pieces, driven against a fake permission
     * set so the gating can be demonstrated rather than described.
     */
    import type { AdminPermissions } from 'gateway/lib/api'
    import {
        CREATE_ACTIONS,
        NAVIGATION_ACTIONS,
        permittedActions,
    } from 'shell/actions'
    import Breadcrumbs from 'shell/Breadcrumbs.svelte'
    import CommandPalette, {
        type PaletteEntity,
    } from 'shell/CommandPalette.svelte'
    import { fuzzyRank } from 'shell/fuzzy'
    import { NAV_SECTIONS, permittedSections } from 'shell/navItems'
    import Sidebar from 'shell/Sidebar.svelte'
    import TopBar from 'shell/TopBar.svelte'
    import Button from 'ui/Button.svelte'
    import SegmentedControl from 'ui/SegmentedControl.svelte'

    type Persona = 'full' | 'operator' | 'auditor'

    // Three real shapes of operator, so the gating is visible rather than
    // asserted. "Operator" can see and terminate sessions but cannot touch
    // configuration; "auditor" can only read.
    // Keys come from ADMIN_PERMISSIONS rather than string literals, so a
    // renamed permission breaks this at compile time instead of silently
    // producing a persona that grants nothing.
    function permissionsFor(persona: Persona): AdminPermissions {
        const base = emptyPermissions()
        const on = (...keys: AdminPermissionKey[]) => {
            for (const k of keys) {
                base[k] = true
            }
        }

        if (persona === 'full') {
            on(...ADMIN_PERMISSIONS.map(p => p.key))
        } else if (persona === 'operator') {
            on(
                'sessionsView',
                'sessionsTerminate',
                'approveSessions',
                'recordingsView',
                'targetsEdit',
                'ticketsCreate',
            )
        } else {
            on('sessionsView', 'recordingsView')
        }
        return base
    }

    let persona: Persona = $state('full')
    let collapsed = $state(false)
    let paletteOpen = $state(false)
    let path = $state('/config/targets')

    const permissions = $derived(permissionsFor(persona))
    const sections = $derived(permittedSections(NAV_SECTIONS, permissions))
    const actions = $derived(
        permittedActions(
            [...NAVIGATION_ACTIONS, ...CREATE_ACTIONS],
            permissions,
        ),
    )

    const DEMO_ENTITIES: PaletteEntity[] = [
        {
            id: 't1',
            label: 'prod-bastion-01',
            detail: 'Primary production bastion',
            group: 'Targets',
            href: '#/config/targets/t1',
            mono: true,
        },
        {
            id: 't2',
            label: 'prod-bastion-02',
            detail: 'Failover bastion',
            group: 'Targets',
            href: '#/config/targets/t2',
            mono: true,
        },
        {
            id: 't3',
            label: 'analytics-warehouse-ro',
            detail: 'Read-only analytics',
            group: 'Targets',
            href: '#/config/targets/t3',
            mono: true,
        },
        {
            id: 'u1',
            label: 'marta.kowalski',
            detail: 'Platform engineering',
            group: 'Users',
            href: '#/config/users/u1',
            mono: true,
        },
        {
            id: 'u2',
            label: 'svc-backup',
            detail: 'Service account',
            group: 'Users',
            href: '#/config/users/u2',
            mono: true,
        },
        {
            id: 's1',
            label: 'j.okafor',
            detail: 'core-redis · SSH · 10.2.9.14',
            group: 'Sessions (live)',
            href: '#/status/sessions/s1',
            mono: true,
        },
    ]

    // A live demonstration of the ranking rules, so the scoring is inspectable
    // rather than a claim in a comment.
    let probe = $state('pb')
    const probeResults = $derived(
        fuzzyRank(probe, DEMO_ENTITIES, e => [e.label, e.detail ?? ''], 6),
    )

    const CRUMBS = [
        { label: 'Targets', href: '#/config/targets' },
        { label: 'prod-bastion-01', mono: true },
    ]
</script>

<section>
    <h2>Shell</h2>
    <p class="note">
        Sidebar, top bar, breadcrumbs and command palette. Not wired into the
        app — Phase 4 mounts it behind <code>VITE_NEW_UI</code>.
    </p>

    <p class="label">Permission persona — everything below re-gates live</p>
    <SegmentedControl
        label="Persona"
        labelHidden={false}
        bind:value={persona}
        segments={[
            { value: 'full', label: 'Full admin' },
            { value: 'operator', label: 'Operator' },
            { value: 'auditor', label: 'Auditor' },
        ]}
    />
    <p class="note" style="margin-top: var(--wg-space-sm)">
        The auditor sees five nav items and six actions; the full admin sees
        every one. Items are <strong>absent, not disabled</strong> — a
        greyed-out "Manage admin roles" still tells you the capability exists.
    </p>
</section>

<section>
    <h2>Sidebar</h2>
    <p class="note">
        240px expanded, 56px rail collapsed. In the rail every item is
        icon-only, so the label is <em>clipped rather than removed</em> — the
        link keeps its accessible name without a parallel
        <code>aria-label</code>
        that could drift from the visible text. Section headings become a 1px
        rule so the grouping survives.
        <strong>Tab through the collapsed rail</strong>
        and the names are still announced.
    </p>
    <div class="shell-demo">
        <Sidebar {sections} {path} bind:collapsed />
        <div class="shell-demo-body">
            <p class="note" style="margin: 0">
                Active item is derived by longest-prefix match, so
                <code>/config/targets/abc</code>
                highlights Targets and
                <code>/config/target-groups</code>
                is not captured by it.
            </p>
            <SegmentedControl
                label="Simulated route"
                labelHidden={false}
                bind:value={path}
                segments={[
                    { value: '/status/sessions', label: 'Sessions' },
                    { value: '/config/targets', label: 'Targets' },
                    { value: '/config/targets/abc', label: 'Targets/abc' },
                    { value: '/config/target-groups', label: 'Groups' },
                ]}
            />
            <Button size="compact" onclick={() => (collapsed = !collapsed)}>
                {collapsed ? 'Expand' : 'Collapse'}
                the rail
            </Button>
        </div>
    </div>
</section>

<section>
    <h2>Top bar and breadcrumbs</h2>
    <p class="note">
        56px with a bottom hairline. The last crumb is the current page and is
        never a link — a link to where you already are is a keyboard stop that
        does nothing. Separators are pseudo-elements, so a screen reader reads
        "Targets, prod-bastion-01" rather than "Targets slash prod-bastion-01".
    </p>
    <div class="shell-topbar-demo">
        <TopBar crumbs={CRUMBS} onopenPalette={() => (paletteOpen = true)} />
    </div>
    <p class="label">Breadcrumbs alone, at depth</p>
    <Breadcrumbs
        crumbs={[
            { label: 'Users', href: '#/config/users' },
            { label: 'marta.kowalski', href: '#/config/users/u1', mono: true },
            { label: 'Credentials' },
        ]}
    />
</section>

<section>
    <h2>Command palette</h2>
    <p class="note">
        <strong>Press Cmd/Ctrl+K</strong>
        anywhere on this page, or use the button above. ARIA combobox: the input
        keeps focus for the whole interaction and announces the active row
        through
        <code>aria-activedescendant</code>, so arrow keys move the highlight
        without moving DOM focus — which is what lets you keep typing to narrow
        while navigating.
    </p>
    <p class="note">
        Actions are filtered by the persona above. Try
        <code>admin roles</code>
        as an auditor: it is not there. As a full admin it is, marked
        <em>Confirms</em>
        — dangerous actions do not fire on Enter, they route through a
        typed-name confirmation, because one Enter from a fuzzy match is the
        fastest mis-click path in the product.
    </p>
    <Button onclick={() => (paletteOpen = true)}>Open the palette</Button>

    <p class="label">
        Fuzzy ranking, live — type here to see how the matcher scores
    </p>
    <div class="probe">
        <input
            bind:value={probe}
            aria-label="Fuzzy match probe"
            placeholder="pb"
            spellcheck="false"
        >
        <ol>
            {#each probeResults as r (r.item.id)}
                <li>
                    <span class="probe-label">{r.item.label}</span>
                    <span class="probe-score">{r.score.toFixed(1)}</span>
                </li>
            {:else}
                <li class="probe-empty">no matches</li>
            {/each}
        </ol>
    </div>
    <p class="note">
        <code>pb</code>
        puts <code>prod-bastion-01</code> on top because both characters land on
        word boundaries. <code>bast</code> prefers consecutive runs. A prefix
        match on the whole string outranks everything, and shorter haystacks win
        ties.
    </p>
</section>

<CommandPalette
    bind:open={paletteOpen}
    {actions}
    entities={DEMO_ENTITIES}
    onnavigate={href => {
        // Swallowed in the styleguide — navigating away would lose the page.
        console.log('palette navigate:', href)
    }}
/>

<style>
    section {
        margin-bottom: var(--wg-space-3xl);
    }

    h2 {
        font: var(--wg-text-headline-md);
        margin: 0 0 var(--wg-space-sm);
    }

    .note {
        color: var(--wg-text-muted);
        font: var(--wg-text-body-md);
        margin: 0 0 var(--wg-space-md);
        max-width: 72ch;
    }

    .label {
        margin: var(--wg-space-lg) 0 var(--wg-space-sm);
        font: var(--wg-text-label-md);
        color: var(--wg-text-subtle);
    }

    code {
        font: var(--wg-text-code-sm);
        color: var(--wg-text);
    }

    .shell-demo {
        display: flex;
        gap: var(--wg-space-lg);
        height: 26rem;
        border: var(--wg-border-width) solid var(--wg-border);
        border-radius: var(--wg-radius-panel);
        overflow: hidden;
    }

    .shell-demo-body {
        display: flex;
        flex-direction: column;
        align-items: flex-start;
        gap: var(--wg-space-md);
        padding: var(--wg-space-lg) var(--wg-space-lg) var(--wg-space-lg) 0;
    }

    .shell-topbar-demo {
        border: var(--wg-border-width) solid var(--wg-border);
        border-radius: var(--wg-radius-panel);
        overflow: hidden;
    }

    .probe {
        max-width: 32rem;
    }

    .probe input {
        width: 100%;
        height: var(--wg-control-height);
        padding: 0 var(--wg-space-sm);
        background: var(--wg-surface-sunken);
        border: var(--wg-border-width) solid var(--wg-border-strong);
        border-radius: var(--wg-radius-control);
        color: var(--wg-text);
        font: var(--wg-text-code-md);
    }

    .probe input:focus-visible {
        outline: var(--wg-focus-ring);
        outline-offset: var(--wg-focus-ring-offset);
        border-color: var(--wg-primary);
    }

    .probe ol {
        list-style: none;
        margin: var(--wg-space-sm) 0 0;
        padding: 0;
        border: var(--wg-border-width) solid var(--wg-border);
        border-radius: var(--wg-radius-panel);
        overflow: hidden;
    }

    .probe li {
        display: flex;
        justify-content: space-between;
        gap: var(--wg-space-md);
        padding: var(--wg-space-xs) var(--wg-space-md);
        border-bottom: var(--wg-border-width) solid var(--wg-border);
        font: var(--wg-text-code-sm);
    }

    .probe li:last-child {
        border-bottom: 0;
    }

    .probe-score {
        color: var(--wg-text-muted);
        font-variant-numeric: tabular-nums;
    }

    .probe-empty {
        color: var(--wg-text-subtle);
    }
</style>
