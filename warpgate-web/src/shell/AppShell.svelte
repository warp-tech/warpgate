<script lang="ts">
    import type { AdminPermissions } from 'gateway/lib/api'
    /**
     * Admin shell: sidebar + top bar + content canvas + command palette.
     *
     * Mounted by admin/AppNew.svelte, which wraps every admin route in it.
     *
     * The content canvas is capped at 1600px and padded 24px, per DESIGN.md.
     */
    import type { Snippet } from 'svelte'
    import ToastHost from 'ui/ToastHost.svelte'
    import {
        CREATE_ACTIONS,
        NAVIGATION_ACTIONS,
        permittedActions,
    } from './actions'
    import type { Crumb } from './Breadcrumbs.svelte'
    import CommandPalette, { type PaletteEntity } from './CommandPalette.svelte'
    import { loadPaletteEntities } from './entities'
    import { NAV_SECTIONS, permittedSections } from './navItems'
    import Sidebar from './Sidebar.svelte'
    import TopBar from './TopBar.svelte'

    interface Props {
        permissions: AdminPermissions
        /** Current SPA path, e.g. "/config/targets/abc". */
        path: string
        crumbs?: Crumb[]
        /** Injected for the styleguide; the app omits it and fetches for real. */
        loadEntities?: typeof loadPaletteEntities
        brand?: Snippet
        trailing?: Snippet
        children?: Snippet
    }

    let {
        permissions,
        path,
        crumbs = [],
        loadEntities = loadPaletteEntities,
        brand,
        trailing,
        children,
    }: Props = $props()

    let collapsed = $state(false)
    let paletteOpen = $state(false)
    let entities: PaletteEntity[] = $state([])
    let entitiesLoading = $state(false)
    let entitiesLoaded = false

    const sections = $derived(permittedSections(NAV_SECTIONS, permissions))
    const actions = $derived(
        permittedActions(
            [...NAVIGATION_ACTIONS, ...CREATE_ACTIONS],
            permissions,
        ),
    )

    async function onPaletteOpen() {
        if (entitiesLoaded) {
            return
        }
        entitiesLoaded = true
        entitiesLoading = true
        try {
            const result = await loadEntities(permissions)
            entities = result.entities
        } finally {
            entitiesLoading = false
        }
    }
</script>

<div class="wg-shell">
    <Sidebar {sections} {path} bind:collapsed {brand} />

    <div class="wg-shell-main">
        <TopBar
            {crumbs}
            onopenPalette={() => (paletteOpen = true)}
            {trailing}
        />

        <!--
          The landmark the skip link targets, and the thing a screen reader
          user jumps to. tabindex="-1" makes it programmatically focusable
          without adding a tab stop.
        -->
        <main id="wg-main" tabindex="-1">
            <div class="wg-canvas">
                {@render children?.()}
            </div>
        </main>
    </div>
</div>

<CommandPalette
    bind:open={paletteOpen}
    {actions}
    {entities}
    loading={entitiesLoading}
    onopen={onPaletteOpen}
/>

<ToastHost />

<style>
    .wg-shell {
        display: flex;
        min-height: 100vh;
        background: var(--wg-surface);
        color: var(--wg-text);
    }

    .wg-shell-main {
        display: flex;
        flex-direction: column;
        flex: 1 1 auto;
        min-width: 0;
    }

    main {
        flex: 1 1 auto;
        min-width: 0;
    }

    main:focus-visible {
        outline: var(--wg-focus-ring);
        outline-offset: calc(-1 * var(--wg-focus-ring-width));
    }

    .wg-canvas {
        max-width: var(--wg-content-max);
        margin: 0 auto;
        padding: var(--wg-content-padding);
    }

    /* Below the compact breakpoint the rail is the only sidebar mode that
     * fits; DESIGN.md's <768px drawer behaviour lands with the responsive
     * pass in Phase 5. */
    @media (max-width: 767px) {
        .wg-canvas {
            padding: var(--wg-margin-mobile);
        }
    }
</style>
