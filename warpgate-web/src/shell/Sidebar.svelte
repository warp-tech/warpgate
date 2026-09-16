<script lang="ts">
    /**
     * Left rail. 240px expanded, 56px icon rail collapsed, per DESIGN.md.
     *
     * Every item in the collapsed rail is icon-only, so every item carries an
     * accessible name on the link itself — the visible label is hidden with a
     * clip, not removed, so the name survives collapse without needing a
     * parallel aria-label that can drift from it. A tooltip shows the same
     * string on hover, which is supplementary; the name is the label.
     *
     * Collapse is persisted under a namespaced key for the same reason the
     * theme is: HTTP targets proxied at the portal root share one localStorage
     * with everything the portal proxies.
     */
    import Tooltip from 'ui/Tooltip.svelte'
    import { activeItemId, type NavSection } from './navItems'

    interface Props {
        sections: NavSection[]
        /** Current SPA path, e.g. "/config/targets/abc". */
        path: string
        collapsed?: boolean
        /** Rendered above the nav — the brand lives here, untouched. */
        brand?: import('svelte').Snippet
    }

    let {
        sections,
        path,
        collapsed = $bindable(false),
        brand,
    }: Props = $props()

    const COLLAPSE_KEY = 'warpgateSidebarCollapsed'

    // Reading in an effect rather than at init keeps this safe in any context
    // where storage throws (private windows, blocked site data).
    $effect(() => {
        try {
            localStorage.setItem(COLLAPSE_KEY, collapsed ? '1' : '0')
        } catch {
            // Persistence is a convenience; the rail still works without it.
        }
    })

    const active = $derived(activeItemId(sections, path))
</script>

<nav
    class="wg-sidebar"
    class:wg-sidebar-collapsed={collapsed}
    aria-label="Main"
>
    {#if brand}
        <div class="wg-sidebar-brand">
            {@render brand()}
        </div>
    {/if}

    <div class="wg-sidebar-scroll">
        {#each sections as section (section.id)}
            <div class="wg-sidebar-section">
                <!-- The heading is decorative when collapsed: the rail has no
                     room for it, and each link already carries its own name. -->
                <p class="wg-sidebar-heading" aria-hidden={collapsed}>
                    {section.label}
                </p>
                <ul>
                    {#each section.items as item (item.id)}
                        <li>
                            {#if collapsed}
                                <Tooltip text={item.label} placement="right">
                                    <a
                                        href={item.href}
                                        class="wg-nav-link"
                                        class:wg-nav-active={active === item.id}
                                        aria-current={active === item.id
                                            ? 'page'
                                            : undefined}
                                    >
                                        <svg
                                            viewBox="0 0 16 16"
                                            width="16"
                                            height="16"
                                            aria-hidden="true"
                                        >
                                            <path
                                                d={item.icon}
                                                fill="none"
                                                stroke="currentColor"
                                                stroke-width="1.4"
                                                stroke-linecap="round"
                                                stroke-linejoin="round"
                                            />
                                        </svg>
                                        <span class="wg-nav-label">
                                            {item.label}
                                        </span>
                                    </a>
                                </Tooltip>
                            {:else}
                                <a
                                    href={item.href}
                                    class="wg-nav-link"
                                    class:wg-nav-active={active === item.id}
                                    aria-current={active === item.id
                                        ? 'page'
                                        : undefined}
                                >
                                    <svg
                                        viewBox="0 0 16 16"
                                        width="16"
                                        height="16"
                                        aria-hidden="true"
                                    >
                                        <path
                                            d={item.icon}
                                            fill="none"
                                            stroke="currentColor"
                                            stroke-width="1.4"
                                            stroke-linecap="round"
                                            stroke-linejoin="round"
                                        />
                                    </svg>
                                    <span class="wg-nav-label"
                                        >{item.label}</span
                                    >
                                </a>
                            {/if}
                        </li>
                    {/each}
                </ul>
            </div>
        {/each}
    </div>

    <button
        type="button"
        class="wg-sidebar-toggle"
        aria-label={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
        aria-expanded={!collapsed}
        onclick={() => (collapsed = !collapsed)}
    >
        <svg viewBox="0 0 16 16" width="14" height="14" aria-hidden="true">
            <path
                d={collapsed ? 'M6 4l4 4-4 4' : 'M10 4L6 8l4 4'}
                fill="none"
                stroke="currentColor"
                stroke-width="1.5"
                stroke-linecap="round"
                stroke-linejoin="round"
            />
        </svg>
        <span class="wg-nav-label">
            {collapsed ? 'Expand' : 'Collapse'}
        </span>
    </button>
</nav>

<style>
    .wg-sidebar {
        display: flex;
        flex-direction: column;
        flex: none;
        width: var(--wg-sidebar-width);
        height: 100vh;
        position: sticky;
        top: 0;
        background: var(--wg-surface-container);
        border-right: var(--wg-border-width) solid var(--wg-border);
        transition: width var(--wg-duration-normal) var(--wg-easing);
        overflow: hidden;
    }

    .wg-sidebar-collapsed {
        width: var(--wg-sidebar-width-rail);
    }

    .wg-sidebar-brand {
        display: flex;
        align-items: center;
        flex: none;
        height: var(--wg-topbar-height);
        padding: 0 var(--wg-space-md);
        border-bottom: var(--wg-border-width) solid var(--wg-border);
        overflow: hidden;
    }

    .wg-sidebar-scroll {
        flex: 1 1 auto;
        overflow-y: auto;
        overflow-x: hidden;
        padding: var(--wg-space-sm) 0;
    }

    .wg-sidebar-section + .wg-sidebar-section {
        margin-top: var(--wg-space-md);
    }

    .wg-sidebar-heading {
        margin: 0;
        padding: var(--wg-space-sm) var(--wg-space-md) var(--wg-space-xs);
        font: var(--wg-text-label-sm);
        color: var(--wg-text-subtle);
        white-space: nowrap;
    }

    .wg-sidebar-collapsed .wg-sidebar-heading {
        /* A 1px rule stands in for the heading, so the grouping survives
         * collapse even though the words cannot. */
        height: var(--wg-border-width);
        padding: 0;
        margin: var(--wg-space-sm) var(--wg-space-sm);
        overflow: hidden;
        background: var(--wg-border);
        color: transparent;
    }

    ul {
        list-style: none;
        margin: 0;
        padding: 0;
    }

    .wg-nav-link {
        display: flex;
        align-items: center;
        gap: var(--wg-space-md);
        height: var(--wg-control-height);
        margin: 1px var(--wg-space-sm);
        padding: 0 var(--wg-space-sm);
        border-radius: var(--wg-radius-control);
        color: var(--wg-text-muted);
        text-decoration: none;
        white-space: nowrap;
        font: var(--wg-text-label-md);
        transition:
            background var(--wg-duration-fast) var(--wg-easing),
            color var(--wg-duration-fast) var(--wg-easing);
    }

    .wg-nav-link svg {
        flex: none;
    }

    .wg-nav-link:hover {
        background: var(--wg-surface-container-high);
        color: var(--wg-text);
    }

    .wg-nav-link:focus-visible,
    .wg-sidebar-toggle:focus-visible {
        outline: var(--wg-focus-ring);
        outline-offset: calc(-1 * var(--wg-focus-ring-width));
    }

    .wg-nav-active {
        background: var(--wg-surface-container-highest);
        color: var(--wg-text);
        /* A left edge rather than a fill alone: the active item stays
         * identifiable in the collapsed rail, where the label is gone. */
        box-shadow: inset 2px 0 0 var(--wg-primary);
    }

    /*
     * Clipped, not removed. The link keeps its accessible name in the
     * collapsed rail without a parallel aria-label that could drift from the
     * visible text when someone renames an item.
     */
    .wg-sidebar-collapsed .wg-nav-label {
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

    .wg-sidebar-toggle {
        display: flex;
        align-items: center;
        gap: var(--wg-space-md);
        flex: none;
        height: var(--wg-control-height);
        margin: var(--wg-space-sm);
        padding: 0 var(--wg-space-sm);
        border: 0;
        border-radius: var(--wg-radius-control);
        background: none;
        color: var(--wg-text-subtle);
        font: var(--wg-text-label-md);
        white-space: nowrap;
        cursor: pointer;
    }

    .wg-sidebar-toggle:hover {
        background: var(--wg-surface-container-high);
        color: var(--wg-text);
    }

    .wg-sidebar-toggle svg {
        flex: none;
    }

    @media (prefers-reduced-motion: reduce) {
        .wg-sidebar {
            transition: none;
        }
    }
</style>
