<script lang="ts">
    /**
     * Fixed 56px bar with a bottom hairline, per DESIGN.md.
     *
     * Carries the breadcrumb trail, the palette trigger and whatever the shell
     * passes as trailing content (auth, theme, requests). The palette trigger
     * is a real button rather than a decorative hint, because Cmd+K is not
     * discoverable and is unavailable to anyone driving the UI by pointer or
     * by switch.
     */
    import type { Snippet } from 'svelte'
    import Breadcrumbs, { type Crumb } from './Breadcrumbs.svelte'

    interface Props {
        crumbs?: Crumb[]
        onopenPalette?: () => void
        /** Right-aligned content — auth bar, theme switcher, requests. */
        trailing?: Snippet
    }

    let { crumbs = [], onopenPalette, trailing }: Props = $props()

    // Mac reads ⌘K, everything else Ctrl K. Detected from the platform rather
    // than the user agent string where possible.
    const isMac =
        typeof navigator !== 'undefined' &&
        /mac|iphone|ipad/i.test(
            // biome-ignore lint/suspicious/noExplicitAny: userAgentData is not in lib.dom yet
            (navigator as any).userAgentData?.platform ??
                navigator.platform ??
                '',
        )
</script>

<header class="wg-topbar">
    <Breadcrumbs {crumbs} />

    <div class="wg-topbar-spacer"></div>

    <button
        type="button"
        class="wg-palette-trigger"
        onclick={onopenPalette}
        aria-keyshortcuts={isMac ? 'Meta+K' : 'Control+K'}
    >
        <svg viewBox="0 0 16 16" width="14" height="14" aria-hidden="true">
            <circle
                cx="7"
                cy="7"
                r="4.5"
                fill="none"
                stroke="currentColor"
                stroke-width="1.5"
            />
            <path
                d="M10.5 10.5L14 14"
                stroke="currentColor"
                stroke-width="1.5"
                stroke-linecap="round"
            />
        </svg>
        <span class="wg-palette-trigger-text">Search</span>
        <kbd aria-hidden="true">{isMac ? '⌘' : 'Ctrl'}</kbd
        ><kbd aria-hidden="true">K</kbd>
    </button>

    {#if trailing}
        <div class="wg-topbar-trailing">
            {@render trailing()}
        </div>
    {/if}
</header>

<style>
    .wg-topbar {
        display: flex;
        align-items: center;
        gap: var(--wg-space-md);
        position: sticky;
        top: 0;
        z-index: 10;
        height: var(--wg-topbar-height);
        padding: 0 var(--wg-content-padding);
        background: var(--wg-surface-container);
        border-bottom: var(--wg-border-width) solid var(--wg-border);
    }

    .wg-topbar-spacer {
        flex: 1 1 auto;
        min-width: var(--wg-space-md);
    }

    .wg-topbar-trailing {
        display: flex;
        align-items: center;
        gap: var(--wg-space-sm);
        flex: none;
    }

    .wg-palette-trigger {
        display: inline-flex;
        align-items: center;
        gap: var(--wg-space-sm);
        flex: none;
        height: var(--wg-control-height-compact);
        padding: 0 var(--wg-space-sm);
        border: var(--wg-border-width) solid var(--wg-border-strong);
        border-radius: var(--wg-radius-control);
        background: var(--wg-surface-sunken);
        color: var(--wg-text-subtle);
        font: var(--wg-text-label-md);
        cursor: pointer;
    }

    .wg-palette-trigger:hover {
        color: var(--wg-text);
        border-color: var(--wg-primary);
    }

    .wg-palette-trigger:focus-visible {
        outline: var(--wg-focus-ring);
        outline-offset: var(--wg-focus-ring-offset);
    }

    kbd {
        display: inline-block;
        min-width: 1.1rem;
        padding: 0 3px;
        border: var(--wg-border-width) solid var(--wg-border);
        border-radius: var(--wg-radius-sm);
        background: var(--wg-surface-container-high);
        font: var(--wg-text-code-sm);
        text-align: center;
    }

    /* Below the compact breakpoint the trigger collapses to its icon; the
     * button keeps its text as the accessible name. */
    @media (max-width: 720px) {
        .wg-palette-trigger-text,
        kbd {
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
    }
</style>
