<script lang="ts">
    /**
     * NET-NEW primitive.
     *
     * A side panel for inspecting or editing one record without leaving the
     * list behind it — the pattern `warpgate_add_target_drawer` draws, and the
     * one the target and user screens migrate to in Phase 4.
     *
     * Semantically identical to Modal (dialog, modal, trapped, Escape-closes)
     * and different only in how it arrives and how much room it gets. Sharing
     * the focus-trap action rather than the component keeps the two honest
     * about that.
     *
     * Below 640px it becomes a bottom sheet: a 30rem side panel on a 390px
     * phone is the whole screen anyway, and sliding up reads better than
     * sliding in from an edge that isn't there.
     */
    import type { Snippet } from 'svelte'
    import { focusTrap, scrollLock } from './focusTrap'

    interface Props {
        open?: boolean
        title: string
        /** Secondary line under the title — a hostname, a record id. */
        subtitle?: string
        side?: 'right' | 'left'
        size?: 'sm' | 'md' | 'lg'
        dismissable?: boolean
        onclose?: () => void
        class?: string
        children?: Snippet
        footer?: Snippet
    }

    let {
        open = $bindable(false),
        title,
        subtitle,
        side = 'right',
        size = 'md',
        dismissable = true,
        onclose,
        class: className = '',
        children,
        footer,
    }: Props = $props()

    const id = `wg-drawer-${Math.random().toString(36).slice(2, 9)}`

    function close() {
        if (!dismissable) {
            return
        }
        open = false
        onclose?.()
    }

    $effect(() => {
        if (!open) {
            return
        }
        const lock = scrollLock()
        return () => lock.release()
    })

    function onkeydown(event: KeyboardEvent) {
        if (event.key === 'Escape') {
            event.stopPropagation()
            close()
        }
    }
</script>

{#if open}
    <div
        class="wg-scrim"
        data-wg-overlay
        onclick={close}
        aria-hidden="true"
    ></div>

    <div
        class="wg-drawer wg-drawer-{side} wg-drawer-{size} {className}"
        role="dialog"
        aria-modal="true"
        aria-labelledby="{id}-title"
        tabindex="-1"
        use:focusTrap
        {onkeydown}
    >
        <header class="wg-drawer-head">
            <div class="wg-drawer-titles">
                <h2 id="{id}-title">{title}</h2>
                {#if subtitle}
                    <p class="wg-drawer-sub">{subtitle}</p>
                {/if}
            </div>
            {#if dismissable}
                <button
                    type="button"
                    class="wg-drawer-close"
                    aria-label="Close {title}"
                    onclick={close}
                >
                    <svg
                        viewBox="0 0 16 16"
                        width="14"
                        height="14"
                        aria-hidden="true"
                    >
                        <path
                            d="M4 4l8 8M12 4l-8 8"
                            fill="none"
                            stroke="currentColor"
                            stroke-width="1.75"
                            stroke-linecap="round"
                        />
                    </svg>
                </button>
            {/if}
        </header>

        <div class="wg-drawer-body">
            {@render children?.()}
        </div>

        {#if footer}
            <footer class="wg-drawer-foot">
                {@render footer()}
            </footer>
        {/if}
    </div>
{/if}

<style>
    .wg-scrim {
        position: fixed;
        inset: 0;
        background: rgb(0 0 0 / 0.6);
        z-index: 1000;
    }

    .wg-drawer {
        position: fixed;
        top: 0;
        bottom: 0;
        z-index: 1001;
        display: flex;
        flex-direction: column;
        width: min(100vw, var(--drawer-w, 30rem));
        background: var(--wg-surface-container);
        border-left: var(--wg-border-width) solid var(--wg-border);
        box-shadow: var(--wg-shadow-overlay);
        color: var(--wg-text);
        animation: wg-drawer-in var(--wg-duration-normal) var(--wg-easing);
    }

    .wg-drawer-sm {
        --drawer-w: 22rem;
    }
    .wg-drawer-md {
        --drawer-w: 30rem;
    }
    .wg-drawer-lg {
        --drawer-w: 44rem;
    }

    .wg-drawer-right {
        right: 0;
    }

    .wg-drawer-left {
        left: 0;
        border-left: 0;
        border-right: var(--wg-border-width) solid var(--wg-border);
        animation-name: wg-drawer-in-left;
    }

    @keyframes wg-drawer-in {
        from {
            transform: translateX(100%);
        }
    }

    @keyframes wg-drawer-in-left {
        from {
            transform: translateX(-100%);
        }
    }

    .wg-drawer:focus-visible {
        outline: var(--wg-focus-ring);
        outline-offset: calc(-1 * var(--wg-focus-ring-width));
    }

    .wg-drawer-head {
        display: flex;
        align-items: flex-start;
        justify-content: space-between;
        gap: var(--wg-space-lg);
        flex: none;
        padding: var(--wg-space-lg);
        border-bottom: var(--wg-border-width) solid var(--wg-border);
    }

    .wg-drawer-titles {
        min-width: 0;
    }

    h2 {
        margin: 0;
        font: var(--wg-text-headline-md);
    }

    .wg-drawer-sub {
        margin: var(--wg-space-xs) 0 0;
        font: var(--wg-text-code-sm);
        color: var(--wg-text-muted);
        overflow-wrap: anywhere;
    }

    .wg-drawer-close {
        display: inline-flex;
        align-items: center;
        justify-content: center;
        flex: none;
        width: var(--wg-control-height-compact);
        height: var(--wg-control-height-compact);
        padding: 0;
        border: 0;
        border-radius: var(--wg-radius-control);
        background: none;
        color: var(--wg-text-muted);
        cursor: pointer;
    }

    .wg-drawer-close:hover {
        background: var(--wg-surface-container-high);
        color: var(--wg-text);
    }

    .wg-drawer-close:focus-visible {
        outline: var(--wg-focus-ring);
        outline-offset: var(--wg-focus-ring-offset);
    }

    .wg-drawer-body {
        flex: 1 1 auto;
        overflow-y: auto;
        padding: var(--wg-space-lg);
        font: var(--wg-text-body-md);
    }

    .wg-drawer-foot {
        display: flex;
        align-items: center;
        justify-content: flex-end;
        gap: var(--wg-space-sm);
        flex: none;
        padding: var(--wg-space-lg);
        border-top: var(--wg-border-width) solid var(--wg-border);
    }

    /* Bottom sheet on small viewports */
    @media (max-width: 640px) {
        .wg-drawer {
            top: auto;
            left: 0;
            right: 0;
            width: 100vw;
            max-height: 85vh;
            border: 0;
            border-top: var(--wg-border-width) solid var(--wg-border);
            border-radius: var(--wg-radius-panel) var(--wg-radius-panel) 0 0;
            animation-name: wg-sheet-in;
        }

        .wg-drawer-foot {
            flex-direction: column-reverse;
            align-items: stretch;
        }
    }

    @keyframes wg-sheet-in {
        from {
            transform: translateY(100%);
        }
    }

    @media (prefers-reduced-motion: reduce) {
        .wg-drawer {
            animation: none;
        }
    }
</style>
