<script lang="ts">
    import type { Snippet } from 'svelte'
    import { focusTrap, scrollLock } from './focusTrap'

    interface Props {
        open?: boolean
        title: string
        /** Narrow for confirmations, wide for forms. */
        size?: 'sm' | 'md' | 'lg'
        /**
         * Destructive confirmations set this false so a stray click or an
         * absent-minded Escape cannot dismiss them.
         */
        dismissable?: boolean
        onclose?: () => void
        class?: string
        children?: Snippet
        footer?: Snippet
    }

    let {
        open = $bindable(false),
        title,
        size = 'md',
        dismissable = true,
        onclose,
        class: className = '',
        children,
        footer,
    }: Props = $props()

    const id = `wg-modal-${Math.random().toString(36).slice(2, 9)}`

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
    <!--
      The scrim is not the dismiss target for a keyboard user — Escape is, and
      the close button is. It carries a click handler for pointer users and is
      aria-hidden so it never appears as an interactive element.
    -->
    <div
        class="wg-scrim"
        data-wg-overlay
        onclick={close}
        aria-hidden="true"
    ></div>

    <div
        class="wg-modal wg-modal-{size} {className}"
        role="dialog"
        aria-modal="true"
        aria-labelledby="{id}-title"
        tabindex="-1"
        use:focusTrap
        {onkeydown}
    >
        <header class="wg-modal-head">
            <h2 id="{id}-title">{title}</h2>
            {#if dismissable}
                <button
                    type="button"
                    class="wg-modal-close"
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

        <div class="wg-modal-body">
            {@render children?.()}
        </div>

        {#if footer}
            <footer class="wg-modal-foot">
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

    .wg-modal {
        position: fixed;
        top: 50%;
        left: 50%;
        transform: translate(-50%, -50%);
        z-index: 1001;
        display: flex;
        flex-direction: column;
        width: min(100vw - 2 * var(--wg-space-lg), var(--modal-w, 32rem));
        max-height: calc(100vh - 2 * var(--wg-space-xl));
        background: var(--wg-surface-container);
        border: var(--wg-border-width) solid var(--wg-border);
        border-radius: var(--wg-radius-panel);
        /* The one sanctioned shadow: overlay planes */
        box-shadow: var(--wg-shadow-overlay);
        color: var(--wg-text);
    }

    .wg-modal-sm {
        --modal-w: 24rem;
    }
    .wg-modal-md {
        --modal-w: 32rem;
    }
    .wg-modal-lg {
        --modal-w: 48rem;
    }

    .wg-modal:focus-visible {
        outline: var(--wg-focus-ring);
        outline-offset: calc(-1 * var(--wg-focus-ring-width));
    }

    .wg-modal-head {
        display: flex;
        align-items: center;
        justify-content: space-between;
        gap: var(--wg-space-lg);
        flex: none;
        padding: var(--wg-space-lg);
        border-bottom: var(--wg-border-width) solid var(--wg-border);
    }

    h2 {
        margin: 0;
        font: var(--wg-text-headline-md);
    }

    .wg-modal-close {
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

    .wg-modal-close:hover {
        background: var(--wg-surface-container-high);
        color: var(--wg-text);
    }

    .wg-modal-close:focus-visible {
        outline: var(--wg-focus-ring);
        outline-offset: var(--wg-focus-ring-offset);
    }

    .wg-modal-body {
        flex: 1 1 auto;
        overflow-y: auto;
        padding: var(--wg-space-lg);
        font: var(--wg-text-body-md);
    }

    .wg-modal-foot {
        display: flex;
        align-items: center;
        justify-content: flex-end;
        gap: var(--wg-space-sm);
        flex: none;
        padding: var(--wg-space-lg);
        border-top: var(--wg-border-width) solid var(--wg-border);
    }

    @media (max-width: 480px) {
        .wg-modal-foot {
            flex-direction: column-reverse;
            align-items: stretch;
        }
    }
</style>
