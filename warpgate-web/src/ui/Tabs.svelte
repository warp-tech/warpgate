<script lang="ts" module>
    export interface Tab<T extends string> {
        value: T
        label: string
        disabled?: boolean
        /** Rendered after the label — a count, a status dot. */
        badge?: string | number
    }
</script>

<script lang="ts" generics="T extends string">
    /**
     * NET-NEW primitive.
     *
     * A real ARIA tablist: it swaps a panel. Where the control only picks a
     * value without swapping content, use SegmentedControl.
     *
     * Implements the APG tabs pattern manually because there is no native
     * element for it: roving tabindex (one tab stop for the strip), Arrow keys
     * to move between tabs, Home/End to jump. Activation is automatic — moving
     * focus selects — which is the right default for cheap panels and the
     * reason panels here must not do expensive work on mount.
     */
    import type { Snippet } from 'svelte'

    interface Props {
        value?: T
        tabs: Tab<T>[]
        /** Accessible name for the tablist. */
        label: string
        class?: string
        onchange?: (value: T) => void
        children?: Snippet<[T]>
    }

    let {
        value = $bindable(),
        tabs,
        label,
        class: className = '',
        onchange,
        children,
    }: Props = $props()

    const id = `wg-tabs-${Math.random().toString(36).slice(2, 9)}`
    let strip: HTMLDivElement | undefined = $state()

    const enabled = $derived(tabs.filter(t => !t.disabled))
    const current = $derived(value ?? enabled[0]?.value)

    function select(v: T) {
        value = v
        onchange?.(v)
    }

    function focusTab(v: T) {
        strip?.querySelector<HTMLButtonElement>(`[data-tab="${v}"]`)?.focus()
    }

    function onkeydown(event: KeyboardEvent) {
        const list = enabled
        const index = list.findIndex(t => t.value === current)
        let next: T | undefined

        switch (event.key) {
            case 'ArrowRight':
                next = list[(index + 1) % list.length]?.value
                break
            case 'ArrowLeft':
                next = list[(index - 1 + list.length) % list.length]?.value
                break
            case 'Home':
                next = list[0]?.value
                break
            case 'End':
                next = list[list.length - 1]?.value
                break
            default:
                return
        }

        if (next !== undefined) {
            event.preventDefault()
            select(next)
            focusTab(next)
        }
    }
</script>

<div class="wg-tabs {className}">
    <!--
      Keydown sits on the tabs, not the tablist. With a roving tabindex focus
      is always on a tab, so the tablist would only ever see bubbled events —
      and a tablist carrying its own handler reads as focusable when it isn't.
    -->
    <div bind:this={strip} class="wg-tablist" role="tablist" aria-label={label}>
        {#each tabs as tab (tab.value)}
            <button
                type="button"
                role="tab"
                data-tab={tab.value}
                id="{id}-tab-{tab.value}"
                aria-selected={current === tab.value}
                aria-controls="{id}-panel-{tab.value}"
                tabindex={current === tab.value ? 0 : -1}
                disabled={tab.disabled}
                class="wg-tab"
                class:wg-tab-active={current === tab.value}
                onclick={() => select(tab.value)}
                {onkeydown}
            >
                {tab.label}
                {#if tab.badge !== undefined}
                    <span class="wg-tab-badge">{tab.badge}</span>
                {/if}
            </button>
        {/each}
    </div>

    {#if current !== undefined}
        <!-- APG tabs: a focusable panel keeps text-only and overflowing panels reachable by keyboard. -->
        <div
            role="tabpanel"
            id="{id}-panel-{current}"
            aria-labelledby="{id}-tab-{current}"
            tabindex="0"
            class="wg-tabpanel"
        >
            {@render children?.(current)}
        </div>
    {/if}
</div>

<style>
    .wg-tablist {
        display: flex;
        gap: var(--wg-space-xs);
        border-bottom: var(--wg-border-width) solid var(--wg-border);
        overflow-x: auto;
    }

    .wg-tab {
        display: inline-flex;
        align-items: center;
        gap: var(--wg-space-xs);
        flex: none;
        height: var(--wg-control-height);
        padding: 0 var(--wg-control-padding-x);
        border: 0;
        /* The indicator is a transparent border that colours in, so the label
         * does not shift by 2px when a tab becomes active. */
        border-bottom: 2px solid transparent;
        margin-bottom: calc(-1 * var(--wg-border-width));
        background: none;
        color: var(--wg-text-muted);
        font: var(--wg-text-label-md);
        white-space: nowrap;
        cursor: pointer;
        transition:
            color var(--wg-duration-fast) var(--wg-easing),
            border-color var(--wg-duration-fast) var(--wg-easing);
    }

    .wg-tab:hover:not(:disabled) {
        color: var(--wg-text);
    }

    .wg-tab-active {
        color: var(--wg-primary);
        border-bottom-color: var(--wg-primary);
    }

    .wg-tab:disabled {
        opacity: 0.45;
        cursor: not-allowed;
    }

    .wg-tab:focus-visible {
        outline: var(--wg-focus-ring);
        outline-offset: calc(-1 * var(--wg-focus-ring-width));
    }

    .wg-tab-badge {
        display: inline-flex;
        align-items: center;
        height: 1rem;
        padding: 0 var(--wg-space-xs);
        border-radius: var(--wg-radius-badge);
        background: var(--wg-surface-container-high);
        color: var(--wg-text-muted);
        font: var(--wg-text-label-sm);
        font-variant-numeric: tabular-nums;
    }

    .wg-tabpanel {
        padding-top: var(--wg-space-lg);
    }

    .wg-tabpanel:focus-visible {
        outline: var(--wg-focus-ring);
        outline-offset: var(--wg-focus-ring-offset);
    }
</style>
