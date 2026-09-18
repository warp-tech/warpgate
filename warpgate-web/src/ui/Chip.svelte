<script lang="ts">
    /**
     * NET-NEW primitive — nothing in the existing UI does this.
     *
     * A chip is a removable or selectable token: an applied filter, a role
     * assigned to a user, an allowed CIDR. It differs from Badge in that it is
     * interactive — Badge is a read-only label.
     *
     * Two modes, and they are mutually exclusive by construction:
     *   - `onRemove` given  -> a dismissible chip with its own remove button
     *   - `onSelect` given  -> a toggleable filter chip (aria-pressed)
     * Passing both is a type error, because a chip that is both selectable and
     * dismissible has two conflicting click targets and no obvious primary.
     */
    import type { Snippet } from 'svelte'

    type Base = {
        /** Machine data — renders in the mono face. */
        mono?: boolean
        disabled?: boolean
        id?: string
        class?: string
        children?: Snippet
    }

    type Props = Base &
        (
            | { onRemove: () => void; onSelect?: never; selected?: never }
            | { onSelect: () => void; selected?: boolean; onRemove?: never }
            | { onRemove?: never; onSelect?: never; selected?: never }
        )

    let {
        mono = false,
        disabled = false,
        id,
        class: className = '',
        children,
        onRemove,
        onSelect,
        selected = false,
    }: Props = $props()

    // Chips carry short labels, and a remove button needs a name that says
    // WHAT it removes — "Remove" alone is useless in a row of eight chips.
    let labelEl: HTMLSpanElement | undefined = $state()
    let text = $state('')
    $effect(() => {
        text = labelEl?.textContent?.trim() ?? ''
    })
</script>

{#if onSelect}
    <button
        {id}
        type="button"
        class="wg-chip wg-chip-selectable {className}"
        class:wg-chip-mono={mono}
        class:wg-chip-selected={selected}
        aria-pressed={selected}
        {disabled}
        onclick={onSelect}
    >
        <span bind:this={labelEl}>{@render children?.()}</span>
    </button>
{:else}
    <span {id} class="wg-chip {className}" class:wg-chip-mono={mono}>
        <span bind:this={labelEl}>{@render children?.()}</span>
        {#if onRemove}
            <button
                type="button"
                class="wg-chip-remove"
                aria-label={text ? `Remove ${text}` : 'Remove'}
                {disabled}
                onclick={onRemove}
            >
                <svg
                    viewBox="0 0 12 12"
                    width="10"
                    height="10"
                    aria-hidden="true"
                >
                    <path
                        d="M3 3l6 6M9 3l-6 6"
                        fill="none"
                        stroke="currentColor"
                        stroke-width="1.75"
                        stroke-linecap="round"
                    />
                </svg>
            </button>
        {/if}
    </span>
{/if}

<style>
    .wg-chip {
        display: inline-flex;
        align-items: center;
        gap: var(--wg-space-xs);
        height: var(--wg-badge-height);
        padding: 0 var(--wg-badge-padding-x);
        border: var(--wg-border-width) solid var(--wg-border-strong);
        border-radius: var(--wg-radius-badge);
        background: var(--wg-surface-container);
        font: var(--wg-text-label-sm);
        color: var(--wg-text);
        white-space: nowrap;
    }

    .wg-chip-mono {
        font-family: var(--wg-font-mono);
        font-variant-numeric: tabular-nums;
    }

    .wg-chip-selectable {
        cursor: pointer;
        transition: background var(--wg-duration-fast) var(--wg-easing);
    }

    .wg-chip-selectable:hover:not(:disabled) {
        background: var(--wg-surface-container-high);
    }

    .wg-chip-selected {
        background: var(--wg-primary);
        color: var(--wg-on-primary);
        border-color: var(--wg-primary);
    }

    .wg-chip-selectable:focus-visible,
    .wg-chip-remove:focus-visible {
        outline: var(--wg-focus-ring);
        outline-offset: var(--wg-focus-ring-offset);
    }

    .wg-chip-selectable:disabled,
    .wg-chip-remove:disabled {
        opacity: 0.45;
        cursor: not-allowed;
    }

    .wg-chip-remove {
        display: inline-flex;
        align-items: center;
        justify-content: center;
        /* 16px hit area inside a 20px chip; the chip itself is the padding */
        width: 16px;
        height: 16px;
        margin-right: -3px;
        padding: 0;
        border: 0;
        border-radius: var(--wg-radius-sm);
        background: none;
        color: var(--wg-text-muted);
        cursor: pointer;
    }

    .wg-chip-remove:hover:not(:disabled) {
        background: var(--wg-surface-container-highest);
        color: var(--wg-text);
    }
</style>
