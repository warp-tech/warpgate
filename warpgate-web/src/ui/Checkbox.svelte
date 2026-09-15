<script lang="ts">
    interface Props {
        checked?: boolean
        /** Renders the dash state. Clears itself once the user clicks. */
        indeterminate?: boolean
        label?: string
        /** Hides the label visually — needed for per-row selection checkboxes. */
        labelHidden?: boolean
        disabled?: boolean
        id?: string
        name?: string
        value?: string
        hint?: string
        class?: string
        onchange?: (event: Event) => void
    }

    let {
        checked = $bindable(false),
        indeterminate = $bindable(false),
        label,
        labelHidden = false,
        disabled = false,
        id = `wg-check-${Math.random().toString(36).slice(2, 9)}`,
        name,
        value,
        hint,
        class: className = '',
        onchange,
    }: Props = $props()

    let input: HTMLInputElement | undefined = $state()

    // `indeterminate` is a DOM property with no HTML attribute, so it has to
    // be assigned imperatively whenever it changes.
    $effect(() => {
        if (input) {
            input.indeterminate = indeterminate
        }
    })
</script>

<div class="wg-check-wrap {className}">
    <label class="wg-check" class:wg-check-disabled={disabled}>
        <input
            bind:this={input}
            type="checkbox"
            {id}
            {name}
            {value}
            {disabled}
            bind:checked
            aria-describedby={hint ? `${id}-hint` : undefined}
            onchange={e => {
                indeterminate = false
                onchange?.(e)
            }}
        >
        <span class="wg-check-box" aria-hidden="true">
            {#if indeterminate}
                <svg
                    viewBox="0 0 16 16"
                    width="12"
                    height="12"
                    aria-hidden="true"
                >
                    <path
                        d="M4 8h8"
                        fill="none"
                        stroke="currentColor"
                        stroke-width="2"
                        stroke-linecap="round"
                    />
                </svg>
            {:else if checked}
                <svg
                    viewBox="0 0 16 16"
                    width="12"
                    height="12"
                    aria-hidden="true"
                >
                    <path
                        d="M3.5 8.5l3 3L12.5 5"
                        fill="none"
                        stroke="currentColor"
                        stroke-width="2"
                        stroke-linecap="round"
                        stroke-linejoin="round"
                    />
                </svg>
            {/if}
        </span>
        {#if label}
            <span class="wg-check-label" class:wg-sr-only={labelHidden}>
                {label}
            </span>
        {/if}
    </label>
    {#if hint}
        <p class="wg-field-hint" id="{id}-hint">{hint}</p>
    {/if}
</div>

<style>
    .wg-check-wrap {
        display: flex;
        flex-direction: column;
        gap: var(--wg-space-xs);
    }

    .wg-check {
        display: inline-flex;
        align-items: center;
        gap: var(--wg-space-sm);
        font: var(--wg-text-body-md);
        color: var(--wg-text);
        cursor: pointer;
    }

    .wg-check-disabled {
        opacity: 0.45;
        cursor: not-allowed;
    }

    /* The native input stays in the layout and keeps every built-in
     * behaviour — focus, form participation, space to toggle — it is just
     * transparent, with the styled box painted underneath it. */
    input {
        position: absolute;
        opacity: 0;
        width: 16px;
        height: 16px;
        margin: 0;
        cursor: inherit;
    }

    .wg-check-box {
        display: inline-flex;
        align-items: center;
        justify-content: center;
        flex: none;
        width: 16px;
        height: 16px;
        border: var(--wg-border-width) solid var(--wg-border-strong);
        border-radius: var(--wg-radius-sm);
        background: var(--wg-surface-sunken);
        color: var(--wg-on-primary);
        transition:
            background var(--wg-duration-fast) var(--wg-easing),
            border-color var(--wg-duration-fast) var(--wg-easing);
    }

    input:checked + .wg-check-box,
    input:indeterminate + .wg-check-box {
        background: var(--wg-primary);
        border-color: var(--wg-primary);
    }

    input:focus-visible + .wg-check-box {
        outline: var(--wg-focus-ring);
        outline-offset: var(--wg-focus-ring-offset);
    }

    .wg-check:hover:not(.wg-check-disabled) .wg-check-box {
        border-color: var(--wg-primary);
    }

    .wg-field-hint {
        margin: 0 0 0 calc(16px + var(--wg-space-sm));
        font: var(--wg-text-label-sm);
        color: var(--wg-text-subtle);
    }

    .wg-sr-only {
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
</style>
