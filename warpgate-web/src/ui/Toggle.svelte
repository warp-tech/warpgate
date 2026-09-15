<script lang="ts">
    /**
     * NET-NEW primitive.
     *
     * Built on `role="switch"` rather than a restyled checkbox. The difference
     * matters here: a checkbox says "this will be true when you save", a
     * switch says "this is on now". Warpgate's toggles are mostly the latter —
     * enabling a target, allowing ticket self-service — and a screen reader
     * announcing "checkbox, checked" for a live setting is misleading.
     *
     * Where a toggle really is deferred until a save, use Checkbox instead.
     */
    interface Props {
        checked?: boolean
        label: string
        /** Hides the label visually but keeps it as the accessible name. */
        labelHidden?: boolean
        hint?: string
        disabled?: boolean
        id?: string
        size?: 'standard' | 'compact'
        class?: string
        onchange?: (checked: boolean) => void
    }

    let {
        checked = $bindable(false),
        label,
        labelHidden = false,
        hint,
        disabled = false,
        id = `wg-toggle-${Math.random().toString(36).slice(2, 9)}`,
        size = 'standard',
        class: className = '',
        onchange,
    }: Props = $props()

    function toggle() {
        if (disabled) {
            return
        }
        checked = !checked
        onchange?.(checked)
    }

    // role="switch" gets Space from the button role for free, but not Enter
    // in every screen reader's forms mode; both are wired explicitly.
    function onkeydown(event: KeyboardEvent) {
        if (event.key === ' ' || event.key === 'Enter') {
            event.preventDefault()
            toggle()
        }
    }
</script>

<div class="wg-toggle-wrap {className}">
    <div class="wg-toggle-row">
        <button
            type="button"
            role="switch"
            {id}
            aria-checked={checked}
            aria-label={labelHidden ? label : undefined}
            aria-describedby={hint ? `${id}-hint` : undefined}
            {disabled}
            class="wg-toggle wg-toggle-{size}"
            onclick={toggle}
            {onkeydown}
        >
            <span class="wg-toggle-thumb" aria-hidden="true"></span>
        </button>
        {#if !labelHidden}
            <label for={id}>{label}</label>
        {/if}
    </div>
    {#if hint}
        <p class="wg-field-hint" id="{id}-hint">{hint}</p>
    {/if}
</div>

<style>
    .wg-toggle-wrap {
        display: flex;
        flex-direction: column;
        gap: var(--wg-space-xs);
    }

    .wg-toggle-row {
        display: flex;
        align-items: center;
        gap: var(--wg-space-sm);
    }

    label {
        font: var(--wg-text-body-md);
        color: var(--wg-text);
        cursor: pointer;
    }

    .wg-toggle {
        --track-w: 2rem;
        --track-h: 1.125rem;
        --thumb: 0.75rem;

        flex: none;
        position: relative;
        width: var(--track-w);
        height: var(--track-h);
        padding: 0;
        border: var(--wg-border-width) solid var(--wg-border-strong);
        border-radius: var(--wg-radius-full);
        background: var(--wg-surface-sunken);
        cursor: pointer;
        transition:
            background var(--wg-duration-fast) var(--wg-easing),
            border-color var(--wg-duration-fast) var(--wg-easing);
    }

    .wg-toggle-compact {
        --track-w: 1.75rem;
        --track-h: 1rem;
        --thumb: 0.625rem;
    }

    .wg-toggle-thumb {
        position: absolute;
        top: 50%;
        left: 2px;
        width: var(--thumb);
        height: var(--thumb);
        border-radius: var(--wg-radius-full);
        background: var(--wg-text-muted);
        transform: translateY(-50%);
        transition:
            left var(--wg-duration-fast) var(--wg-easing),
            background var(--wg-duration-fast) var(--wg-easing);
    }

    .wg-toggle[aria-checked="true"] {
        background: var(--wg-primary);
        border-color: var(--wg-primary);
    }

    .wg-toggle[aria-checked="true"] .wg-toggle-thumb {
        left: calc(100% - var(--thumb) - 2px);
        background: var(--wg-on-primary);
    }

    .wg-toggle:focus-visible {
        outline: var(--wg-focus-ring);
        outline-offset: var(--wg-focus-ring-offset);
    }

    .wg-toggle:disabled {
        opacity: 0.45;
        cursor: not-allowed;
    }

    .wg-field-hint {
        margin: 0 0 0 calc(2rem + var(--wg-space-sm));
        font: var(--wg-text-label-sm);
        color: var(--wg-text-subtle);
    }
</style>
