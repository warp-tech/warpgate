<script lang="ts">
    import type { Snippet } from 'svelte'

    interface Props {
        value?: string
        label?: string
        /** Hides the label visually but keeps it for assistive tech. */
        labelHidden?: boolean
        placeholder?: string
        type?:
            | 'text'
            | 'password'
            | 'email'
            | 'number'
            | 'search'
            | 'url'
            /* The only date type used anywhere in the product. */
            | 'datetime-local'
        disabled?: boolean
        readonly?: boolean
        required?: boolean
        invalid?: boolean
        /** Shown under the field and wired up via aria-describedby. */
        error?: string
        hint?: string
        /** Machine data — renders the value in the mono face. */
        mono?: boolean
        id?: string
        name?: string
        autocomplete?: AutoFill
        /**
         * Range bounds for number and datetime-local. Forwarded to the
         * element so the browser's own validation and stepper honour them —
         * six numeric fields across the migrated screens need this, and a
         * port box with no max is a support ticket waiting to happen.
         */
        min?: string | number
        max?: string | number
        /** Picks the on-screen keyboard — "numeric" for codes and ports. */
        inputmode?:
            | 'text'
            | 'numeric'
            | 'decimal'
            | 'tel'
            | 'email'
            | 'url'
            | 'search'
        size?: 'standard' | 'compact'
        /**
         * Marks this field as the one a dialog should focus on open.
         * focusTrap looks for `[data-autofocus]` on a real element, so the
         * attribute has to be forwarded rather than landing on the wrapper.
         */
        autofocus?: boolean
        class?: string
        oninput?: (event: Event) => void
        onkeydown?: (event: KeyboardEvent) => void
        onkeyup?: (event: KeyboardEvent) => void
        prefix?: Snippet
        suffix?: Snippet
    }

    let {
        value = $bindable(''),
        label,
        labelHidden = false,
        placeholder,
        type = 'text',
        disabled = false,
        readonly = false,
        required = false,
        invalid = false,
        error,
        hint,
        mono = false,
        id = `wg-input-${Math.random().toString(36).slice(2, 9)}`,
        name,
        autocomplete,
        min,
        max,
        inputmode,
        size = 'standard',
        autofocus = false,
        class: className = '',
        oninput,
        onkeydown,
        onkeyup,
        prefix,
        suffix,
    }: Props = $props()

    // An error message implies the invalid state; callers should not have to
    // remember to set both.
    const isInvalid = $derived(invalid || !!error)
    const describedBy = $derived(
        [error ? `${id}-error` : null, hint ? `${id}-hint` : null]
            .filter(Boolean)
            .join(' ') || undefined,
    )
</script>

<div class="wg-field {className}">
    {#if label}
        <label for={id} class:wg-sr-only={labelHidden}>
            {label}
            {#if required}
                <span class="wg-required" aria-hidden="true">*</span>
            {/if}
        </label>
    {/if}

    <div
        class="wg-input-shell wg-input-{size}"
        class:wg-input-invalid={isInvalid}
        class:wg-input-disabled={disabled}
    >
        {#if prefix}
            <span class="wg-input-affix" aria-hidden="true">
                {@render prefix()}
            </span>
        {/if}
        <input
            {id}
            {name}
            {type}
            {placeholder}
            {disabled}
            {readonly}
            {required}
            {autocomplete}
            {min}
            {max}
            {inputmode}
            data-autofocus={autofocus ? '' : undefined}
            bind:value
            class:wg-mono-input={mono}
            aria-invalid={isInvalid || undefined}
            aria-describedby={describedBy}
            {oninput}
            {onkeydown}
            {onkeyup}
        >
        {#if suffix}
            <span class="wg-input-affix" aria-hidden="true">
                {@render suffix()}
            </span>
        {/if}
    </div>

    {#if error}
        <p class="wg-field-error" id="{id}-error">{error}</p>
    {:else if hint}
        <p class="wg-field-hint" id="{id}-hint">{hint}</p>
    {/if}
</div>

<style>
    .wg-field {
        display: flex;
        flex-direction: column;
        /* DESIGN.md: labels sit above with 4px separation */
        gap: var(--wg-space-xs);
        min-width: 0;
    }

    label {
        font: var(--wg-text-body-md);
        color: var(--wg-text-muted);
    }

    .wg-required {
        color: var(--wg-error);
    }

    .wg-input-shell {
        display: flex;
        align-items: center;
        gap: var(--wg-space-sm);
        height: var(--wg-control-height);
        padding: 0 var(--wg-space-sm);
        background: var(--wg-surface-sunken);
        /* border-strong: this boundary tells the operator where to type */
        border: var(--wg-border-width) solid var(--wg-border-strong);
        border-radius: var(--wg-radius-control);
        transition: border-color var(--wg-duration-fast) var(--wg-easing);
    }

    .wg-input-compact {
        height: var(--wg-control-height-compact);
    }

    .wg-input-shell:focus-within {
        border-color: var(--wg-primary);
        outline: var(--wg-focus-ring);
        outline-offset: var(--wg-focus-ring-offset);
    }

    .wg-input-invalid {
        border-color: var(--wg-error);
    }

    .wg-input-disabled {
        opacity: 0.45;
    }

    input {
        flex: 1 1 auto;
        min-width: 0;
        height: 100%;
        border: 0;
        background: none;
        color: var(--wg-text);
        font: var(--wg-text-body-md);
    }

    input:focus {
        /* the shell carries the ring */
        outline: none;
    }

    input::placeholder {
        color: var(--wg-text-subtle);
    }

    input:disabled {
        cursor: not-allowed;
    }

    .wg-mono-input {
        font-family: var(--wg-font-mono);
        font-variant-numeric: tabular-nums;
    }

    .wg-input-affix {
        display: inline-flex;
        align-items: center;
        color: var(--wg-text-subtle);
        flex: none;
    }

    .wg-field-error,
    .wg-field-hint {
        margin: 0;
        font: var(--wg-text-label-sm);
    }

    .wg-field-error {
        color: var(--wg-error);
    }

    .wg-field-hint {
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
