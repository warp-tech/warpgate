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
        /**
         * Native validation pattern. The sign-in screen needs it: the
         * one-time-password field accepts 6 TO 8 digits, because recovery
         * codes are longer than TOTP codes, and dropping the pattern would
         * let a malformed code through to a network round trip.
         */
        pattern?: string
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
         * Focus this field on arrival. Emits BOTH the native `autofocus`
         * attribute and `data-autofocus`, because the two cover different
         * cases: focusTrap selects `[data-autofocus]` when a dialog opens,
         * and the native attribute is what focuses a field on a plain page,
         * where no focus trap exists. Emitting only the data attribute
         * silently does nothing outside a dialog.
         */
        autofocus?: boolean
        /**
         * The underlying element, for the rare caller that must focus or
         * measure it imperatively — the sign-in screen refocuses the
         * one-time-password field when the auth state changes, which is not
         * a mount and so cannot be expressed as an attribute.
         */
        inner?: HTMLInputElement
        class?: string
        oninput?: (event: Event) => void
        onkeydown?: (event: KeyboardEvent) => void
        onkeyup?: (event: KeyboardEvent) => void
        prefix?: Snippet
        suffix?: Snippet
    }

    let {
        // NO FALLBACK, deliberately. Svelte throws props_invalid_value for
        // `bind:value={x}` when x is undefined and the prop has one, and the
        // callers bind directly into API objects whose string fields are
        // optional — a target with no password has `password: undefined`.
        // Nothing here reads `value` except the binding below, and Svelte
        // renders undefined as an empty field.
        value = $bindable(),
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
        pattern,
        inputmode,
        size = 'standard',
        autofocus = false,
        inner = $bindable(),
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

<!--
  svelte-ignore a11y_autofocus

  Targeted, and only reachable when a caller explicitly opts in. Autofocus is
  a problem when it steals focus on a page the user did not come to in order
  to type; it is correct on a sign-in form and inside a dialog, which are the
  only places this prop is used. The alternative — every such caller reaching
  for `inner` and calling focus() in an effect — reintroduces the same
  behaviour with more code and no warning to review.
-->
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
            {pattern}
            {inputmode}
            data-autofocus={autofocus ? '' : undefined}
            autofocus={autofocus || undefined}
            bind:this={inner}
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
