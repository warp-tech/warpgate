<script lang="ts" module>
    export interface SelectOption<T extends string | number = string> {
        value: T
        label: string
        disabled?: boolean
    }
</script>

<script lang="ts" generics="T extends string | number">
    interface Props {
        value?: T
        options: SelectOption<T>[]
        label?: string
        labelHidden?: boolean
        /** Shown as a disabled first option when value is unset. */
        placeholder?: string
        disabled?: boolean
        required?: boolean
        invalid?: boolean
        error?: string
        hint?: string
        id?: string
        name?: string
        size?: 'standard' | 'compact'
        class?: string
        onchange?: (event: Event) => void
    }

    let {
        value = $bindable(),
        options,
        label,
        labelHidden = false,
        placeholder,
        disabled = false,
        required = false,
        invalid = false,
        error,
        hint,
        id = `wg-select-${Math.random().toString(36).slice(2, 9)}`,
        name,
        size = 'standard',
        class: className = '',
        onchange,
    }: Props = $props()

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
        class="wg-select-shell wg-select-{size}"
        class:wg-select-invalid={isInvalid}
        class:wg-select-disabled={disabled}
    >
        <select
            {id}
            {name}
            {disabled}
            {required}
            bind:value
            aria-invalid={isInvalid || undefined}
            aria-describedby={describedBy}
            {onchange}
        >
            {#if placeholder}
                <option
                    value={undefined}
                    disabled
                    selected={value === undefined}
                >
                    {placeholder}
                </option>
            {/if}
            {#each options as option (option.value)}
                <option value={option.value} disabled={option.disabled}>
                    {option.label}
                </option>
            {/each}
        </select>
        <!-- Native arrow varies wildly across platforms; ours is consistent -->
        <svg
            class="wg-select-arrow"
            viewBox="0 0 12 12"
            width="12"
            height="12"
            aria-hidden="true"
        >
            <path
                d="M3 4.5L6 8l3-3.5"
                fill="none"
                stroke="currentColor"
                stroke-width="1.5"
                stroke-linecap="round"
                stroke-linejoin="round"
            />
        </svg>
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

    .wg-select-shell {
        position: relative;
        display: flex;
        align-items: center;
        height: var(--wg-control-height);
        background: var(--wg-surface-sunken);
        border: var(--wg-border-width) solid var(--wg-border-strong);
        border-radius: var(--wg-radius-control);
        transition: border-color var(--wg-duration-fast) var(--wg-easing);
    }

    .wg-select-compact {
        height: var(--wg-control-height-compact);
    }

    .wg-select-shell:focus-within {
        border-color: var(--wg-primary);
        outline: var(--wg-focus-ring);
        outline-offset: var(--wg-focus-ring-offset);
    }

    .wg-select-invalid {
        border-color: var(--wg-error);
    }

    .wg-select-disabled {
        opacity: 0.45;
    }

    select {
        flex: 1 1 auto;
        min-width: 0;
        height: 100%;
        /* room for the arrow */
        padding: 0 calc(var(--wg-space-lg) + var(--wg-space-sm)) 0
            var(--wg-space-sm);
        border: 0;
        background: none;
        color: var(--wg-text);
        font: var(--wg-text-body-md);
        appearance: none;
        cursor: pointer;
    }

    select:focus {
        outline: none;
    }

    select:disabled {
        cursor: not-allowed;
    }

    /* The dropdown list itself is OS-rendered, so it needs explicit colours
     * or it inherits the page's dark ground with the OS's light text. */
    select option {
        background: var(--wg-surface-container);
        color: var(--wg-text);
    }

    .wg-select-arrow {
        position: absolute;
        right: var(--wg-space-sm);
        pointer-events: none;
        color: var(--wg-text-muted);
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
