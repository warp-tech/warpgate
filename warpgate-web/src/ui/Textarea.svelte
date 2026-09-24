<script lang="ts">
    /**
     * Multi-line text field.
     *
     * Built when the mechanical fork check found byte-identical hand-rolled
     * textarea styling in two places — kubernetes/Options.svelte (screen 4f,
     * already committed) and PublicKeyCredentialModal.svelte — each with its
     * own label-wrapper div. Same omission as Callout: the Phase 2 primitive
     * set has no multi-line field, so every screen that needs one invents it.
     *
     * The API mirrors Input deliberately, so the two are interchangeable at a
     * call site and neither grows its own vocabulary: same label /
     * labelHidden / hint / error / invalid / required / mono / autofocus
     * semantics, same error-implies-invalid rule, same aria-describedby
     * wiring, same shell-carries-the-focus-ring arrangement.
     *
     * `mono` defaults to true here. Every multi-line field in Warpgate holds
     * machine text — PEM blocks, OpenSSH keys, YAML — and proportional type
     * makes those materially harder to proofread.
     */
    interface Props {
        value?: string
        label?: string
        /** Hides the label visually but keeps it for assistive tech. */
        labelHidden?: boolean
        placeholder?: string
        rows?: number
        disabled?: boolean
        readonly?: boolean
        required?: boolean
        invalid?: boolean
        /** Shown under the field and wired up via aria-describedby. */
        error?: string
        hint?: string
        /** Machine data — renders the value in the mono face. */
        mono?: boolean
        /** Off by default: these fields hold keys and config, not prose. */
        spellcheck?: boolean
        /** Lets the browser grow the box; 'vertical' matches the old markup. */
        resize?: 'vertical' | 'none' | 'both'
        id?: string
        name?: string
        /** See Input: focusTrap looks for [data-autofocus] on a real element. */
        autofocus?: boolean
        class?: string
        oninput?: (event: Event) => void
        onkeydown?: (event: KeyboardEvent) => void
        onpaste?: (event: ClipboardEvent) => void
    }

    let {
        // No fallback, for the same reason as ui/Input: the Kubernetes
        // options bind `options.auth.certificate` and `privateKey`, both
        // optional, and a fallback makes Svelte throw on undefined.
        value = $bindable(),
        label,
        labelHidden = false,
        placeholder,
        rows = 6,
        disabled = false,
        readonly = false,
        required = false,
        invalid = false,
        error,
        hint,
        mono = true,
        spellcheck = false,
        resize = 'vertical',
        id = `wg-textarea-${Math.random().toString(36).slice(2, 9)}`,
        name,
        autofocus = false,
        class: className = '',
        oninput,
        onkeydown,
        onpaste,
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
        class="wg-textarea-shell"
        class:wg-textarea-invalid={isInvalid}
        class:wg-textarea-disabled={disabled}
    >
        <textarea
            {id}
            {name}
            {rows}
            {placeholder}
            {disabled}
            {readonly}
            {required}
            {spellcheck}
            data-autofocus={autofocus ? '' : undefined}
            bind:value
            class:wg-mono-textarea={mono}
            style:resize
            aria-invalid={isInvalid || undefined}
            aria-describedby={describedBy}
            {oninput}
            {onkeydown}
            {onpaste}
        ></textarea>
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

    .wg-textarea-shell {
        display: flex;
        background: var(--wg-surface-sunken);
        /* border-strong: this boundary tells the operator where to type */
        border: var(--wg-border-width) solid var(--wg-border-strong);
        border-radius: var(--wg-radius-control);
        transition: border-color var(--wg-duration-fast) var(--wg-easing);
    }

    .wg-textarea-shell:focus-within {
        border-color: var(--wg-primary);
        outline: var(--wg-focus-ring);
        outline-offset: var(--wg-focus-ring-offset);
    }

    .wg-textarea-invalid {
        border-color: var(--wg-error);
    }

    .wg-textarea-disabled {
        opacity: 0.45;
    }

    textarea {
        flex: 1 1 auto;
        min-width: 0;
        padding: var(--wg-space-sm);
        border: 0;
        background: none;
        color: var(--wg-text);
        font: var(--wg-text-body-md);
    }

    textarea:focus {
        /* the shell carries the ring */
        outline: none;
    }

    textarea::placeholder {
        color: var(--wg-text-subtle);
    }

    textarea:disabled {
        cursor: not-allowed;
    }

    .wg-mono-textarea {
        font: var(--wg-text-code-sm);
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
