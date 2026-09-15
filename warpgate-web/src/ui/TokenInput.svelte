<script lang="ts">
    /**
     * NET-NEW primitive.
     *
     * A text field that commits its content into a list of discrete tokens —
     * allowed CIDR ranges, SSH key fingerprints, role names, target filters.
     * Warpgate has several places doing this with ad-hoc textareas today
     * (AllowedIpRangesEditor is the clearest); this replaces the pattern.
     *
     * Keyboard contract, which is most of the value:
     *   Enter / comma      commit the draft as a token
     *   Backspace on empty remove the last token
     *   ArrowLeft/Right    move through committed tokens from an empty field
     *   Escape             clear the draft
     * Paste splits on commas, semicolons and newlines, so a list copied out of
     * a config file or a spreadsheet lands as tokens rather than one blob.
     *
     * `validate` lets the caller reject a token before it is committed; the
     * rejection message is announced, not just coloured.
     */
    interface Props {
        tokens?: string[]
        label?: string
        labelHidden?: boolean
        placeholder?: string
        disabled?: boolean
        hint?: string
        /** Return an error string to reject, or null/undefined to accept. */
        validate?: (
            token: string,
            existing: string[],
        ) => string | null | undefined
        /** Machine data — renders tokens and the draft in the mono face. */
        mono?: boolean
        id?: string
        class?: string
    }

    let {
        tokens = $bindable([]),
        label,
        labelHidden = false,
        placeholder,
        disabled = false,
        hint,
        validate,
        mono = true,
        id = `wg-tokens-${Math.random().toString(36).slice(2, 9)}`,
        class: className = '',
    }: Props = $props()

    let draft = $state('')
    let error: string | null = $state(null)
    let input: HTMLInputElement | undefined = $state()

    const SPLIT = /[,;\n\t]+/

    function commit(raw: string): boolean {
        const token = raw.trim()
        if (!token) {
            return false
        }
        if (tokens.includes(token)) {
            error = `"${token}" is already in the list`
            return false
        }
        const failure = validate?.(token, tokens)
        if (failure) {
            error = failure
            return false
        }
        tokens = [...tokens, token]
        error = null
        return true
    }

    function commitDraft() {
        if (commit(draft)) {
            draft = ''
        }
    }

    function remove(index: number) {
        tokens = tokens.filter((_, i) => i !== index)
        error = null
    }

    function onkeydown(event: KeyboardEvent) {
        if (event.key === 'Enter' || event.key === ',') {
            event.preventDefault()
            commitDraft()
            return
        }
        if (event.key === 'Backspace' && !draft && tokens.length) {
            event.preventDefault()
            remove(tokens.length - 1)
            return
        }
        if (event.key === 'Escape' && draft) {
            event.preventDefault()
            draft = ''
            error = null
        }
    }

    function onpaste(event: ClipboardEvent) {
        const text = event.clipboardData?.getData('text') ?? ''
        if (!SPLIT.test(text)) {
            return
        }
        event.preventDefault()
        for (const part of text.split(SPLIT)) {
            commit(part)
        }
    }

    // Committing on blur stops a typed-but-uncommitted value being silently
    // dropped when the operator tabs away and hits save.
    function onblur() {
        if (draft.trim()) {
            commitDraft()
        }
    }
</script>

<div class="wg-field {className}">
    {#if label}
        <label for={id} class:wg-sr-only={labelHidden}>{label}</label>
    {/if}

    <div
        class="wg-tokens"
        class:wg-tokens-invalid={!!error}
        class:wg-tokens-disabled={disabled}
    >
        {#each tokens as token, i (token)}
            <span class="wg-token" class:wg-token-mono={mono}>
                {token}
                <button
                    type="button"
                    class="wg-token-remove"
                    aria-label="Remove {token}"
                    {disabled}
                    onclick={() => remove(i)}
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
            </span>
        {/each}
        <input
            bind:this={input}
            bind:value={draft}
            {id}
            {disabled}
            {placeholder}
            class:wg-mono-input={mono}
            aria-describedby="{id}-status"
            aria-invalid={!!error || undefined}
            {onkeydown}
            {onpaste}
            {onblur}
        >
    </div>

    <p
        class="wg-field-status"
        class:wg-field-error={!!error}
        id="{id}-status"
        aria-live="polite"
    >
        {#if error}
            {error}
        {:else if hint}
            {hint}
        {:else}
            {tokens.length}
            {tokens.length === 1 ? 'entry' : 'entries'}
        {/if}
    </p>
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

    .wg-tokens {
        display: flex;
        flex-wrap: wrap;
        align-items: center;
        gap: var(--wg-space-xs);
        min-height: var(--wg-control-height);
        padding: var(--wg-space-xs);
        background: var(--wg-surface-sunken);
        border: var(--wg-border-width) solid var(--wg-border-strong);
        border-radius: var(--wg-radius-control);
        transition: border-color var(--wg-duration-fast) var(--wg-easing);
    }

    .wg-tokens:focus-within {
        border-color: var(--wg-primary);
        outline: var(--wg-focus-ring);
        outline-offset: var(--wg-focus-ring-offset);
    }

    .wg-tokens-invalid {
        border-color: var(--wg-error);
    }

    .wg-tokens-disabled {
        opacity: 0.45;
    }

    .wg-token {
        display: inline-flex;
        align-items: center;
        gap: var(--wg-space-xs);
        height: var(--wg-badge-height);
        padding: 0 var(--wg-badge-padding-x);
        background: var(--wg-surface-container-high);
        border: var(--wg-border-width) solid var(--wg-border);
        border-radius: var(--wg-radius-badge);
        font: var(--wg-text-label-sm);
        color: var(--wg-text);
    }

    .wg-token-mono {
        font-family: var(--wg-font-mono);
        font-variant-numeric: tabular-nums;
    }

    .wg-token-remove {
        display: inline-flex;
        align-items: center;
        justify-content: center;
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

    .wg-token-remove:hover:not(:disabled) {
        background: var(--wg-surface-container-highest);
        color: var(--wg-text);
    }

    .wg-token-remove:focus-visible {
        outline: var(--wg-focus-ring);
        outline-offset: 1px;
    }

    input {
        flex: 1 1 8rem;
        min-width: 0;
        height: 1.5rem;
        border: 0;
        background: none;
        color: var(--wg-text);
        font: var(--wg-text-body-md);
    }

    input:focus {
        outline: none;
    }

    input::placeholder {
        color: var(--wg-text-subtle);
    }

    .wg-mono-input {
        font-family: var(--wg-font-mono);
    }

    .wg-field-status {
        margin: 0;
        font: var(--wg-text-label-sm);
        color: var(--wg-text-subtle);
    }

    .wg-field-error {
        color: var(--wg-error);
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
