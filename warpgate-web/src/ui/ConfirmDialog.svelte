<script lang="ts">
    /**
     * Destructive confirmation.
     *
     * NOTE: this is a NEW pattern, not an existing one. Every destructive flow
     * in the product today uses native `window.confirm()` — nine call sites,
     * all one Enter away from committing. Phase 4 migrates them here.
     *
     * Two modes:
     *   - default: a plain confirm/cancel dialog, same weight as the
     *     `confirm()` it replaces.
     *   - `confirmText` given: the operator must type that exact string before
     *     the destructive button enables. Reserved for actions reached without
     *     deliberate navigation — the command palette above all, where a fuzzy
     *     match plus Enter is the fastest mis-click path in the product.
     *
     * The typed name is compared exactly, not case-insensitively or trimmed at
     * the ends only: the point is to make the operator read the identifier of
     * the thing they are about to destroy, and a forgiving comparison defeats
     * that. Leading/trailing whitespace is forgiven because it comes from
     * paste, not from misreading.
     */
    import type { Snippet } from 'svelte'
    import Button from './Button.svelte'
    import Input from './Input.svelte'
    import Modal from './Modal.svelte'

    interface Props {
        open?: boolean
        title: string
        /** Label on the destructive button, e.g. "Delete target". */
        confirmLabel: string
        /** When set, this exact string must be typed to enable confirmation. */
        confirmText?: string
        /** What the operator types to confirm, e.g. "target name". */
        confirmTextLabel?: string
        onconfirm: () => unknown | Promise<unknown>
        oncancel?: () => void
        children?: Snippet
    }

    let {
        open = $bindable(false),
        title,
        confirmLabel,
        confirmText,
        confirmTextLabel = 'name',
        onconfirm,
        oncancel,
        children,
    }: Props = $props()

    let typed = $state('')

    const needsTyping = $derived(!!confirmText)
    const matches = $derived(!needsTyping || typed.trim() === confirmText)

    // Reset between openings, so a previous confirmation cannot leave the
    // button pre-armed for the next thing that reuses this dialog.
    $effect(() => {
        if (!open) {
            typed = ''
        }
    })

    function cancel() {
        open = false
        oncancel?.()
    }

    // Named runConfirm, not confirm: a local `confirm` shadows window.confirm
    // and makes the "no native dialogs left" audit grep unreadable.
    async function runConfirm() {
        if (!matches) {
            return
        }
        await onconfirm()
        open = false
    }
</script>

<Modal bind:open {title} size="sm" onclose={oncancel}>
    {#if children}
        {@render children()}
    {/if}

    {#if needsTyping}
        <p class="wg-confirm-prompt">
            Type <code>{confirmText}</code> to confirm.
        </p>
        <Input
            label="Confirm by typing the {confirmTextLabel}"
            labelHidden
            bind:value={typed}
            mono
            placeholder={confirmText}
            autocomplete="off"
        />
    {/if}

    {#snippet footer()}
        <Button onclick={cancel}>Cancel</Button>
        <Button variant="destructive" disabled={!matches} click={runConfirm}>
            {confirmLabel}
        </Button>
    {/snippet}
</Modal>

<style>
    .wg-confirm-prompt {
        margin: var(--wg-space-lg) 0 var(--wg-space-sm);
        font: var(--wg-text-body-md);
        color: var(--wg-text-muted);
    }

    code {
        font: var(--wg-text-code-md);
        color: var(--wg-text);
        padding: 0 var(--wg-space-xs);
        background: var(--wg-surface-sunken);
        border-radius: var(--wg-radius-sm);
    }
</style>
