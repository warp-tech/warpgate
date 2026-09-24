<script lang="ts">
    /**
     * A read-only block of machine text with a copy button — screen 13,
     * chrome only.
     *
     * Behaviour preserved: the value renders verbatim with wrapping that
     * breaks anywhere (connection strings and PEM blocks have no spaces to
     * break at), and the copy button floats over the top-right corner.
     *
     * Changed: the copy button no longer overlaps the text. The original
     * cleared it with `padding-top: 35px !important` on the value, which
     * pushed every one-line value down by a line and a half and still
     * collided once the button had a label. The header row now owns the
     * label and the button, so nothing overlaps and no !important is needed.
     */
    import CopyButton from 'ui/CopyButton.svelte'

    interface Props {
        label: string
        value: string
        class?: string
    }

    let { label, value, class: className = '' }: Props = $props()
</script>

<div class="copyable {className}">
    <div class="copyable-head">
        <span class="copyable-label">{label}</span>
        <CopyButton text={value} size="compact" name="Copy {label}" />
    </div>
    <div class="copyable-text">{value}</div>
</div>

<style>
    .copyable {
        display: flex;
        flex-direction: column;
        gap: var(--wg-space-xs);
        margin-bottom: var(--wg-space-lg);
        min-width: 0;
    }

    .copyable-head {
        display: flex;
        align-items: center;
        justify-content: space-between;
        gap: var(--wg-space-sm);
    }

    .copyable-label {
        font: var(--wg-text-body-md);
        color: var(--wg-text-muted);
    }

    .copyable-text {
        padding: var(--wg-space-sm);
        background: var(--wg-surface-sunken);
        border: var(--wg-border-width) solid var(--wg-border);
        border-radius: var(--wg-radius-control);
        color: var(--wg-text);
        font: var(--wg-text-code-sm);
        white-space: pre-wrap;
        overflow-wrap: anywhere;
    }
</style>
