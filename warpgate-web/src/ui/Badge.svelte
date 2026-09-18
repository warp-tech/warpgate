<script lang="ts" module>
    export type BadgeTone =
        | 'neutral'
        | 'primary'
        | 'success'
        | 'warning'
        | 'danger'
</script>

<script lang="ts">
    import type { Snippet } from 'svelte'

    interface Props {
        tone?: BadgeTone
        /** Machine data — renders the label in the mono face. */
        mono?: boolean
        id?: string
        class?: string
        children?: Snippet
    }

    let {
        tone = 'neutral',
        mono = false,
        id,
        class: className = '',
        children,
    }: Props = $props()
</script>

<span
    {id}
    class="wg-badge wg-badge-{tone} {className}"
    class:wg-badge-mono={mono}
>
    {@render children?.()}
</span>

<style>
    /*
     * Colour accents sit on the border and the text, never the fill. DESIGN.md
     * keeps badge backgrounds subdued so that a row of them does not turn a
     * table into a colour chart — the accent is enough to sort them by eye.
     */
    .wg-badge {
        display: inline-flex;
        align-items: center;
        height: var(--wg-badge-height);
        padding: 0 var(--wg-badge-padding-x);
        border: var(--wg-border-width) solid var(--wg-border);
        border-radius: var(--wg-radius-badge);
        background: var(--wg-surface-container);
        font: var(--wg-text-label-sm);
        color: var(--wg-text);
        white-space: nowrap;
    }

    .wg-badge-mono {
        font-family: var(--wg-font-mono);
        font-variant-numeric: tabular-nums;
    }

    .wg-badge-primary {
        border-color: var(--wg-primary);
        color: var(--wg-primary);
    }

    .wg-badge-success {
        border-color: var(--wg-tertiary);
        color: var(--wg-tertiary);
    }

    .wg-badge-warning {
        border-color: var(--wg-secondary);
        color: var(--wg-secondary);
    }

    .wg-badge-danger {
        border-color: var(--wg-error);
        color: var(--wg-error);
    }
</style>
