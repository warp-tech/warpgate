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
        /**
         * Makes the badge a link. Pass a hash href ("#/config/users/1"): the
         * router is hash-based, so this navigates without svelte-spa-router's
         * `use:link` action, which a primitive cannot apply to a caller's
         * href. It also keeps middle-click and open-in-new-tab working.
         */
        href?: string
        id?: string
        class?: string
        children?: Snippet
    }

    let {
        tone = 'neutral',
        mono = false,
        href,
        id,
        class: className = '',
        children,
    }: Props = $props()
</script>

{#if href}
    <a
        {id}
        {href}
        class="wg-badge wg-badge-{tone} wg-badge-link {className}"
        class:wg-badge-mono={mono}
    >
        {@render children?.()}
    </a>
{:else}
    <span
        {id}
        class="wg-badge wg-badge-{tone} {className}"
        class:wg-badge-mono={mono}
    >
        {@render children?.()}
    </span>
{/if}

<style>
    .wg-badge-link {
        text-decoration: none;
        color: inherit;
    }

    .wg-badge-link:hover {
        text-decoration: underline;
    }

    .wg-badge-link:focus-visible {
        outline: var(--wg-focus-ring);
        outline-offset: var(--wg-focus-ring-offset);
    }

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
