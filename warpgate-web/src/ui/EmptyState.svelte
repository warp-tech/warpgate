<script lang="ts">
    /**
     * Replaces common/EmptyState.svelte, which centres a 50%-width block at
     * `opacity: .5`. Two changes beyond the reskin:
     *
     *  - no blanket opacity. Dimming the whole block dims its action too, and
     *    an empty state whose only job is to get you to the next step should
     *    not make that step look disabled. Hierarchy comes from the ink tiers.
     *  - an optional action slot, because "no targets yet" is useless without
     *    "add one".
     */
    import type { Snippet } from 'svelte'

    interface Props {
        title: string
        hint?: string
        /** 'compact' fits inside a table body; 'page' stands alone. */
        size?: 'compact' | 'page'
        class?: string
        action?: Snippet
    }

    let {
        title,
        hint,
        size = 'page',
        class: className = '',
        action,
    }: Props = $props()
</script>

<div class="wg-empty wg-empty-{size} {className}">
    <p class="wg-empty-title">{title}</p>
    {#if hint}
        <p class="wg-empty-hint">{hint}</p>
    {/if}
    {#if action}
        <div class="wg-empty-action">
            {@render action()}
        </div>
    {/if}
</div>

<style>
    .wg-empty {
        display: flex;
        flex-direction: column;
        align-items: center;
        justify-content: center;
        text-align: center;
        gap: var(--wg-space-xs);
    }

    .wg-empty-page {
        padding: var(--wg-space-3xl) var(--wg-space-lg);
    }

    .wg-empty-compact {
        padding: var(--wg-space-xl) var(--wg-space-lg);
    }

    .wg-empty-title {
        margin: 0;
        font: var(--wg-text-headline-md);
        color: var(--wg-text);
    }

    .wg-empty-compact .wg-empty-title {
        font: var(--wg-text-body-lg);
    }

    .wg-empty-hint {
        margin: 0;
        max-width: 44ch;
        font: var(--wg-text-body-md);
        color: var(--wg-text-muted);
    }

    .wg-empty-action {
        margin-top: var(--wg-space-md);
    }
</style>
