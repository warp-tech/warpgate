<script lang="ts">
    import type { Snippet } from 'svelte'

    interface Props {
        title: string
        class?: string
        children?: Snippet
    }

    const props: Props = $props()
</script>

<div class="subsection {props.class ?? ''}">
    <div class="heading">{props.title}</div>
    <p>
        {@render props.children?.()}
    </p>
</div>

<style>
    .subsection {
        margin-bottom: 1.5rem;
    }

    /* Sentence case. DESIGN.md prohibits all-caps outright, and this heading
     * was the last text-transform: uppercase left in the codebase. */
    .heading {
        display: block;
        font: var(--wg-text-label-md);
        color: var(--wg-text-muted);
        margin: var(--wg-space-lg) 0 var(--wg-space-sm);
    }
</style>
