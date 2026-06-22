<script lang="ts">
    import type { Snippet } from 'svelte'

    interface Props {
        class?: string
        start?: Snippet
        end?: Snippet
        children?: Snippet
    }

    const props: Props = $props()
</script>

<div class="sticky-action-bar {props.class ?? ''}">
    <div class="sticky-action-bar-start">
        {@render props.start?.()}
    </div>
    <div class="sticky-action-bar-content">
        {@render props.children?.()}
    </div>
    <div class="sticky-action-bar-end">
        {@render props.end?.()}
    </div>
</div>

<style>
    .sticky-action-bar {
        display: flex;
        align-items: center;
        gap: 0.5rem;
        padding: 1rem 0;
        border-top: 1px solid var(--bs-border-color);
        background: var(--bs-body-bg);
        position: sticky;
        bottom: 0;
        z-index: 5;
    }

    .sticky-action-bar-start,
    .sticky-action-bar-content,
    .sticky-action-bar-end {
        display: flex;
        align-items: center;
        gap: 0.5rem;
    }

    .sticky-action-bar-start {
        margin-right: auto;
    }
</style>
