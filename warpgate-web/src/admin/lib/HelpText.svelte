<script lang="ts">
    import type { Snippet } from 'svelte'

    interface Props {
        class?: string
        children?: Snippet
    }

    const props: Props = $props()
</script>

<small class="help-text {props.class ?? ''}">
    {@render props.children?.()}
</small>

<style>
    small {
        display: block;
        color: var(--wg-text-muted);
        line-height: 1.2;
        margin: var(--wg-space-sm) 0 var(--wg-space-xl) var(--wg-space-sm);
        padding-left: var(--wg-space-sm);
        border-left: 2px dotted var(--wg-border-strong);
    }
</style>
