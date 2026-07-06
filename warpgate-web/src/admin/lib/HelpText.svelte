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
        color: var(--bs-secondary-color);
        line-height: 1.2;
        margin: 0.5rem 0 1.5rem 0.5rem;
        padding-left: 0.5rem;

        border-left: 2px dashed rgba(var(--bs-secondary-color-rgb), 30%);
        border-left-style: dotted;
    }
</style>
