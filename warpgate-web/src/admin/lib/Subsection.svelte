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

    .heading {
        display: block;
        font-size: 0.75rem;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 0.06em;
        color: var(--bs-secondary-color);
        margin: 1rem 0 0.5rem;
    }
</style>
