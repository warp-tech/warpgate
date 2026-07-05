<script lang="ts">
    import type { Snippet } from 'svelte'

    interface Props {
        id: string
        title: string
        bodyTitle?: string
        class?: string
        hideHeading?: boolean
        children?: Snippet
    }

    const props: Props = $props()
</script>

<section data-section={props.id} data-section-title={props.title} class="sectioned-form-section {props.class ?? ''}" id={`${props.id}-heading`}>
    {#if !props.hideHeading}
        <h4>{props.bodyTitle ?? props.title}</h4>
    {/if}
    {@render props.children?.()}
</section>

<style>
    section {
        scroll-margin-top: 50px;
    }

    .sectioned-form-section {
        margin: 0 0 3rem;
    }

    .sectioned-form-section:last-child {
        border-bottom: none;
    }

    .sectioned-form-section h4 {
        margin-top: 0;
        margin-bottom: 1rem;
    }
</style>
