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

<section
    data-section={props.id}
    data-section-title={props.title}
    class="sectioned-form-section {props.class ?? ''}"
    id={`${props.id}-heading`}
>
    {#if !props.hideHeading}
        <h4>{props.bodyTitle ?? props.title}</h4>
    {/if}
    {@render props.children?.()}
</section>

<style>
    section {
        /* Clears the sticky top bar plus the section-tab strip */
        scroll-margin-top: calc(var(--wg-topbar-height) + var(--wg-space-2xl));
    }

    .sectioned-form-section {
        margin: 0 0 var(--wg-space-3xl);
    }

    .sectioned-form-section h4 {
        margin: 0 0 var(--wg-space-lg);
        padding-bottom: var(--wg-space-sm);
        border-bottom: var(--wg-border-width) solid var(--wg-border);
        font: var(--wg-text-headline-md);
        color: var(--wg-text);
    }
</style>
