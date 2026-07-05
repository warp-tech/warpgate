<script lang="ts">
    import type { Snippet } from 'svelte'

    interface Props {
        title: string
        subtitle?: string
        class?: string
        extra?: Snippet
    }

    const props: Props = $props()
</script>

<div class="page-summary-bar {props.class ?? ''}">
    <div>
        <h1>{props.title}</h1>
        {#if props.subtitle}
            <div class="text-muted">{props.subtitle}</div>
        {/if}
    </div>
    {#if props.extra}
        <div class="page-summary-bar-extra">
            {@render props.extra()}
        </div>
    {/if}
</div>

<style>
    .page-summary-bar-extra {
        margin-left: auto;
    }
</style>
