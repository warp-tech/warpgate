<script lang="ts">
    import { api } from 'admin/lib/api'
    import { stringifyError } from 'common/errors'
    import Callout from 'ui/Callout.svelte'

    interface Props {
        normal: boolean
    }

    let { normal }: Props = $props()

    let preview = $state<{ url: string; payload: string } | undefined>()
    let error = $state<string | undefined>()

    $effect(() => {
        load(normal)
    })

    async function load(n: boolean) {
        error = undefined
        try {
            preview = await api.getAnalyticsPreview({ normal: n })
        } catch (e) {
            error = await stringifyError(e)
        }
    }
</script>

{#if error}
    <Callout tone="danger" title="Could not load the preview">{error}</Callout>
{:else if preview}
    <p class="target">Sent as POST to <code>{preview.url}</code></p>
    <pre>{preview.payload}</pre>
{/if}

<style>
    .target {
        margin: 0 0 var(--wg-space-xs);
        font: var(--wg-text-label-sm);
        color: var(--wg-text-muted);
    }

    code {
        font: var(--wg-text-code-sm);
        color: var(--wg-text);
    }

    pre {
        margin: 0;
        padding: var(--wg-space-lg);
        background: var(--wg-surface-sunken);
        border: var(--wg-border-width) solid var(--wg-border);
        border-radius: var(--wg-radius-panel);
        font: var(--wg-text-code-sm);
        overflow-x: auto;
    }
</style>
