<script lang="ts">
    import { Alert } from '@sveltestrap/sveltestrap'
    import { api } from 'admin/lib/api'
    import { stringifyError } from 'common/errors'

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
    <Alert color="danger">{error}</Alert>
{:else if preview}
    <div class="small text-secondary mb-1">
        Sent as POST to <code>{preview.url}</code>
    </div>
    <pre class="border rounded">{preview.payload}</pre>
{/if}

<style lang="scss">
    pre {
        font-size: 0.75rem;
        margin: 0;
        padding: 1rem;
    }
</style>
