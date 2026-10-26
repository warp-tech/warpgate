<script lang="ts">
    import { Alert } from '@sveltestrap/sveltestrap'
    import { api, type TargetOptionsTargetOracleOptions } from 'admin/lib/api'
    import AsyncButton from 'common/AsyncButton.svelte'
    import { stringifyError } from 'common/errors'

    interface Props {
        id: string
        options: TargetOptionsTargetOracleOptions
    }

    let { id, options }: Props = $props()

    type Result =
        | { state: 'ok'; message: string }
        | { state: 'error'; error: string }

    let result: Result | null = $state(null)

    $effect(() => {
        // Reset when the target is re-saved: host/port/service/credentials may
        // have changed, so a previous result no longer describes the target.
        options
        result = null
    })

    async function testConnection() {
        result = null
        try {
            const response = await api.testOracleConnection({
                testOracleConnectionRequest: { targetId: id },
            })
            result = { state: 'ok', message: response.message }
        } catch (err) {
            result = { state: 'error', error: await stringifyError(err) }
        }
    }
</script>

<div class="d-flex oracle-test-connection">
    {#if result?.state === 'ok'}
        <Alert color="success">{result.message}</Alert>
    {/if}

    {#if result?.state === 'error'}
        <Alert color="danger">{result.error}</Alert>
    {/if}

    <div class="buttons">
        <AsyncButton color="secondary" click={testConnection}>
            Test connection
        </AsyncButton>
    </div>
</div>

<style lang="scss">
    .oracle-test-connection {
        .buttons {
            display: flex;
            flex-direction: column;
            align-items: stretch;
            flex-shrink: 0;
            margin-left: 0.5rem;

            :global(.btn) {
                flex: 1 0 auto;
            }
        }
    }

    :global(.alert) {
        min-width: 0;
        flex-grow: 1;
        padding-top: 0.5rem;
        padding-bottom: 0.5rem;
        margin-bottom: 0;
    }
</style>
