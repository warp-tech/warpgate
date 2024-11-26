<script lang="ts">
    import { Input } from '@sveltestrap/sveltestrap'
    import { api, type ParameterValues } from 'admin/lib/api'
    import Alert from 'common/sveltestrap-s5-ports/Alert.svelte'
    import DelayedSpinner from 'common/DelayedSpinner.svelte'
    import { stringifyError } from 'common/errors'

    let parameters: ParameterValues | undefined = $state()
    let error: string|null = $state(null)

    async function load () {
        try {
            parameters = await api.getParameters({})
        } catch (err) {
            error = await stringifyError(err)
        }
    }

</script>

<div class="page-summary-bar">
    <h1>Global parameters</h1>
</div>

{#await load()}
    <DelayedSpinner />
{:then}
{#if parameters}
    <label
        for="allowOwnCredentialManagement"
        class="d-flex align-items-center"
    >
        <Input
            id="allowOwnCredentialManagement"
            class="mb-0 me-2"
            type="switch"
            on:change={() => {
                parameters!.allowOwnCredentialManagement = !parameters!.allowOwnCredentialManagement
                api.updateParameters({
                    parameterUpdate: {
                        allowOwnCredentialManagement: parameters!.allowOwnCredentialManagement,
                    },
                })
            }}
            checked={parameters.allowOwnCredentialManagement} />
        <div>Allow users to manage their own credentials</div>
    </label>
{/if}
{/await}

{#if error}
    <Alert color="danger">{error}</Alert>
{/if}
