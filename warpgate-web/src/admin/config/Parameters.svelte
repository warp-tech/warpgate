<script lang="ts">
    import { FormGroup, Input } from '@sveltestrap/sveltestrap'
    import { api, type ParameterValues } from 'admin/lib/api'
    import Loadable from 'common/Loadable.svelte'
    import RateLimitInput from 'common/RateLimitInput.svelte'

    let parameters: ParameterValues | undefined = $state()
    const initPromise = init()

    async function init () {
        parameters = await api.getParameters({})
    }

    async function update() {
        api.updateParameters({
            parameterUpdate: parameters!,
        })
    }
</script>

<div class="page-summary-bar">
<h1>global parameters</h1>
</div>

<Loadable promise={initPromise}>
{#if parameters}
    <h4 class="mt-4">Credentials</h4>
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
                update()
            }}
            checked={parameters.allowOwnCredentialManagement} />
        <div>Allow users to manage their own credentials</div>
    </label>

    <h4 class="mt-4">Traffic</h4>
    <FormGroup floating label="Global bandwidth limit">
        <RateLimitInput
            bind:value={parameters.rateLimitBytesPerSecond}
            change={update}
            />
    </FormGroup>
{/if}
</Loadable>
