<script lang="ts">
import { Input } from '@sveltestrap/sveltestrap'
import { api, type ParameterValues } from 'admin/lib/api'
import Loadable from 'common/Loadable.svelte'

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

    <label
        for="globalRateLimit"
        class="d-flex align-items-center"
    >
        <Input
            id="globalRateLimit"
            class="mb-0 me-2"
            type="number"
            min="0"
            step="1"
            bind:value={parameters.rateLimitBytesPerSecond}
            on:change={update}
            />
    </label>
{/if}
</Loadable>
