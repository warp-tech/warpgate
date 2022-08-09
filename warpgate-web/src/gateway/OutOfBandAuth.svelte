<script lang="ts">
import { Alert, Spinner } from 'sveltestrap'

import { api, ApiAuthState, AuthStateResponseInternal } from 'gateway/lib/api'
import AsyncButton from 'common/AsyncButton.svelte'

export let params: { stateId: string }
let authState: AuthStateResponseInternal

async function reload () {
    authState = await api.getAuthState({ id: params.stateId })
}

async function init () {
    await reload()
}

async function approve () {
    api.approveAuth({ id: params.stateId })
    await reload()
}

async function reject () {
    api.rejectAuth({ id: params.stateId })
    await reload()
}
</script>

{#await init()}
    <Spinner />
{:then}
    <div class="page-summary-bar">
        <h1>Authorization request</h1>
    </div>

    <p>Authorize this {authState.protocol} session?</p>

    {#if authState.state === ApiAuthState.Success}
        <Alert color="success">
            Approved
        </Alert>
    {:else if authState.state === ApiAuthState.Failed}
        <Alert color="danger">
            Rejected
        </Alert>
    {:else}
        <div class="d-flex">
            <AsyncButton
                color="primary"
                class="d-flex align-items-center ms-auto"
                click={approve}
            >
                Authorize
            </AsyncButton>
            <AsyncButton
                outline
                color="secondary"
                class="d-flex align-items-center ms-2"
                click={reject}
            >
                Reject
            </AsyncButton>
        </div>
    {/if}
{/await}
