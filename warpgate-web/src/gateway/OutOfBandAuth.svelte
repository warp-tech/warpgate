<script lang="ts">
import { Spinner } from 'sveltestrap'

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
    OOB auth for {authState.protocol}

    {#if authState.state === ApiAuthState.Success}
        Approved
    {:else if authState.state === ApiAuthState.Failed}
        Rejected
    {:else}
        <AsyncButton
            outline
            class="d-flex align-items-center"
            click={approve}
        >
            Approve
        </AsyncButton>
        <AsyncButton
            outline
            class="d-flex align-items-center"
            click={reject}
        >
            Reject
        </AsyncButton>
    {/if}
{/await}
