<script lang="ts">
    import { api, ApiAuthState, type AuthStateResponseInternal } from 'gateway/lib/api'
    import AsyncButton from 'common/AsyncButton.svelte'
    import RelativeDate from 'admin/RelativeDate.svelte'
    import Alert from 'common/sveltestrap-s5-ports/Alert.svelte'
    import Loadable from 'common/Loadable.svelte'

    interface Props {
        params: { stateId: string };
    }

    let { params }: Props = $props()

    let authState: AuthStateResponseInternal | undefined = $state()

    async function reload () {
        authState = await api.getAuthState({ id: params.stateId })
    }

    async function init () {
        await reload()
    }

    async function approve () {
        api.approveAuth({ id: params.stateId })
        await reload()
        window.close()
    }

    async function reject () {
        api.rejectAuth({ id: params.stateId })
        await reload()
        window.close()
    }
</script>

<style lang="scss">
    .identification-string {
        display: flex;
        font-size: 3rem;

        .card {
            padding: 0rem 0.5rem;
            border-radius: .5rem;
            margin-right: .5rem;
        }
    }
</style>

<Loadable promise={init()}>
{#if authState}
    <div class="page-summary-bar">
        <h1>authorization request</h1>
    </div>

    <div class="mb-5">
        <div class="mb-2">Ensure this security key matches your authentication prompt:</div>
        <div class="identification-string">
            {#each authState?.identificationString as char}
                <div class="card bg-secondary text-light">
                    <div class="card-body">{char}</div>
                </div>
            {/each}
        </div>    </div>

    <div class="mb-3">
        <div>
            Authorize this {authState.protocol} session?
        </div>
        <small>
            Requested <RelativeDate date={authState.started} />
            {#if authState.address}from {authState.address}{/if}
        </small>
    </div>

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
                color="secondary"
                class="d-flex align-items-center ms-2"
                click={reject}
            >
                Reject
            </AsyncButton>
        </div>
    {/if}
{/if}
</Loadable>
