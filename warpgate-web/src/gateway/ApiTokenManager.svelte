<script lang="ts">
    import { api, type ExistingApiToken } from 'gateway/lib/api'
    import Loadable from 'common/Loadable.svelte'
    import { faKey } from '@fortawesome/free-solid-svg-icons'
    import Fa from 'svelte-fa'
    import CreateApiTokenModal from './CreateApiTokenModal.svelte'
    import Alert from 'common/sveltestrap-s5-ports/Alert.svelte'
    import CopyButton from 'common/CopyButton.svelte'
    import Badge from 'common/sveltestrap-s5-ports/Badge.svelte'
    import EmptyState from 'common/EmptyState.svelte'

    let tokens: ExistingApiToken[] = $state([])
    let creatingToken = $state(false)
    let lastCreatedSecret: string | undefined = $state()
    const now = Date.now()

    async function deleteToken (token: ExistingApiToken) {
        tokens = tokens.filter(c => c.id !== token.id)
        await api.deleteMyApiToken(token)
        lastCreatedSecret = undefined
    }

    async function createToken (label: string, expiry: Date) {
        const { secret, token } = await api.createApiToken({ newApiToken : { label, expiry } })
        lastCreatedSecret = secret
        tokens = [...tokens, token]
    }
</script>

<div class="page-summary-bar mt-4">
    <h1>API tokens</h1>
    <!-- svelte-ignore a11y_click_events_have_key_events -->
    <!-- svelte-ignore a11y_no_static_element_interactions -->
    <!-- svelte-ignore a11y_missing_attribute -->
    <a class="btn btn-primary ms-auto" onclick={e => {
        creatingToken = true
        e.preventDefault()
    }}>Create token</a>
</div>

{#if lastCreatedSecret}
<Alert color="info">
    <div>Your token - shown only once:</div>
    <div class="d-flex align-items-center mt-2">
        <code style="min-width: 0">{lastCreatedSecret}</code>
        <CopyButton class="ms-auto" text={lastCreatedSecret} />
    </div>
</Alert>
{/if}

<Loadable promise={api.getMyApiTokens()} bind:data={tokens}>
    {#if tokens.length === 0}
        <EmptyState
            title="No tokens yet"
            hint="Tokens let you manage Warpgate programmatically via its API"
        />
    {/if}

    <div class="list-group list-group-flush mb-3">
        {#each tokens as token (token.id)}
        <!-- svelte-ignore a11y_no_static_element_interactions -->
        <!-- svelte-ignore a11y_missing_attribute -->
        <div class="list-group-item d-flex align-items-center">
            <Fa fw icon={faKey} />
            <span class="label ms-3">{token.label}</span>
            {#if token.expiry.getTime() < now}
                <Badge color="danger" class="ms-2">Expired</Badge>
            {:else}
                <Badge color="success" class="ms-2">{token.expiry.toLocaleDateString()}</Badge>
            {/if}
            <span class="ms-auto"></span>
            <!-- svelte-ignore a11y_click_events_have_key_events -->
            <a
                color="link"
                class="ms-2"
                onclick={e => {
                    deleteToken(token)
                    e.preventDefault()
                }}
            >
                Delete
            </a>
        </div>
        {/each}
    </div>
</Loadable>

{#if creatingToken}
<CreateApiTokenModal
    bind:isOpen={creatingToken}
    create={createToken}
/>
{/if}
