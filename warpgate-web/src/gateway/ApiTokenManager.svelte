<script lang="ts">
    import { api, type ExistingApiToken } from 'gateway/lib/api'
    import Loadable from 'common/Loadable.svelte'
    import { stringifyError } from 'common/errors'
    import { faKey } from '@fortawesome/free-solid-svg-icons'
    import Fa from 'svelte-fa'
    import CreateApiTokenModal from './CreateApiTokenModal.svelte'
    import { Alert, Badge, Button } from '@sveltestrap/sveltestrap'
    import EmptyState from 'common/EmptyState.svelte'
    import { router } from 'svelte-spa-router'
    import { parseHumantimeDuration } from 'common/duration'
    import CopyableTextArea from 'common/CopyableTextArea.svelte'

    let tokens: ExistingApiToken[] = $state([])
    let creatingToken = $state(false)
    let lastCreatedSecret: string | undefined = $state()
    let error: string | undefined = $state()
    const now = Date.now()

    const urlParams = new URLSearchParams(router.querystring ?? '')
    const autoCreate = urlParams.get('create') === 'true'
    const paramLabel = urlParams.get('label') ?? ''
    const paramExpiry = urlParams.get('expiry')

    const initialExpiryMs = paramExpiry
        ? parseHumantimeDuration(paramExpiry)
        : undefined

    if (autoCreate) {
        creatingToken = true
    }

    async function deleteToken(token: ExistingApiToken) {
        tokens = tokens.filter(c => c.id !== token.id)
        await api.deleteMyApiToken(token)
        lastCreatedSecret = undefined
    }

    async function createToken(label: string, expiry: Date) {
        try {
            error = undefined
            const { secret, token } = await api.createApiToken({
                newApiToken: { label, expiry },
            })
            lastCreatedSecret = secret
            tokens = [...tokens, token]
        } catch (err: any) {
            error = await stringifyError(err)
        }
    }
</script>

<div class="page-summary-bar mt-4">
    <h1>API tokens</h1>
    <Button
        color="primary"
        class="ms-auto"
        onclick={e => {
        creatingToken = true
        e.preventDefault()
    }}
        >Create token</Button
    >
</div>

{#if error}
    <Alert color="danger">{error}</Alert>
{/if}

{#if lastCreatedSecret}
    <CopyableTextArea
        class="border-warning"
        label="Your new token (shown only once)"
        value={lastCreatedSecret}
    />
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
            <div class="list-group-item d-flex align-items-center pr-0">
                <Fa fw icon={faKey} />
                <span class="label ms-3">{token.label}</span>
                {#if token.expiry.getTime() < now}
                    <Badge color="danger" class="ms-2">Expired</Badge>
                {:else}
                    <Badge color="success" class="ms-2"
                        >{token.expiry.toLocaleDateString()}</Badge
                    >
                {/if}
                <span class="ms-auto"></span>
                <Button
                    color="link"
                    class="ms-2"
                    onclick={e => {
                    deleteToken(token)
                    e.preventDefault()
                }}
                >
                    Delete
                </Button>
            </div>
        {/each}
    </div>
</Loadable>

{#if creatingToken}
    <CreateApiTokenModal
        bind:isOpen={creatingToken}
        create={createToken}
        initialLabel={paramLabel}
        {initialExpiryMs}
    />
{/if}
