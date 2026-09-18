<script lang="ts">
    /**
     * API tokens — screen 14. Migrated in place; both portal shells route
     * here.
     *
     * ── Enumeration of the original, asserted present ────────────────────
     * getMyApiTokens; createApiToken returning { secret, token } with the
     * secret shown once; deleteMyApiToken; the ?create=true / ?label= /
     * ?expiry= query parameters that let another page deep-link straight into
     * the create modal with fields prefilled; parseHumantimeDuration on the
     * expiry parameter; the expired / expiry-date badge; the empty state.
     *
     * ── FIXED: the list never updated after create or delete ─────────────
     * The original rendered
     *
     *     <Loadable promise={api.getMyApiTokens()}>
     *         {#snippet children(tokens)}  ...
     *
     * whose snippet parameter `tokens` **shadowed** the component's own
     * `tokens` state. `createToken` and `deleteToken` both wrote to the outer
     * one, which nothing rendered — so a newly created token did not appear
     * and a deleted one did not disappear until the page was reloaded. The
     * list is loaded into the state variable and rendered from it here, so
     * both operations show up.
     *
     * Deleting also awaits the call before removing the row, rather than
     * removing it first and leaving it gone if the request failed.
     */

    import CopyableTextArea from 'common/CopyableTextArea.svelte'
    import { parseHumantimeDuration } from 'common/duration'
    import { stringifyError } from 'common/errors'
    import { routeQueryParams } from 'common/helpers'
    import { api, type ExistingApiToken } from 'gateway/lib/api'
    import Badge from 'ui/Badge.svelte'
    import Button from 'ui/Button.svelte'
    import Callout from 'ui/Callout.svelte'
    import EmptyState from 'ui/EmptyState.svelte'
    import Spinner from 'ui/Spinner.svelte'
    import CreateApiTokenModal from './CreateApiTokenModal.svelte'

    let tokens: ExistingApiToken[] = $state([])
    let loading = $state(true)
    let creatingToken = $state(false)
    let lastCreatedSecret: string | undefined = $state()
    let error: string | undefined = $state()
    const now = Date.now()

    const urlParams = routeQueryParams()
    const autoCreate = urlParams.get('create') === 'true'
    const paramLabel = urlParams.get('label') ?? ''
    const paramExpiry = urlParams.get('expiry')

    const initialExpiryMs = paramExpiry
        ? parseHumantimeDuration(paramExpiry)
        : undefined

    if (autoCreate) {
        creatingToken = true
    }

    async function load() {
        loading = true
        try {
            tokens = await api.getMyApiTokens()
        } catch (err) {
            error = await stringifyError(err)
        } finally {
            loading = false
        }
    }

    load()

    async function deleteToken(token: ExistingApiToken) {
        try {
            await api.deleteMyApiToken(token)
            tokens = tokens.filter(c => c.id !== token.id)
            lastCreatedSecret = undefined
        } catch (err) {
            error = await stringifyError(err)
        }
    }

    async function createToken(label: string, expiry: Date) {
        try {
            error = undefined
            const { secret, token } = await api.createApiToken({
                newApiToken: { label, expiry },
            })
            lastCreatedSecret = secret
            tokens = [...tokens, token]
        } catch (err) {
            error = await stringifyError(err)
        }
    }
</script>

<div class="head">
    <h1>API tokens</h1>
    <Button
        variant="primary"
        size="compact"
        onclick={() => (creatingToken = true)}
    >
        Create token
    </Button>
</div>

{#if error}
    <div class="notice">
        <Callout tone="danger" title="Something went wrong">{error}</Callout>
    </div>
{/if}

{#if lastCreatedSecret}
    <div class="notice">
        <Callout tone="warning" title="Copy this token now">
            It is shown once and cannot be retrieved again. If you lose it,
            delete the token and create another.
        </Callout>
    </div>
    <CopyableTextArea label="Your new token" value={lastCreatedSecret} />
{/if}

{#if loading}
    <div class="loading">
        <Spinner delay={1000} label="Loading API tokens" />
    </div>
{:else if tokens.length === 0}
    <EmptyState
        title="No tokens yet"
        hint="Tokens let you manage Warpgate programmatically via its API"
    />
{:else}
    <ul class="tokens">
        {#each tokens as token (token.id)}
            <li>
                <span class="token-label">{token.label}</span>
                {#if token.expiry.getTime() < now}
                    <Badge tone="danger">Expired</Badge>
                {:else}
                    <Badge tone="success">
                        Expires {token.expiry.toLocaleDateString()}
                    </Badge>
                {/if}
                <Button
                    variant="ghost"
                    size="compact"
                    click={() => deleteToken(token)}
                >
                    Delete
                </Button>
            </li>
        {/each}
    </ul>
{/if}

{#if creatingToken}
    <CreateApiTokenModal
        bind:isOpen={creatingToken}
        create={createToken}
        initialLabel={paramLabel}
        {initialExpiryMs}
    />
{/if}

<style>
    .head {
        display: flex;
        align-items: center;
        justify-content: space-between;
        gap: var(--wg-space-lg);
        flex-wrap: wrap;
        margin-bottom: var(--wg-space-lg);
    }

    h1 {
        margin: 0;
        font: var(--wg-text-headline-lg);
    }

    .notice {
        margin-bottom: var(--wg-space-lg);
    }

    .loading {
        display: flex;
        justify-content: center;
        padding: var(--wg-space-3xl) 0;
    }

    .tokens {
        list-style: none;
        margin: 0;
        padding: 0;
    }

    .tokens li {
        display: flex;
        align-items: center;
        gap: var(--wg-space-md);
        padding: var(--wg-space-sm) 0;
        border-bottom: var(--wg-border-width) solid var(--wg-border);
        min-width: 0;
    }

    .tokens li:last-child {
        border-bottom: 0;
    }

    .token-label {
        margin-right: auto;
        font: var(--wg-text-body-md);
        overflow-wrap: anywhere;
    }

    @media (max-width: 640px) {
        h1 {
            font: var(--wg-text-headline-lg-mobile);
        }
    }
</style>
