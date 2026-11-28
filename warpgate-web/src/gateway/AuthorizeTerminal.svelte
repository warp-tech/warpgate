<script lang="ts">
    import { Alert } from '@sveltestrap/sveltestrap'
    import { hasAdminAccess } from 'admin/lib/store'
    import AsyncButton from 'common/AsyncButton.svelte'
    import { stringifyError } from 'common/errors'
    import { routeQueryParams } from 'common/helpers'
    import InfoBox from 'common/InfoBox.svelte'
    import Loadable from 'common/Loadable.svelte'
    import { api } from 'gateway/lib/api'
    import { serverInfo } from 'gateway/lib/store'
    import {
        deliverResult,
        parseLoopbackRedirectUri,
        probeClient,
    } from 'gateway/lib/terminalAuthorization'

    const DEFAULT_EXPIRY_SECONDS = 365 * 24 * 60 * 60
    const CLOCK_SKEW_MARGIN_SECONDS = 300

    let appLabel = $state('')
    let requestState = $state('')

    let redirectUri: URL | undefined
    let clientAddress: string | undefined = $state()
    let publicKey: string | undefined = $state()
    let existingKey: { id: string; label: string } | undefined = $state()
    let busy = $state(false)
    let outcome: 'approved' | 'denied' | undefined = $state()
    let error: string | undefined = $state()

    let addsKey = $derived(
        !!publicKey && !!$serverInfo?.ownCredentialManagementAllowed,
    )

    let expirySeconds = $derived.by(() => {
        const max = $serverInfo?.maxApiTokenDurationSeconds
        if (!max) {
            return DEFAULT_EXPIRY_SECONDS
        }
        const margin = Math.min(CLOCK_SKEW_MARGIN_SECONDS, max / 10)
        return Math.min(DEFAULT_EXPIRY_SECONDS, Math.floor(max - margin))
    })

    let tokenScope = $derived(
        $hasAdminAccess
            ? 'full API access as you, including your admin permissions'
            : 'full API access as you',
    )

    let expiryLabel = $derived(
        new Date(Date.now() + expirySeconds * 1000).toLocaleString(),
    )

    async function init() {
        const params = routeQueryParams()
        appLabel = (params.get('app') ?? '').trim().slice(0, 64)
        if (!appLabel) {
            throw new Error('Missing `app` parameter')
        }
        requestState = params.get('state') ?? ''
        if (!requestState) {
            throw new Error('Missing `state` parameter')
        }
        const uri = parseLoopbackRedirectUri(params.get('redirect_uri'))
        const probe = await probeClient(uri, requestState)
        if (probe.publicKey && probe.publicKeyId) {
            if ($serverInfo?.ownCredentialManagementAllowed) {
                const credentials = await api.getMyCredentials()
                existingKey = credentials.publicKeys.find(
                    k => k.id === probe.publicKeyId,
                )
            }
        }
        redirectUri = uri
        clientAddress = uri.host
        publicKey = probe.publicKey
    }

    const initPromise = init()

    async function deny() {
        if (redirectUri) {
            await deliverResult(redirectUri, requestState, {
                error: 'denied',
            }).catch(() => undefined)
        }
        outcome = 'denied'
        window.close()
    }

    async function guarded(fn: () => Promise<void>) {
        if (busy) {
            return
        }
        busy = true
        error = undefined
        try {
            await fn()
        } catch (err) {
            error = await stringifyError(err)
            throw err
        } finally {
            busy = false
        }
    }

    async function approve() {
        const { secret, token } = await api.createApiToken({
            newApiToken: {
                label: appLabel,
                expiry: new Date(Date.now() + expirySeconds * 1000),
            },
        })

        let publicKeyId = existingKey?.id
        let addedKeyId: string | undefined
        try {
            if (addsKey && publicKey && !existingKey) {
                publicKeyId = (
                    await api.addMyPublicKey({
                        newPublicKeyCredential: {
                            label: appLabel,
                            opensshPublicKey: publicKey,
                        },
                    })
                ).id
                addedKeyId = publicKeyId
            }

            if (!redirectUri) {
                return
            }
            await deliverResult(redirectUri, requestState, {
                token: secret,
                token_id: token.id,
                public_key_id: publicKeyId,
            })

            outcome = 'approved'
            window.close()
        } catch (err) {
            // Don't leave credentials behind for a setup that didn't happen.
            const leftovers: string[] = []
            await api.deleteMyApiToken(token).catch(() => {
                leftovers.push(`API token “${appLabel}”`)
            })
            if (addedKeyId) {
                await api.deleteMyPublicKey({ id: addedKeyId }).catch(() => {
                    leftovers.push(`SSH key “${appLabel}”`)
                })
            }
            if (leftovers.length) {
                throw new Error(
                    `${await stringifyError(err)} Remove the ${leftovers.join(' and ')} from your profile.`,
                )
            }
            throw err
        }
    }
</script>

<Loadable promise={initPromise}>
    <div class="page-summary-bar">
        <h1>Connect a terminal</h1>
    </div>

    {#if outcome === 'approved'}
        <Alert color="success">
            Done. You can close this tab and return to {appLabel}.
        </Alert>
    {:else if outcome === 'denied'}
        <Alert color="secondary">Request denied. You can close this tab.</Alert>
    {:else}
        <InfoBox variant="warning">
            Only approve if you just started this from {appLabel} yourself.
        </InfoBox>
        <p>
            An application calling itself <code>{appLabel}</code>, listening at
            <code>{clientAddress}</code>
            on your computer, is asking to access Warpgate as
            <code>{$serverInfo?.username}</code>.
        </p>
        <p>Approving this will:</p>
        <ul>
            <li class="mb-2">
                create an API token labelled <code>{appLabel}</code> with
                {tokenScope}, valid until {expiryLabel}
            </li>
            {#if existingKey}
                <li>
                    keep using the SSH key “{existingKey.label}” already on your
                    account
                </li>
            {:else if addsKey}
                <li>
                    add a new SSH key to your account:
                    <pre class="mt-1">{publicKey}</pre>
                </li>
            {/if}
        </ul>

        {#if publicKey && !addsKey}
            <Alert color="warning">
                Your administrator does not allow managing your own credentials,
                so the SSH key can't be added.
            </Alert>
        {/if}

        {#if error}
            <Alert color="danger">{error}</Alert>
        {/if}

        <div class="d-flex">
            <div class="ms-auto"></div>
            <AsyncButton
                color="primary"
                disabled={busy}
                click={() => guarded(approve)}
            >
                Approve
            </AsyncButton>
            <AsyncButton
                color="secondary"
                class="ms-2"
                disabled={busy}
                click={() => guarded(deny)}
            >
                Deny
            </AsyncButton>
        </div>
    {/if}
</Loadable>
