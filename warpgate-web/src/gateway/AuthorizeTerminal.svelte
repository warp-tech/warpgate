<script lang="ts">
    import { Alert } from '@sveltestrap/sveltestrap'
    import AsyncButton from 'common/AsyncButton.svelte'
    import { stringifyError } from 'common/errors'
    import { routeQueryParams } from 'common/helpers'
    import Loadable from 'common/Loadable.svelte'
    import { api } from 'gateway/lib/api'
    import { serverInfo } from 'gateway/lib/store'
    import {
        deliverResult,
        parseLoopbackRedirectUri,
        probeClient,
        sshKeyFingerprint,
        type TerminalAuthorizationResult,
    } from 'gateway/lib/terminalAuthorization'

    // ponytail: no server-side default, a year keeps re-authorization rare
    const DEFAULT_EXPIRY_SECONDS = 365 * 24 * 60 * 60
    // The server checks the cap against its own clock.
    const CLOCK_SKEW_MARGIN_SECONDS = 60

    const params = routeQueryParams()
    // Self-declared by whoever built the link - shown as such.
    const app = (params.get('app') ?? '').trim().slice(0, 64) || 'Terminal app'
    const requestState = params.get('state') ?? ''

    let redirectUri: URL | undefined
    let publicKey: string | undefined = $state()
    let fingerprint: string | undefined = $state()
    let busy = $state(false)
    let outcome: 'approved' | 'denied' | undefined = $state()
    let error: string | undefined = $state()

    let addsKey = $derived(
        !!publicKey && !!$serverInfo?.ownCredentialManagementAllowed,
    )

    async function init() {
        const uri = parseLoopbackRedirectUri(params.get('redirect_uri'))
        if (!requestState) {
            throw new Error('The request is missing its state parameter.')
        }
        const probe = await probeClient(uri, requestState)
        if (probe.publicKey) {
            fingerprint = await sshKeyFingerprint(probe.publicKey)
        }
        redirectUri = uri
        publicKey = probe.publicKey
    }

    // Not inline in the template: Loadable's prop would run it inside a
    // $derived, where writing state throws.
    const initPromise = init()

    async function finish(result: TerminalAuthorizationResult) {
        if (!redirectUri) {
            return
        }
        await deliverResult(redirectUri, requestState, result)
        outcome = 'error' in result ? result.error : 'approved'
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
        const maxSeconds = $serverInfo?.maxApiTokenDurationSeconds
        const expirySeconds = maxSeconds
            ? Math.min(
                  maxSeconds - CLOCK_SKEW_MARGIN_SECONDS,
                  DEFAULT_EXPIRY_SECONDS,
              )
            : DEFAULT_EXPIRY_SECONDS
        const { secret, token } = await api.createApiToken({
            newApiToken: {
                label: app,
                expiry: new Date(Date.now() + expirySeconds * 1000),
            },
        })

        let publicKeyId: string | undefined
        try {
            if (addsKey && publicKey) {
                publicKeyId = (
                    await api.addMyPublicKey({
                        newPublicKeyCredential: {
                            label: app,
                            opensshPublicKey: publicKey,
                        },
                    })
                ).id
            }
            await finish({
                token: secret,
                token_id: token.id,
                public_key_id: publicKeyId,
            })
        } catch (err) {
            // Don't leave credentials behind for a setup that didn't happen.
            const leftovers: string[] = []
            await api.deleteMyApiToken(token).catch(() => {
                leftovers.push(`API token “${app}”`)
            })
            if (publicKeyId) {
                await api.deleteMyPublicKey({ id: publicKeyId }).catch(() => {
                    leftovers.push(`SSH key “${app}”`)
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
        <h1>Connect {app}</h1>
    </div>

    {#if outcome === 'approved'}
        <Alert color="success">
            Done. You can close this tab and return to {app}.
        </Alert>
    {:else if outcome === 'denied'}
        <Alert color="secondary">Request denied. You can close this tab.</Alert>
    {:else}
        <p>
            An application calling itself <strong>{app}</strong> is asking to
            access Warpgate as <strong>{$serverInfo?.username}</strong>.
            Approving will:
        </p>
        <ul>
            <li>create an API token labelled “{app}” for your account</li>
            {#if addsKey}
                <li>
                    add an SSH key to your account
                    <div><code>{fingerprint}</code></div>
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
                click={() => guarded(() => finish({ error: 'denied' }))}
            >
                Deny
            </AsyncButton>
        </div>
    {/if}
</Loadable>
