<script lang="ts">
    import {
        faApple,
        faGoogle,
        faMicrosoft,
    } from '@fortawesome/free-brands-svg-icons'
    import { faArrowRight } from '@fortawesome/free-solid-svg-icons'
    import { Alert, Button, FormGroup } from '@sveltestrap/sveltestrap'
    import { stringifyError } from 'common/errors'
    import { navigateToExternalUrl, routeQueryParams } from 'common/helpers'
    import Loadable from 'common/Loadable.svelte'

    import {
        ApiAuthState,
        api,
        LoginFailureResponseFromJSON,
        PasswordLoginMode,
        ResponseError,
        type SsoProviderDescription,
        SsoProviderKind,
    } from 'gateway/lib/api'
    import { reloadServerInfo, serverInfo } from 'gateway/lib/store'
    import Fa from 'svelte-fa'
    import { replace } from 'svelte-spa-router'

    let error: string | null = $state(null)
    let username = $state('')
    let password = $state('')
    let otp = $state('')
    let busy = $state(false)
    let webauthnBusy = $state(false)
    let credentialRejected = $state(false)
    let otpInput: HTMLInputElement | undefined = $state()
    let authState: ApiAuthState | undefined = $state()
    let ssoProvidersPromise = api.getSsoProviders()
    let showPasswordLogin = $state(false)

    const passwordLoginMode = $derived(
        $serverInfo?.passwordLoginMode ?? PasswordLoginMode.Enabled,
    )
    const passwordLoginAllowed = $derived(
        passwordLoginMode !== PasswordLoginMode.Disabled,
    )
    const passwordLoginMinimized = $derived(
        passwordLoginMode === PasswordLoginMode.Minimized,
    )

    const urlParams = routeQueryParams()
    const nextURL = urlParams.get('next') ?? undefined
    const reauthRequired = urlParams.get('reauth') === '1'
    const serverErrorMessage = new URLSearchParams(location.search).get(
        'login_error',
    )
    const initPromise = init()

    async function init() {
        try {
            authState = (await api.getDefaultAuthState()).state
        } catch (err) {
            if (err instanceof ResponseError) {
                if (err.response.status === 404) {
                    authState = ApiAuthState.NotStarted
                }
            } else {
                throw err
            }
        }
        await continueWithState()
    }

    function sanitizeRedirect(url: string): string | undefined {
        try {
            const resolved = new URL(url, location.origin)
            return resolved.origin === location.origin
                ? resolved.href
                : undefined
        } catch {
            return undefined
        }
    }

    function success() {
        const target = nextURL ? sanitizeRedirect(nextURL) : undefined
        if (target) {
            location.assign(target)
        } else {
            replace('/')
        }
    }

    async function continueWithState({ allowSsoRedirect = true } = {}) {
        if (authState === ApiAuthState.Success) {
            success()
        }
        if (authState === ApiAuthState.SsoNeeded && allowSsoRedirect) {
            const providers = await ssoProvidersPromise
            if (providers.length === 1) {
                // biome-ignore lint/style/noNonNullAssertion: length checked above
                startSSO(providers[0]!)
            }
        }
        if (authState === ApiAuthState.OtpNeeded) {
            setTimeout(() => {
                otpInput?.focus()
            })
        }
        if (authState === ApiAuthState.WebAuthnNeeded) {
            // Auto-start the WebAuthn ceremony
            doWebauthn()
        }
    }

    async function login() {
        busy = true
        try {
            await _login()
        } finally {
            busy = false
        }
    }

    async function _login() {
        error = null
        credentialRejected = false
        try {
            if (authState === ApiAuthState.OtpNeeded) {
                await api.otpLogin({
                    otpLoginRequest: {
                        otp,
                    },
                })
            } else {
                await api.login({
                    loginRequest: {
                        username,
                        password,
                    },
                })
            }
            await reloadServerInfo()
            success()
        } catch (err) {
            if (err instanceof ResponseError) {
                if (err.response.status === 401) {
                    const failure = LoginFailureResponseFromJSON(
                        await err.response.json(),
                    )
                    authState = failure.state
                    credentialRejected = failure.credentialRejected ?? false

                    // Don't auto-advance to another auth method (e.g. SSO) when
                    // the submitted credential was rejected — show the error and
                    // let the user retry or pick a method themselves.
                    continueWithState({ allowSsoRedirect: !credentialRejected })
                } else {
                    error = await err.response.text()
                }
            } else {
                error = await stringifyError(err)
            }
        }
    }

    async function cancel() {
        await api.cancelDefaultAuth()
        location.reload()
    }

    async function startSSO(provider: SsoProviderDescription) {
        busy = true
        try {
            const p = await api.startSso({ name: provider.name, next: nextURL })
            navigateToExternalUrl(p.url)
        } catch (err) {
            error = await stringifyError(err)
            busy = false
        }
    }

    async function doWebauthn() {
        webauthnBusy = true
        error = null
        try {
            // Start authentication ceremony (generates a fresh challenge)
            const startResp = await api.startWebauthnAuthentication()
            const challengeOptions = JSON.parse(startResp.challengeJson)

            // Call the browser's WebAuthn API
            let credential: PublicKeyCredential | null
            try {
                credential = (await navigator.credentials.get({
                    publicKey: {
                        ...challengeOptions.publicKey,
                        challenge: base64UrlToBuffer(
                            challengeOptions.publicKey.challenge,
                        ),
                        allowCredentials: (
                            challengeOptions.publicKey.allowCredentials ?? []
                        ).map((c: { id: string }) => ({
                            ...c,
                            id: base64UrlToBuffer(c.id),
                        })),
                    },
                })) as PublicKeyCredential | null
            } catch (domErr: unknown) {
                // User cancelled or timed out — allow retry without error
                if (
                    domErr instanceof DOMException &&
                    domErr.name === 'NotAllowedError'
                ) {
                    error = null
                    return
                }
                throw domErr
            }

            if (!credential) {
                // Cancelled — allow retry
                return
            }

            const response =
                credential.response as AuthenticatorAssertionResponse
            const credentialJson = JSON.stringify({
                id: credential.id,
                rawId: bufferToBase64Url(credential.rawId),
                type: credential.type,
                response: {
                    authenticatorData: bufferToBase64Url(
                        response.authenticatorData,
                    ),
                    clientDataJSON: bufferToBase64Url(response.clientDataJSON),
                    signature: bufferToBase64Url(response.signature),
                    userHandle: response.userHandle
                        ? bufferToBase64Url(response.userHandle)
                        : null,
                },
            })

            await api.completeWebauthnAuthentication({
                authenticationCompleteRequest: {
                    credentialJson,
                },
            })

            // Check if auth is now complete
            try {
                const state = await api.getDefaultAuthState()
                authState = state.state
                if (authState === ApiAuthState.Success) {
                    await reloadServerInfo()
                    success()
                } else {
                    continueWithState()
                }
            } catch {
                await reloadServerInfo()
                success()
            }
        } catch (err) {
            error = await stringifyError(err)
        } finally {
            webauthnBusy = false
        }
    }

    function base64UrlToBuffer(base64url: string): ArrayBuffer {
        const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/')
        const padded = base64 + '='.repeat((4 - (base64.length % 4)) % 4)
        const binary = atob(padded)
        const bytes = new Uint8Array(binary.length)
        for (let i = 0; i < binary.length; i++) {
            bytes[i] = binary.charCodeAt(i)
        }
        return bytes.buffer
    }

    function bufferToBase64Url(buffer: ArrayBuffer): string {
        const bytes = new Uint8Array(buffer)
        let binary = ''
        for (const byte of bytes) {
            binary += String.fromCharCode(byte)
        }
        return btoa(binary)
            .replace(/\+/g, '-')
            .replace(/\//g, '_')
            .replace(/=/g, '')
    }
</script>

{#snippet localLoginForm()}
    <form
        autocomplete="on"
        onsubmit={e => {
        login()
        e.preventDefault()
    }}
    >
        <FormGroup floating label="Username">
            <!-- svelte-ignore a11y_autofocus -->
            <input
                bind:value={username}
                name="username"
                autocomplete="username"
                disabled={busy}
                class="form-control"
                required
                autofocus
            >
        </FormGroup>

        <FormGroup floating label="Password">
            <input
                bind:value={password}
                name="password"
                type="password"
                autocomplete="current-password"
                disabled={busy}
                required
                class="form-control"
            >
        </FormGroup>

        <Button
            class="d-flex align-items-center login-view-button"
            color="primary"
            type="submit"
            disabled={busy}
        >
            Log in
            <Fa class="ms-2" fw icon={faArrowRight} />
        </Button>
    </form>
{/snippet}

<Loadable promise={initPromise}>
    <div class="content">
        <div class="page-summary-bar">
            {#if authState === ApiAuthState.NotStarted || authState === ApiAuthState.Failed || authState === ApiAuthState.IpRejected}
                <h1>Welcome</h1>
            {:else}
                <h1>Continue login</h1>
            {/if}
        </div>
        {#if authState === ApiAuthState.OtpNeeded}
            <form
                class="d-flex align-items-stretch gap-2"
                onsubmit={e => {
                login()
                e.preventDefault()
            }}
            >
                <FormGroup floating label="One-time password" class="w-100">
                    <!-- svelte-ignore a11y_autofocus -->
                    <input
                        bind:value={otp}
                        bind:this={otpInput}
                        name="otp"
                        required
                        pattern="\d&lbrace;6,8&rbrace;"
                        autofocus
                        inputmode="numeric"
                        disabled={busy}
                        class="form-control"
                    >
                </FormGroup>

                <Button
                    class="mb-3"
                    color="primary"
                    type="submit"
                    disabled={busy}
                >
                    <Fa icon={faArrowRight} />
                </Button>
            </form>
        {/if}
        {#if authState === ApiAuthState.WebAuthnNeeded}
            <div class="text-center py-4">
                <p class="mb-3">Use your passkey or security key to continue</p>
                <Button
                    color="primary"
                    class="login-view-button"
                    disabled={webauthnBusy}
                    on:click={doWebauthn}
                >
                    {webauthnBusy ? 'Waiting...' : 'Authenticate'}
                </Button>
            </div>
        {/if}
        {#if (authState === ApiAuthState.NotStarted || authState === ApiAuthState.PasswordNeeded || authState === ApiAuthState.Failed || authState === ApiAuthState.IpRejected) && passwordLoginAllowed && (!passwordLoginMinimized || showPasswordLogin)}
            {@render localLoginForm()}
        {/if}

        {#if reauthRequired}
            <Alert class="mt-3" color="warning">
                The security policy requires you to sign in again before
                accessing this function.
            </Alert>
        {/if}
        {#if credentialRejected || authState === ApiAuthState.Failed}
            <Alert class="mt-3" color="danger">Incorrect credentials</Alert>
        {/if}
        {#if authState === ApiAuthState.IpRejected}
            <Alert class="mt-3" color="danger">
                Login denied: your IP address is not in the allowed range for
                this user
            </Alert>
        {/if}
        {#if serverErrorMessage}
            <Alert class="mt-3" color="danger">{serverErrorMessage}</Alert>
        {/if}
        {#if error}
            <Alert class="mt-3" color="danger">{error}</Alert>
        {/if}

        {#if authState === ApiAuthState.SsoNeeded || authState === ApiAuthState.NotStarted || authState === ApiAuthState.Failed || authState === ApiAuthState.IpRejected}
            <Loadable promise={ssoProvidersPromise}>
                {#snippet children(ssoProviders)}
                    {#if ssoProviders.length && passwordLoginAllowed && !(passwordLoginMinimized && !showPasswordLogin)}
                        <div class="sso-separator"></div>
                    {/if}
                    <div class="sso-buttons">
                        {#each ssoProviders as ssoProvider (ssoProvider.name)}
                            <button
                                type="button"
                                class="btn btn-secondary login-view-button"
                                disabled={busy}
                                onclick={() => startSSO(ssoProvider)}
                            >
                                {#if ssoProvider.kind === SsoProviderKind.Google}
                                    <Fa fw class="me-2" icon={faGoogle} />
                                {/if}
                                {#if ssoProvider.kind === SsoProviderKind.Azure}
                                    <Fa fw class="me-2" icon={faMicrosoft} />
                                {/if}
                                {#if ssoProvider.kind === SsoProviderKind.Apple}
                                    <Fa fw class="me-2" icon={faApple} />
                                {/if}
                                {ssoProvider.label || ssoProvider.name}
                            </button>
                        {/each}
                    </div>
                    {#if ssoProviders.length && passwordLoginAllowed && passwordLoginMinimized && !showPasswordLogin}
                        <div class="sso-separator"></div>
                    {/if}
                {/snippet}
            </Loadable>
        {/if}

        {#if (authState === ApiAuthState.NotStarted || authState === ApiAuthState.PasswordNeeded || authState === ApiAuthState.Failed || authState === ApiAuthState.IpRejected) && passwordLoginMinimized && !showPasswordLogin}
            <div class="text-center">
                <button
                    type="button"
                    class="btn btn-link"
                    onclick={() => showPasswordLogin = true}
                >
                    Password login
                </button>
            </div>
        {/if}

        {#if authState !== ApiAuthState.NotStarted && authState !== ApiAuthState.Failed && authState !== ApiAuthState.IpRejected}
            <button
                type="button"
                class="btn w-100 mt-3 btn-secondary login-view-button"
                onclick={cancel}
            >
                Cancel
            </button>
        {/if}
    </div>
</Loadable>

<style lang="scss">
    h1 {
        font-size: 3rem;
    }

    .sso-buttons {
        display: flex;
        flex-wrap: wrap;
        gap: 0.85rem 1rem;

        button {
            flex: 1 0 0;
            display: flex;
            align-items: center;
            justify-content: center;
            text-wrap: nowrap;
        }
    }

    .sso-separator {
        position: relative;
        text-align: center;
        margin: 1.5rem 0;
        font-style: italic;
        font-size: 0.75rem;
        opacity: 0.5;

        &::before {
            content: '';
            position: absolute;
            top: 50%;
            left: 0;
            right: 0;
            height: 1px;
            background-color: var(--bs-body-color);
            opacity: 0.5;
        }

        &::after {
            content: 'or';
            position: relative;
            display: inline-block;
            padding: 0 1rem;
            background-color: var(--bs-body-bg);
        }
    }

    :global(.login-view-button) {
        min-height: 45px;
    }

    .content {
        display: flex;
        flex-direction: column;
        justify-content: center;

        padding-bottom: 5rem;
        flex-grow: 1;
    }
</style>
