<script lang="ts">
    import {
        faApple,
        faGoogle,
        faMicrosoft,
    } from '@fortawesome/free-brands-svg-icons'
    import { faArrowRight } from '@fortawesome/free-solid-svg-icons'
    import { Alert, Button, FormGroup } from '@sveltestrap/sveltestrap'
    import { stringifyError } from 'common/errors'
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
    import { replace, router } from 'svelte-spa-router'

    let error: string | null = $state(null)
    let username = $state('')
    let password = $state('')
    let otp = $state('')
    let busy = $state(false)
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

    const nextURL =
        new URLSearchParams(router.querystring ?? '').get('next') ?? undefined
    const reauthRequired =
        new URLSearchParams(router.querystring ?? '').get('reauth') === '1'
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

    function success() {
        if (nextURL) {
            location.assign(nextURL)
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
            location.href = p.url
        } catch (err) {
            error = await stringifyError(err)
            busy = false
        }
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
            class="d-flex align-items-center"
            color="primary"
            type="submit"
            disabled={busy}
        >
            Login
            <Fa class="ms-2" fw icon={faArrowRight} />
        </Button>
    </form>
{/snippet}

<Loadable promise={initPromise}>
    <div class="mt-5">
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
        {#if (authState === ApiAuthState.NotStarted || authState === ApiAuthState.PasswordNeeded || authState === ApiAuthState.Failed || authState === ApiAuthState.IpRejected) && passwordLoginAllowed && (!passwordLoginMinimized || showPasswordLogin)}
            {@render localLoginForm()}
        {/if}

        <div class="mt-3"></div>

        {#if reauthRequired}
            <Alert color="warning"
                >The security policy requires you to sign in again before
                accessing this function.</Alert
            >
        {/if}
        {#if credentialRejected || authState === ApiAuthState.Failed}
            <Alert color="danger">Incorrect credentials</Alert>
        {/if}
        {#if authState === ApiAuthState.IpRejected}
            <Alert color="danger"
                >Login denied: your IP address is not in the allowed range for
                this user</Alert
            >
        {/if}
        {#if serverErrorMessage}
            <Alert color="danger">{serverErrorMessage}</Alert>
        {/if}
        {#if error}
            <Alert color="danger">{error}</Alert>
        {/if}
    </div>

    {#if authState === ApiAuthState.SsoNeeded || authState === ApiAuthState.NotStarted || authState === ApiAuthState.Failed || authState === ApiAuthState.IpRejected}
        <Loadable promise={ssoProvidersPromise}>
            {#snippet children(ssoProviders)}
                <div class="mt-3 sso-buttons">
                    {#each ssoProviders as ssoProvider (ssoProvider.name)}
                        <button
                            type="button"
                            class="btn btn-secondary"
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
            {/snippet}
        </Loadable>
    {/if}

    {#if (authState === ApiAuthState.NotStarted || authState === ApiAuthState.PasswordNeeded || authState === ApiAuthState.Failed || authState === ApiAuthState.IpRejected) && passwordLoginMinimized && !showPasswordLogin}
        <div class="mt-3 text-center">
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
            class="btn w-100 mt-3 btn-secondary"
            onclick={cancel}
        >
            Cancel
        </button>
    {/if}
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


</style>
