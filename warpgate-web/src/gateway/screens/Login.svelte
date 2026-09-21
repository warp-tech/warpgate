<script lang="ts">
    /**
     * Sign in — screen 12. The highest-risk screen in the product: a
     * regression here locks everyone out, so this is a restyle of an
     * unchanged state machine rather than a rewrite.
     *
     * ── Enumeration of gateway/Login.svelte, asserted present ────────────
     * Params:  `next` and `reauth` from the hash query, `login_error` from
     *          location.search — a different source, and it stays that way
     *          because the server sets it on a real redirect.
     * init():  getDefaultAuthState; a 404 means NotStarted; anything else
     *          rethrows rather than being swallowed into a blank form.
     * sanitizeRedirect(): resolves `next` against location.origin and
     *          returns it only when the origin still matches — the
     *          open-redirect guard. Kept character for character.
     * continueWithState(): Success -> success(); SsoNeeded with exactly one
     *          provider and redirects allowed -> startSSO automatically;
     *          OtpNeeded -> focus the code field on the next tick.
     * _login(): OtpNeeded -> otpLogin({ otp }); otherwise
     *          login({ username, password }); then reloadServerInfo, then
     *          success. On 401, parse LoginFailureResponse, adopt its state
     *          and credentialRejected, and re-enter continueWithState with
     *          `allowSsoRedirect: !credentialRejected`. Non-401 uses the
     *          response text; non-ResponseError uses stringifyError.
     * cancel(): cancelDefaultAuth then a full location.reload().
     * startSSO(): startSso({ name, next }) then navigateToExternalUrl.
     * Modes:   passwordLoginMode Enabled / Disabled / Minimized, with the
     *          "Password login" disclosure and both separator placements.
     * Copy:    reauth warning, "Incorrect credentials", the IP-rejected
     *          message, the server error, and the generic error.
     * Cancel:  shown whenever the state is not NotStarted / Failed /
     *          IpRejected.
     *
     * ── Why allowSsoRedirect is load-bearing ─────────────────────────────
     * With one SSO provider configured, continueWithState redirects to it
     * automatically. If that also happened after a rejected password, a user
     * who mistyped would be bounced to the IdP instead of being told, and
     * would never see the error. The original carried a comment saying so;
     * the behaviour and the reason are both preserved.
     *
     * ── What the mockup shows that does not exist ────────────────────────
     * The export is a three-state spec sheet with the ADMIN sidebar pasted
     * behind it; sign-in has no chrome at all. Omitted: "PORT: 2222",
     * "CORE ENGINE v0.28.6", "FIPS-140-2 COMPLIANT", "SESSION NONCE /
     * TTL 284 SEC", the CLIENT_IP / FAIL_COUNT / INCIDENT_ID block,
     * "SECURITY BAN" with "Request Access Unban", the SYSTEM TELEMETRY BUS
     * footer, and "DEFENSE SHIELD ACTIVE". None has an API, and the
     * compliance and crypto claims in particular would be false statements
     * rather than decoration.
     *
     * The six separate digit boxes are omitted for a different reason: the
     * field accepts 6 *to 8* digits (`pattern="\d{6,8}"`, because recovery
     * codes are longer), so a fixed six-box control cannot express the input
     * it has to accept. One field also pastes correctly from a password
     * manager, which split boxes routinely do not.
     *
     * "Forgot password?" is omitted because there is no password-reset
     * endpoint — a link that goes nowhere is worse than no link.
     */
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
    import { replace } from 'svelte-spa-router'
    import Button from 'ui/Button.svelte'
    import Callout from 'ui/Callout.svelte'
    import Input from 'ui/Input.svelte'
    import 'ui/layout.css'

    let error: string | null = $state(null)
    let username = $state('')
    let password = $state('')
    let otp = $state('')
    let busy = $state(false)
    let credentialRejected = $state(false)
    let otpInput: HTMLInputElement | undefined = $state()
    let authState: ApiAuthState | undefined = $state()
    const ssoProvidersPromise = api.getSsoProviders()
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

    /**
     * Written as a regex literal and read back via `.source` rather than as a
     * string. `'\d{6,8}'` in a JS string is just `'d{6,8}'` — an unrecognised
     * escape collapses to the bare character — which would have made the
     * field reject every valid code while looking correct in the source.
     * A regex literal cannot go wrong that way.
     *
     * 6 to 8 digits: TOTP codes are 6, recovery codes are longer.
     */
    const OTP_PATTERN = /\d{6,8}/.source

    const urlParams = routeQueryParams()
    const nextURL = urlParams.get('next') ?? undefined
    const reauthRequired = urlParams.get('reauth') === '1'
    // location.search, not the hash params: the server sets this one.
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

    /** Open-redirect guard: only ever return a same-origin URL. */
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
                await api.otpLogin({ otpLoginRequest: { otp } })
            } else {
                await api.login({ loginRequest: { username, password } })
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
                    continueWithState({
                        allowSsoRedirect: !credentialRejected,
                    })
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

    const atStart = $derived(
        authState === ApiAuthState.NotStarted ||
            authState === ApiAuthState.Failed ||
            authState === ApiAuthState.IpRejected,
    )
    const canShowPasswordForm = $derived(
        (atStart || authState === ApiAuthState.PasswordNeeded) &&
            passwordLoginAllowed,
    )
    const passwordFormVisible = $derived(
        canShowPasswordForm && (!passwordLoginMinimized || showPasswordLogin),
    )
    const showSsoSection = $derived(
        authState === ApiAuthState.SsoNeeded || atStart,
    )
    const showCancel = $derived(authState !== undefined && !atStart)
</script>

<Loadable promise={initPromise}>
    <div class="login">
        <h1>{atStart ? 'Welcome' : 'Continue signing in'}</h1>

        {#if authState === ApiAuthState.OtpNeeded}
            <form
                class="otp-form"
                onsubmit={e => {
                    e.preventDefault()
                    login()
                }}
            >
                <div class="otp-field">
                    <Input
                        label="One-time password"
                        name="otp"
                        required
                        autofocus
                        mono
                        inputmode="numeric"
                        pattern={OTP_PATTERN}
                        autocomplete="one-time-code"
                        disabled={busy}
                        bind:value={otp}
                        bind:inner={otpInput}
                        hint="6 digits from your authenticator, or a recovery code."
                    />
                </div>
                <Button variant="primary" type="submit" disabled={busy}>
                    Continue
                </Button>
            </form>
        {/if}

        {#if passwordFormVisible}
            <form
                class="wg-field-stack"
                autocomplete="on"
                onsubmit={e => {
                    e.preventDefault()
                    login()
                }}
            >
                <Input
                    label="Username"
                    name="username"
                    autocomplete="username"
                    required
                    autofocus
                    disabled={busy}
                    bind:value={username}
                />

                <Input
                    label="Password"
                    name="password"
                    type="password"
                    autocomplete="current-password"
                    required
                    disabled={busy}
                    bind:value={password}
                />

                <Button variant="primary" type="submit" disabled={busy} block>
                    Sign in
                </Button>
            </form>
        {/if}

        {#if reauthRequired}
            <div class="message">
                <Callout tone="warning" title="Sign in again to continue">
                    The security policy requires you to sign in again before
                    using this function.
                </Callout>
            </div>
        {/if}
        {#if credentialRejected || authState === ApiAuthState.Failed}
            <div class="message">
                <Callout tone="danger" title="Incorrect credentials">
                    Check the username and password and try again.
                </Callout>
            </div>
        {/if}
        {#if authState === ApiAuthState.IpRejected}
            <div class="message">
                <Callout tone="danger" title="Sign-in denied from this address">
                    Your IP address is not in the allowed range for this user.
                    Either you are connecting from somewhere new, or someone
                    else is using your username. Contact your administrator
                    through a channel that does not go through Warpgate.
                </Callout>
            </div>
        {/if}
        {#if serverErrorMessage}
            <div class="message">
                <Callout tone="danger" title="Sign-in failed">
                    {serverErrorMessage}
                </Callout>
            </div>
        {/if}
        {#if error}
            <div class="message">
                <Callout tone="danger" title="Something went wrong">
                    {error}
                </Callout>
            </div>
        {/if}

        {#if showSsoSection}
            <Loadable promise={ssoProvidersPromise}>
                {#snippet children(ssoProviders)}
                    {#if ssoProviders.length && passwordFormVisible}
                        <div class="separator"><span>or</span></div>
                    {/if}

                    <div class="sso-buttons">
                        {#each ssoProviders as ssoProvider (ssoProvider.name)}
                            <Button
                                block
                                disabled={busy}
                                onclick={() => startSSO(ssoProvider)}
                            >
                                {#if ssoProvider.kind === SsoProviderKind.Google}
                                    <svg
                                        viewBox="0 0 16 16"
                                        width="14"
                                        height="14"
                                        aria-hidden="true"
                                    >
                                        <path
                                            d="M14.5 8.16c0-.47-.04-.92-.12-1.35H8v2.55h3.64a3.11 3.11 0 0 1-1.35 2.04v1.7h2.18c1.28-1.18 2.03-2.92 2.03-4.94z"
                                            fill="currentColor"
                                        />
                                        <path
                                            d="M8 15c1.83 0 3.36-.6 4.47-1.64l-2.18-1.7c-.6.41-1.38.65-2.29.65-1.76 0-3.25-1.19-3.79-2.79H1.96v1.75A6.75 6.75 0 0 0 8 15z"
                                            fill="currentColor"
                                            opacity="0.7"
                                        />
                                        <path
                                            d="M4.21 9.52a4.05 4.05 0 0 1 0-2.58V5.19H1.96a6.75 6.75 0 0 0 0 6.08l2.25-1.75z"
                                            fill="currentColor"
                                            opacity="0.5"
                                        />
                                        <path
                                            d="M8 4.15c.99 0 1.88.34 2.58 1.01l1.94-1.93A6.75 6.75 0 0 0 1.96 5.19l2.25 1.75c.54-1.6 2.03-2.79 3.79-2.79z"
                                            fill="currentColor"
                                            opacity="0.85"
                                        />
                                    </svg>
                                {:else if ssoProvider.kind === SsoProviderKind.Azure}
                                    <svg
                                        viewBox="0 0 16 16"
                                        width="14"
                                        height="14"
                                        aria-hidden="true"
                                    >
                                        <rect
                                            x="1.5"
                                            y="1.5"
                                            width="5.8"
                                            height="5.8"
                                            fill="currentColor"
                                        />
                                        <rect
                                            x="8.7"
                                            y="1.5"
                                            width="5.8"
                                            height="5.8"
                                            fill="currentColor"
                                            opacity="0.75"
                                        />
                                        <rect
                                            x="1.5"
                                            y="8.7"
                                            width="5.8"
                                            height="5.8"
                                            fill="currentColor"
                                            opacity="0.75"
                                        />
                                        <rect
                                            x="8.7"
                                            y="8.7"
                                            width="5.8"
                                            height="5.8"
                                            fill="currentColor"
                                            opacity="0.5"
                                        />
                                    </svg>
                                {:else if ssoProvider.kind === SsoProviderKind.Apple}
                                    <svg
                                        viewBox="0 0 16 16"
                                        width="14"
                                        height="14"
                                        aria-hidden="true"
                                    >
                                        <path
                                            d="M11.1 8.5c0-1.5 1.2-2.2 1.3-2.3-.7-1-1.8-1.2-2.2-1.2-.9-.1-1.8.6-2.3.6s-1.2-.6-2-.5c-1 0-2 .6-2.5 1.5-1.1 1.9-.3 4.6.8 6.1.5.7 1.1 1.5 1.9 1.5s1.1-.5 2-.5 1.2.5 2 .5 1.3-.7 1.8-1.4c.6-.8.8-1.6.8-1.6s-1.6-.6-1.6-2.7zM9.8 3.8c.4-.5.7-1.2.6-1.9-.6 0-1.4.4-1.8.9-.4.5-.7 1.2-.6 1.9.7.1 1.4-.4 1.8-.9z"
                                            fill="currentColor"
                                        />
                                    </svg>
                                {/if}
                                {ssoProvider.label || ssoProvider.name}
                            </Button>
                        {/each}
                    </div>

                    {#if ssoProviders.length && canShowPasswordForm && passwordLoginMinimized && !showPasswordLogin}
                        <div class="separator"><span>or</span></div>
                    {/if}
                {/snippet}
            </Loadable>
        {/if}

        {#if canShowPasswordForm && passwordLoginMinimized && !showPasswordLogin}
            <div class="disclosure">
                <Button
                    variant="ghost"
                    onclick={() => (showPasswordLogin = true)}
                >
                    Sign in with a password
                </Button>
            </div>
        {/if}

        {#if showCancel}
            <div class="cancel">
                <Button block click={cancel}>Cancel</Button>
            </div>
        {/if}
    </div>
</Loadable>

<style>
    .login {
        display: flex;
        flex-direction: column;
        justify-content: center;
        flex-grow: 1;
        padding-bottom: var(--wg-space-3xl);
    }

    h1 {
        margin: 0 0 var(--wg-space-xl);
        font: var(--wg-text-headline-lg);
    }

    .otp-form {
        display: flex;
        align-items: flex-end;
        gap: var(--wg-space-md);
    }

    .otp-field {
        flex: 1 1 auto;
        min-width: 0;
    }

    .message {
        margin-top: var(--wg-space-lg);
    }

    .sso-buttons {
        display: flex;
        flex-direction: column;
        gap: var(--wg-space-sm);
    }

    .separator {
        position: relative;
        text-align: center;
        margin: var(--wg-space-xl) 0;
    }

    .separator::before {
        content: "";
        position: absolute;
        top: 50%;
        left: 0;
        right: 0;
        height: var(--wg-border-width);
        background: var(--wg-border);
    }

    .separator span {
        position: relative;
        display: inline-block;
        padding: 0 var(--wg-space-md);
        background: var(--wg-surface);
        color: var(--wg-text-subtle);
        font: var(--wg-text-label-sm);
    }

    .disclosure {
        display: flex;
        justify-content: center;
        margin-top: var(--wg-space-md);
    }

    .cancel {
        margin-top: var(--wg-space-lg);
    }

    @media (max-width: 640px) {
        h1 {
            font: var(--wg-text-headline-lg-mobile);
        }
    }
</style>
