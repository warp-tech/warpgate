<script lang="ts">
import { get } from 'svelte/store'
import { querystring, replace } from 'svelte-spa-router'
import { FormGroup } from '@sveltestrap/sveltestrap'
import Fa from 'svelte-fa'
import { faArrowRight } from '@fortawesome/free-solid-svg-icons'
import { faGoogle, faMicrosoft, faApple } from '@fortawesome/free-brands-svg-icons'

import { api, ApiAuthState, LoginFailureResponseFromJSON, type SsoProviderDescription, SsoProviderKind, ResponseError } from 'gateway/lib/api'
import { reloadServerInfo } from 'gateway/lib/store'
import AsyncButton from 'common/AsyncButton.svelte'
import DelayedSpinner from 'common/DelayedSpinner.svelte'
import { stringifyError } from 'common/errors'
import Alert from 'common/sveltestrap-s5-ports/Alert.svelte'

let error: string|null = $state(null)
let username = $state('')
let password = $state('')
let otp = $state('')
let busy = $state(false)
let otpInput: HTMLInputElement|undefined = $state()
let authState: ApiAuthState|undefined = $state()
let ssoProvidersPromise = api.getSsoProviders()

const nextURL = new URLSearchParams(get(querystring)).get('next') ?? undefined
const serverErrorMessage = new URLSearchParams(location.search).get('login_error')

async function init () {
    try {
        authState = (await api.getDefaultAuthState()).state
    } catch (err) {
        if (err instanceof ResponseError) {
            if (err.response.status === 404) {
                authState = ApiAuthState.NotStarted
            }
        }
    }
    continueWithState()
}

function success () {
    if (nextURL) {
        location.assign(nextURL)
    } else {
        replace('/')
    }
}

async function continueWithState () {
    if (authState === ApiAuthState.Success) {
        success()
    }
    if (authState === ApiAuthState.SsoNeeded) {
        const providers = await ssoProvidersPromise
        if (!providers.length) {
            // todo
        }
        if (providers.length === 1) {
            startSSO(providers[0]!)
        }
    }
    if (authState === ApiAuthState.OtpNeeded) {
        setTimeout(() => {
            otpInput?.focus()
        })
    }
}

async function login () {
    busy = true
    try {
        await _login()
    } finally {
        busy = false
    }
}

async function _login () {
    error = null
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
                const failure = LoginFailureResponseFromJSON(await err.response.json())
                authState = failure.state

                continueWithState()
            } else {
                error = await err.response.text()
            }
        } else {
            error = await stringifyError(err)
        }
    }
}

async function cancel () {
    await api.cancelDefaultAuth()
    location.reload()
}

function onInputKey (event: KeyboardEvent) {
    if (event.key === 'Enter') {
        login()
        event.preventDefault()
    }
}

async function startSSO (provider: SsoProviderDescription) {
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

{#await init()}
    <DelayedSpinner />
{:then}
    <form class="mt-5" autocomplete="on">
        <div class="page-summary-bar">
            {#if authState === ApiAuthState.NotStarted || authState === ApiAuthState.Failed}
                <h1>Welcome</h1>
            {:else}
                <h1>Continue login</h1>
            {/if}
        </div>
        {#if authState === ApiAuthState.OtpNeeded}
            <FormGroup floating label="One-time password">
                <!-- svelte-ignore a11y_autofocus -->
                <input
                    bind:value={otp}
                    bind:this={otpInput}
                    onkeypress={onInputKey}
                    name="otp"
                    autofocus
                    inputmode="numeric"
                    disabled={busy}
                    class="form-control" />
            </FormGroup>
        {/if}
        {#if authState === ApiAuthState.NotStarted || authState === ApiAuthState.PasswordNeeded || authState === ApiAuthState.Failed}
            <FormGroup floating label="Username">
                <!-- svelte-ignore a11y_autofocus -->
                <input
                    bind:value={username}
                    onkeypress={onInputKey}
                    name="username"
                    autocomplete="username"
                    disabled={busy}
                    class="form-control"
                    autofocus />
            </FormGroup>

            <FormGroup floating label="Password">
                <input
                    bind:value={password}
                    onkeypress={onInputKey}
                    name="password"
                    type="password"
                    autocomplete="current-password"
                    disabled={busy}
                    class="form-control" />
            </FormGroup>

            <AsyncButton
                outline
                class="d-flex align-items-center"
                type="submit"
                disabled={busy}
                click={login}
            >
                Login
                <Fa class="ms-2" fw icon={faArrowRight} />
            </AsyncButton>

        {/if}
        {#if authState === ApiAuthState.Failed}
            <Alert color="danger">Incorrect credentials</Alert>
        {/if}
        {#if serverErrorMessage}
            <Alert color="danger">{serverErrorMessage}</Alert>
        {/if}
        {#if error}
            <Alert color="danger">{error}</Alert>
        {/if}
    </form>

    {#await ssoProvidersPromise then ssoProviders}
        {#if authState === ApiAuthState.SsoNeeded || authState === ApiAuthState.NotStarted || authState === ApiAuthState.Failed}
            <div class="mt-5 sso-buttons">
                {#each ssoProviders as ssoProvider}
                    <button
                        class="btn btn-outline-primary"
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
                        {ssoProvider.label}
                    </button>
                {/each}
            </div>
        {/if}
    {/await}

    {#if authState !== ApiAuthState.NotStarted && authState !== ApiAuthState.Failed}
        <button
            class="btn w-100 mt-3 btn-outline-secondary"
            onclick={cancel}
        >
            Cancel
        </button>
    {/if}
{/await}

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
