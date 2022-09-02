<script lang="ts">
import { get } from 'svelte/store'
import { querystring, replace } from 'svelte-spa-router'
import { Alert, FormGroup } from 'sveltestrap'
import Fa from 'svelte-fa'
import { faArrowRight } from '@fortawesome/free-solid-svg-icons'
import { faGoogle, faMicrosoft, faApple } from '@fortawesome/free-brands-svg-icons'

import { api, ApiAuthState, LoginFailureResponseFromJSON, SsoProviderDescription, SsoProviderKind } from 'gateway/lib/api'
import { reloadServerInfo } from 'gateway/lib/store'
import AsyncButton from 'common/AsyncButton.svelte'
import DelayedSpinner from 'common/DelayedSpinner.svelte'

export let params: { stateId?: string } = {}

let error: Error|null = null
let username = ''
let password = ''
let otp = ''
let busy = false

let authState: ApiAuthState|undefined = undefined

let ssoProvidersPromise = api.getSsoProviders()

const nextURL = new URLSearchParams(get(querystring)).get('next') ?? undefined
const serverErrorMessage = new URLSearchParams(location.search).get('login_error')

async function init () {
    try {
        authState = (await api.getDefaultAuthState()).state
    } catch (err) {
        if (err.status) {
            const response = err as Response
            if (response.status === 404) {
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
            startSSO(providers[0])
        }
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
        if (err.status) {
            const response = err as Response
            if (response.status === 401) {
                const failure = LoginFailureResponseFromJSON(await response.json())
                authState = failure.state

                continueWithState()
            } else {
                error = new Error(await response.text())
            }
        } else {
            error = err
        }
    }
}

function onInputKey (event: KeyboardEvent) {
    if (event.key === 'Enter') {
        login()
    }
}

async function startSSO (provider: SsoProviderDescription) {
    busy = true
    try {
        const p = await api.startSso({ name: provider.name, next: nextURL })
        location.href = p.url
    } catch {
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
        {#if params.stateId}
        //todo
        loggin in for auth state id {params.stateId}
        {/if}
        {#if authState === ApiAuthState.OtpNeeded}
            <FormGroup floating label="One-time password">
                <!-- svelte-ignore a11y-autofocus -->
                <input
                    bind:value={otp}
                    on:keypress={onInputKey}
                    name="otp"
                    autofocus
                    disabled={busy}
                    class="form-control" />
            </FormGroup>
        {/if}
        {#if authState === ApiAuthState.NotStarted || authState === ApiAuthState.PasswordNeeded || authState === ApiAuthState.Failed}
            <FormGroup floating label="Username">
                <!-- svelte-ignore a11y-autofocus -->
                <input
                    bind:value={username}
                    on:keypress={onInputKey}
                    name="username"
                    autocomplete="username"
                    disabled={busy}
                    class="form-control"
                    autofocus />
            </FormGroup>

            <FormGroup floating label="Password">
                <input
                    bind:value={password}
                    on:keypress={onInputKey}
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

            {#if authState === ApiAuthState.Failed}
                <Alert color="danger">Incorrect credentials</Alert>
            {/if}
            {#if serverErrorMessage}
                <Alert color="danger">{serverErrorMessage}</Alert>
            {/if}
            {#if error}
                <Alert color="danger">{error}</Alert>
            {/if}
        {/if}
    </form>

    {#await ssoProvidersPromise then ssoProviders}
        {#if authState === ApiAuthState.SsoNeeded || authState === ApiAuthState.NotStarted || authState === ApiAuthState.Failed}
            <div class="mt-5">
                {#each ssoProviders as ssoProvider}
                    <button
                        class="btn d-flex align-items-center w-100 mb-2 btn-outline-primary"
                        disabled={busy}
                        on:click={() => startSSO(ssoProvider)}
                    >
                        <span class="m-auto">
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
                        </span>
                    </button>
                {/each}
            </div>
        {/if}
    {/await}
{/await}
