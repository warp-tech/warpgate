<script lang="ts">
import { replace } from 'svelte-spa-router'
import { Alert, FormGroup } from 'sveltestrap'
import Fa from 'svelte-fa'
import { faArrowRight } from '@fortawesome/free-solid-svg-icons'
import { faGoogle } from '@fortawesome/free-brands-svg-icons'

import { api, LoginFailureReason, LoginFailureResponseFromJSON, SsoProviderDescription, SsoProviderKind } from 'gateway/lib/api'
import { reloadServerInfo } from 'gateway/lib/store'
import AsyncButton from 'common/AsyncButton.svelte'

let error: Error|null = null
let username = ''
let password = ''
let otp = ''
let incorrectCredentials = false
let otpInputVisible = false
let ssoRequiredNow = false
let busy = false

let ssoProvidersPromise = api.getSsoProviders()

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
    incorrectCredentials = false
    try {
        await api.login({
            loginRequest: {
                username,
                password,
                otp: otp || undefined,
            },
        })
        let next = new URLSearchParams(location.search).get('next')
        if (next) {
            location.href = next
        } else {
            await reloadServerInfo()
            replace('/')
        }
    } catch (err) {
        if (err.status) {
            const response = err as Response
            if (response.status === 401) {
                const failure = LoginFailureResponseFromJSON(await response.json())
                if (failure.reason === LoginFailureReason.InvalidCredentials) {
                    incorrectCredentials = true
                } else if (failure.reason === LoginFailureReason.OtpNeeded) {
                    presentOTPInput()
                } else if (failure.reason === LoginFailureReason.SsoNeeded) {
                    const providers = await ssoProvidersPromise
                    if (!providers.length) {
                        // todo
                    }
                    if (providers.length === 1) {
                        startSSO(providers[0])
                    }
                    ssoRequiredNow = true
                }
            } else {
                error = new Error(await response.text())
            }
        } else {
            error = err
        }
    }
}

function presentOTPInput () {
    otpInputVisible = true
}

function onInputKey (event: KeyboardEvent) {
    if (event.key === 'Enter') {
        login()
    }
}

async function startSSO (provider: SsoProviderDescription) {
    busy = true
    try {
        const params = await api.startSso(provider)
        location.href = params.url
    } catch {
        busy = false
    }
}
</script>

{#if !ssoRequiredNow}
    <form class="mt-5" autocomplete="on">
        <div class="page-summary-bar">
            <h1>Welcome</h1>
        </div>

        {#if !otpInputVisible}
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
        {/if}

        {#if otpInputVisible}
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

        <AsyncButton
            outline
            class="d-flex align-items-center"
            type="submit"
            disabled={busy}
            click={login}
        >
            Login
            <Fa class="ms-2" icon={faArrowRight} />
        </AsyncButton>

        {#if incorrectCredentials}
            <Alert color="danger">Incorrect credentials</Alert>
        {/if}
        {#if error}
            <Alert color="danger">{error}</Alert>
        {/if}
    </form>
{/if}

{#await ssoProvidersPromise then ssoProviders}
<div class="mt-5">
    {#each ssoProviders as ssoProvider}
        <button
            class="btn d-flex align-items-center w-100 btn-outline-primary"
            disabled={busy}
            on:click={() => startSSO(ssoProvider)}
        >
            <span class="m-auto">
                {#if ssoProvider.kind === SsoProviderKind.Google}
                    <Fa fw class="me-2" icon={faGoogle} />
                {/if}
                {ssoProvider.label}
            </span>
        </button>
    {/each}
</div>
{/await}
