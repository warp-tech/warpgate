<script lang="ts">
import { replace } from 'svelte-spa-router'
import { Alert, FormGroup } from 'sveltestrap'
import { api, LoginFailureReason, LoginFailureResponseFromJSON } from 'gateway/lib/api'
import { reloadServerInfo } from 'gateway/lib/store'
import AsyncButton from 'common/AsyncButton.svelte';

let error: Error|null = null
let username = ''
let password = ''
let otp = ''
let incorrectCredentials = false
let otpInputVisible = false
let busy = false

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
</script>

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
        type="submit"
        disabled={busy}
        click={login}
    >Login</AsyncButton>

    {#if incorrectCredentials}
        <Alert color="danger">Incorrect credentials</Alert>
    {/if}
    {#if error}
        <Alert color="danger">{error}</Alert>
    {/if}
</form>
