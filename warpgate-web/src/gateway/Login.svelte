<script lang="ts">
import { replace } from 'svelte-spa-router'
import { Alert, Button, FormGroup } from 'sveltestrap'
import { api } from 'gateway/lib/api'
import { reloadServerInfo } from 'gateway/lib/store'

let error: Error|null = null
let username = ''
let password = ''
let incorrectCredentials = false

async function login (event?: MouseEvent) {
    event?.preventDefault()
    error = null
    incorrectCredentials = false
    try {
        await api.login({
            loginRequest: {
                username,
                password,
            },
        })
    } catch (err) {
        if (err.status === 401) {
            incorrectCredentials = true
        } else {
            error = err
        }
        return
    }

    let next = new URLSearchParams(location.search).get('next')
    if (next) {
        location.href = next
    } else {
        await reloadServerInfo()
        replace('/')
    }
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

    <FormGroup floating label="Username">
        <!-- svelte-ignore a11y-autofocus -->
        <input
            bind:value={username}
            on:keypress={onInputKey}
            name="username"
            autocomplete="username"
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
            class="form-control" />
    </FormGroup>

    <Button
        outline
        type="submit"
        on:click={login}
    >Login</Button>

    {#if incorrectCredentials}
        <Alert color="danger">Incorrect credentials</Alert>
    {/if}
    {#if error}
        <Alert color="danger">{error}</Alert>
    {/if}
</form>
