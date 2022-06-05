<script lang="ts">
import { api } from 'lib/api'
import { authenticatedUsername } from 'lib/store'
import { replace } from 'svelte-spa-router'

import { Alert, Button, FormGroup } from 'sveltestrap'
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
    const info = await api.getInfo()
    authenticatedUsername.set(info.username!)
    replace('/')
}

function onInputKey (event: KeyboardEvent) {
    if (event.key === 'Enter') {
        login()
    }
}
</script>

<form class="mt-5 row" autocomplete="on">
    <div class="col-12 col-md-3"></div>
    <form class="col-12 col-md-6">
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
    <div class="col-12 col-md-3"></div>
</form>
