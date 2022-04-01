<script lang="ts">
import { api } from 'lib/api'
import { authenticatedUsername } from 'lib/store'
import { replace } from 'svelte-spa-router'

import { Alert, Button, FormGroup } from 'sveltestrap'
let error: Error|null = null
let username = ''
let password = ''
let wrongPassword = false

async function login () {
    error = null
    wrongPassword = false
    try {
        await api.login({
            loginRequest: {
                username,
                password,
            },
        })
    } catch (error) {
        if (error.status === 401) {
            wrongPassword = true
        } else {
            error = error
        }
        return
    }
    const info = await api.getInfo()
    authenticatedUsername.set(info.username!)
    replace('/')
}
</script>

<div class="mt-5 row">
    <div class="col-12 col-md-3"></div>
    <div class="col-12 col-md-6">
        <div class="page-summary-bar">
            <h1>Welcome</h1>
        </div>

        {#if wrongPassword}
            <Alert color="danger">Wrong password</Alert>
        {/if}
        {#if error}
            <Alert color="danger">{error.message}</Alert>
        {/if}

        <FormGroup floating label="Username">
            <!-- svelte-ignore a11y-autofocus -->
            <input bind:value={username} class="form-control" autofocus />
        </FormGroup>

        <FormGroup floating label="Password">
            <input bind:value={password} type="password" class="form-control" />
        </FormGroup>

        <Button
            outline
            on:click={login}
        >Login</Button>

    </div>
    <div class="col-12 col-md-3"></div>
</div>
