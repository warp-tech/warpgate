<script lang="ts">
import { api } from 'admin/lib/api'
import AsyncButton from 'common/AsyncButton.svelte'
import { replace } from 'svelte-spa-router'
import { Alert, FormGroup } from 'sveltestrap'

let error: Error|null = null
let username = ''

async function create () {
    if (!username) {
        return
    }
    try {
        const user = await api.createUser({
            userDataRequest: {
                username,
                credentials: [],
                credentialPolicy: {},
            },
        })
        replace(`/users/${user.id}`)
    } catch (err) {
        error = err
    }
}

</script>

{#if error}
<Alert color="danger">{error}</Alert>
{/if}


<div class="page-summary-bar">
    <h1>Add a user</h1>
</div>

<FormGroup floating label="Username">
    <input class="form-control" bind:value={username} />
</FormGroup>

<AsyncButton
    outline
    click={create}
>Create user</AsyncButton>
