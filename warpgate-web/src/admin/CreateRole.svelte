<script lang="ts">
import { api } from 'admin/lib/api'
import AsyncButton from 'common/AsyncButton.svelte'
import { replace } from 'svelte-spa-router'
import { Alert, FormGroup } from 'sveltestrap'

let error: Error|null = null
let name = ''

async function create () {
    if (!name) {
        return
    }
    try {
        const role = await api.createRole({
            roleDataRequest: {
                name,
            },
        })
        replace(`/roles/${role.id}`)
    } catch (err) {
        error = err
    }
}

</script>

{#if error}
<Alert color="danger">{error}</Alert>
{/if}


<div class="page-summary-bar">
    <h1>Add a role</h1>
</div>

<FormGroup floating label="Name">
    <input class="form-control" bind:value={name} />
</FormGroup>

<AsyncButton
    outline
    click={create}
>Create role</AsyncButton>
