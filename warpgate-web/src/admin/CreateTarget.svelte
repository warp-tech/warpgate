<script lang="ts">
import { api } from 'admin/lib/api'
import AsyncButton from 'common/AsyncButton.svelte'
import { push } from 'svelte-spa-router'
import { Alert, FormGroup } from 'sveltestrap'

let error: Error|null = null
let name = ''

async function load () {
}

load().catch(e => {
    error = e
})

async function create () {
    if (!name) {
        return
    }
    try {
        const target = await api.createTarget({
            createTargetRequest: {
                name,
                options: {
                    kind: 'Ssh',
                    host: '192.168.0.1',
                    port: 22,
                    username: 'root',
                    auth: {
                        kind: 'PublicKey',
                    },
                },
            },
        })
        console.log(target)
        push(`/targets`)
    } catch (err) {
        error = err
    }
}

</script>

{#if error}
<Alert color="danger">{error}</Alert>
{/if}


<div class="page-summary-bar">
    <h1>Add a target</h1>
</div>

<FormGroup floating label="Name">
    <input class="form-control" bind:value={name} />
</FormGroup>

<AsyncButton
    outline
    click={create}
>Create target</AsyncButton>
