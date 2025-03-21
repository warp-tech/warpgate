<script lang="ts">
import { api } from 'admin/lib/api'
import AsyncButton from 'common/AsyncButton.svelte'
import { replace } from 'svelte-spa-router'
import { Form, FormGroup } from '@sveltestrap/sveltestrap'
import { stringifyError } from 'common/errors'
import Alert from 'common/sveltestrap-s5-ports/Alert.svelte'

let error: string|null = $state(null)
let name = $state('')

async function create () {
    try {
        const role = await api.createRole({
            roleDataRequest: {
                name,
                description: '',
            },
        })
        replace(`/roles/${role.id}`)
    } catch (err) {
        error = await stringifyError(err)
    }
}

</script>

{#if error}
<Alert color="danger">{error}</Alert>
{/if}


<div class="page-summary-bar">
    <h1>add a role</h1>
</div>

<div class="narrow-page">
    <Form>
        <FormGroup floating label="Name">
            <input class="form-control" bind:value={name} required />
        </FormGroup>

        <AsyncButton
            color="primary"
            click={create}
        >Create role</AsyncButton>
    </Form>
</div>
