<script lang="ts">
import { api } from 'admin/lib/api'
import AsyncButton from 'common/AsyncButton.svelte'
import { replace } from 'svelte-spa-router'
import { Form, FormGroup } from '@sveltestrap/sveltestrap'
import { stringifyError } from 'common/errors'
import Alert from 'common/sveltestrap-s5-ports/Alert.svelte'

let error: string|null = $state(null)
let username = $state('')

async function create () {
    try {
        const user = await api.createUser({
            createUserRequest: {
                username,
            },
        })
        replace(`/users/${user.id}`)
    } catch (err) {
        error = await stringifyError(err)
    }
}

</script>

{#if error}
<Alert color="danger">{error}</Alert>
{/if}


<div class="page-summary-bar">
    <h1>add a user</h1>
</div>
<div class="narrow-page">
    <Form>
        <FormGroup floating label="Username">
            <input class="form-control" required bind:value={username} />
        </FormGroup>

        <AsyncButton
        color="primary"
            click={create}
        >Create user</AsyncButton>
    </Form>
</div>
