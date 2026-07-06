<script lang="ts">
    import { Alert, Form, FormGroup } from '@sveltestrap/sveltestrap'
    import { api } from 'admin/lib/api'
    import AsyncButton from 'common/AsyncButton.svelte'
    import { stringifyError } from 'common/errors'
    import { replace } from 'svelte-spa-router'

    let error: string | null = $state(null)
    let name = $state('')

    async function create() {
        try {
            const role = await api.createRole({
                roleDataRequest: {
                    name,
                    isDefault: false,
                },
            })
            replace(`/config/access-roles/${role.id}`)
        } catch (err) {
            error = await stringifyError(err)
        }
    }
</script>

<div class="container-max-md">
    {#if error}
        <Alert color="danger">{error}</Alert>
    {/if}

    <div class="page-summary-bar">
        <h1>add a role</h1>
    </div>

    <div class="narrow-page">
        <Form>
            <FormGroup floating label="Name">
                <!-- svelte-ignore a11y_autofocus -->
                <input
                    class="form-control"
                    bind:value={name}
                    required
                    autofocus
                >
            </FormGroup>

            <AsyncButton color="primary" click={create}
                >Create role</AsyncButton
            >
        </Form>
    </div>
</div>
