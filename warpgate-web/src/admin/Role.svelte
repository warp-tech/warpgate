<script lang="ts">
import { api, Role } from 'admin/lib/api'
import AsyncButton from 'common/AsyncButton.svelte'
import DelayedSpinner from 'common/DelayedSpinner.svelte'
import { replace } from 'svelte-spa-router'
import { Alert, FormGroup } from '@sveltestrap/sveltestrap'

export let params: { id: string }

let error: Error|undefined
let role: Role

async function load () {
    try {
        role = await api.getRole({ id: params.id })
    } catch (err) {
        error = err as Error
    }
}

async function update () {
    try {
        role = await api.updateRole({
            id: params.id,
            roleDataRequest: role,
        })
    } catch (err) {
        error = err as Error
    }
}

async function remove () {
    if (confirm(`Delete role ${role.name}?`)) {
        await api.deleteRole(role)
        replace('/config')
    }
}
</script>

{#await load()}
    <DelayedSpinner />
{:then}
    <div class="page-summary-bar">
        <div>
            <h1>{role.name}</h1>
            <div class="text-muted">Role</div>
        </div>
    </div>

    <FormGroup floating label="Name">
        <input class="form-control" bind:value={role.name} />
    </FormGroup>
{/await}

{#if error}
    <Alert color="danger">{error}</Alert>
{/if}

<div class="d-flex">
    <AsyncButton
        class="ms-auto"
        outline
        click={update}
    >Update</AsyncButton>

    <AsyncButton
        class="ms-2"
        outline
        color="danger"
        click={remove}
    >Remove</AsyncButton>
</div>
