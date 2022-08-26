<script lang="ts">
import { api, Target, UserSnapshot } from 'admin/lib/api'
import AsyncButton from 'common/AsyncButton.svelte'
import ConnectionInstructions from 'common/ConnectionInstructions.svelte'
import { TargetKind } from 'gateway/lib/api'
import { replace } from 'svelte-spa-router'
import { Alert, FormGroup, Spinner } from 'sveltestrap'

export let params: { id: string }

let error: Error|undefined
let selectedUser: UserSnapshot|undefined
let target: Target

async function load () {
    try {
        target = await api.getTarget({ id: params.id })
    } catch (err) {
        error = err
    }
}

async function update () {
    try {
        target = await api.updateTarget({
            id: params.id,
            targetDataRequest: target,
        })
    } catch (err) {
        error = err
    }
}

async function remove () {
    if (confirm(`Delete target ${target.name}?`)) {
        await api.deleteTarget(target)
        replace('/targets')
    }
}
</script>

{#await load()}
    <Spinner />
{:then}
    <div class="page-summary-bar">
        <div>
            <h1>{target.name}</h1>
            <div class="text-muted">
                {#if target.options.kind === 'MySql'}
                    MySQL target
                {/if}
                {#if target.options.kind === 'Ssh'}
                    SSH target
                {/if}
                {#if target.options.kind === 'WebAdmin'}
                    This web admin interface
                {/if}
            </div>
        </div>
        <!-- <a
            class="btn btn-outline-secondary ms-auto"
            href="/targets/create"
            use:link>
            Add a target
        </a> -->
    </div>

    <h4>Access instructions</h4>

    {#if target.options.kind === 'Ssh' || target.options.kind === 'MySql'}
        {#await api.getUsers()}
            <Spinner/>
        {:then users}
            <FormGroup floating label="Select a user">
                <select bind:value={selectedUser} class="form-control">
                    {#each users as user}
                        <option value={user}>
                            {user.username}
                        </option>
                    {/each}
                </select>
            </FormGroup>
        {:catch error}
            <Alert color="danger">{error}</Alert>
        {/await}
    {/if}

    <ConnectionInstructions
        targetName={target.name}
        username={selectedUser?.username}
        targetKind={{
            Ssh: TargetKind.Ssh,
            WebAdmin: TargetKind.WebAdmin,
            Http: TargetKind.Http,
            MySql: TargetKind.MySql,
        }[target.options.kind ?? '']}
        targetExternalHost={target.options['externalHost']}
    />

    <h4 class="mt-4">Configuration</h4>

    <FormGroup floating label="Name">
        <input class="form-control" bind:value={target.name} />
    </FormGroup>

    {#if target.options.kind === 'Http'}
        <FormGroup floating label="Target URL">
            <input class="form-control" bind:value={target.options.url} />
        </FormGroup>
    {/if}
{/await}

{#if error}
    <Alert color="danger">{error}</Alert>
{/if}

<div class="d-flex">
    <AsyncButton
        class="ms-auto"
        outline
        click={update}
    >Update configuration</AsyncButton>

    <AsyncButton
        class="ms-2"
        outline
        color="danger"
        click={remove}
    >Remove</AsyncButton>
</div>
