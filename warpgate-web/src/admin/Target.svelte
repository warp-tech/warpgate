<script lang="ts">
import { faExternalLink } from '@fortawesome/free-solid-svg-icons'
import { api, Target, UserSnapshot } from 'admin/lib/api'
import AsyncButton from 'common/AsyncButton.svelte'
import ConnectionInstructions from 'common/ConnectionInstructions.svelte'
import { TargetKind } from 'gateway/lib/api'
import { serverInfo } from 'gateway/lib/store'
import Fa from 'svelte-fa'
import { replace } from 'svelte-spa-router'
import { Alert, FormGroup, Input, Spinner } from 'sveltestrap'
import TlsConfiguration from './TlsConfiguration.svelte'

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
        if (target.options.kind === 'Http') {
            // eslint-disable-next-line @typescript-eslint/prefer-nullish-coalescing
            target.options.externalHost = target.options.externalHost || undefined
        }
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
                {#if target.options.kind === 'Http'}
                    HTTP target
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

    {#if target.options.kind === 'Ssh'}
        <div class="row">
            <div class="col-8">
                <FormGroup floating label="Target host">
                    <input class="form-control" bind:value={target.options.host} />
                </FormGroup>
            </div>
            <div class="col-4">
                <FormGroup floating label="Target port">
                    <input class="form-control" type="number" bind:value={target.options.port} min="1" max="65535" step="1" />
                </FormGroup>
            </div>
        </div>

        <FormGroup floating label="Username">
            <input class="form-control" bind:value={target.options.username} />
        </FormGroup>

        <div class="d-flex">
            <FormGroup floating label="Authentication" class="w-100">
                <select bind:value={target.options.auth.kind} class="form-control">
                    <option value={'PublicKey'}>Warpgate's private keys</option>
                    <option value={'Password'}>Password</option>
                </select>
            </FormGroup>
            {#if target.options.auth.kind === 'PublicKey'}
                <a
                    class="btn btn-link mb-3 d-flex align-items-center"
                    href="/@warpgate/admin#/ssh"
                    target="_blank">
                    <Fa fw icon={faExternalLink} />
                </a>
            {/if}
            {#if target.options.auth.kind === 'Password'}
                <FormGroup floating label="Password" class="w-100 ms-3">
                    <input class="form-control" type="password" autocomplete="off" bind:value={target.options.auth.password} />
                </FormGroup>
            {/if}
        </div>
    {/if}

    {#if target.options.kind === 'Http'}
        <FormGroup floating label="Target URL">
            <input class="form-control" bind:value={target.options.url} />
        </FormGroup>

        <TlsConfiguration bind:value={target.options.tls} />

        {#if $serverInfo?.externalHost}
            <FormGroup floating label="Bind to a domain">
                <Input type="text" placeholder={'foo.' + $serverInfo.externalHost} bind:value={target.options.externalHost} />
            </FormGroup>
        {/if}
    {/if}

    {#if target.options.kind === 'MySql'}
        <div class="row">
            <div class="col-8">
                <FormGroup floating label="Target host">
                    <input class="form-control" bind:value={target.options.host} />
                </FormGroup>
            </div>
            <div class="col-4">
                <FormGroup floating label="Target port">
                    <input class="form-control" type="number" bind:value={target.options.port} min="1" max="65535" step="1" />
                </FormGroup>
            </div>
        </div>

        <div class="row">
            <div class="col">
                <FormGroup floating label="Username">
                    <input class="form-control" bind:value={target.options.username} />
                </FormGroup>
            </div>
            <div class="col">
                <FormGroup floating label="Password">
                    <input class="form-control" type="password" autocomplete="off" bind:value={target.options.password} />
                </FormGroup>
            </div>
        </div>

        <TlsConfiguration bind:value={target.options.tls} />
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
