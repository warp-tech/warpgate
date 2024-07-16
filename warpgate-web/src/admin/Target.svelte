<script lang="ts">
import { faExternalLink } from '@fortawesome/free-solid-svg-icons'
import { api, Role, Target, User } from 'admin/lib/api'
import AsyncButton from 'common/AsyncButton.svelte'
import ConnectionInstructions from 'common/ConnectionInstructions.svelte'
import DelayedSpinner from 'common/DelayedSpinner.svelte'
import { TargetKind } from 'gateway/lib/api'
import { serverInfo } from 'gateway/lib/store'
import Fa from 'svelte-fa'
import { replace } from 'svelte-spa-router'
import { Alert, FormGroup, Input } from '@sveltestrap/sveltestrap'
import TlsConfiguration from './TlsConfiguration.svelte'

export let params: { id: string }

let error: Error|undefined
let selectedUser: User|undefined
let target: Target
let allRoles: Role[] = []
let roleIsAllowed: { [id: string] : any; } = {}

async function load () {
    try {
        target = await api.getTarget({ id: params.id })
    } catch (err) {
        error = err as Error
    }
}

async function loadRoles () {
    allRoles = await api.getRoles()
    const allowedRoles = await api.getTargetRoles(target)
    roleIsAllowed = Object.fromEntries(allowedRoles.map(r => [r.id, true]))
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
        error = err as Error
    }
}

async function remove () {
    if (confirm(`Delete target ${target.name}?`)) {
        await api.deleteTarget(target)
        replace('/config')
    }
}

async function toggleRole (role: Role) {
    if (roleIsAllowed[role.id]) {
        await api.deleteTargetRole({
            id: target.id,
            roleId: role.id,
        })
        roleIsAllowed = { ...roleIsAllowed, [role.id]: false }
    } else {
        await api.addTargetRole({
            id: target.id,
            roleId: role.id,
        })
        roleIsAllowed = { ...roleIsAllowed, [role.id]: true }
    }
}
</script>

{#await load()}
    <DelayedSpinner />
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
    </div>

    <h4>Access instructions</h4>

    {#if target.options.kind === 'Ssh' || target.options.kind === 'MySql'}
        {#await api.getUsers()}
            <DelayedSpinner/>
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
        targetExternalHost={target.options.kind == "Http" ? target.options.externalHost : undefined}
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
            <input class="form-control"
                placeholder="Use the currently logged in user's name"
                bind:value={target.options.username}
            />
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

        <div class="d-flex">
            <Input
                class="mb-0 me-2"
                type="switch"
                label="Allow insecure SSH algorithms (e.g. for older networks devices)"
                checked={target.options.allowInsecureAlgos} />
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

    <h4 class="mt-4">Allow access for roles</h4>
    {#await loadRoles() then}
        <div class="list-group list-group-flush mb-3">
            {#each allRoles as role}
                <div
                    class="list-group-item list-group-item-action d-flex align-items-center"
                    on:click={() => toggleRole(role)}
                >
                    <Input
                        class="mb-0 me-2"
                        type="switch"
                        checked={roleIsAllowed[role.id]} />
                    <div>{role.name}</div>
                </div>
            {/each}
        </div>
    {/await}
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
