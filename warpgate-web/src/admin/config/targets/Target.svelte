<script lang="ts">
    import { api, type Role, type Target } from 'admin/lib/api'
    import AsyncButton from 'common/AsyncButton.svelte'
    import ConnectionInstructions from 'common/ConnectionInstructions.svelte'
    import { TargetKind } from 'gateway/lib/api'
    import { serverInfo } from 'gateway/lib/store'
    import { replace } from 'svelte-spa-router'
    import { Button, FormGroup, Input, Modal, ModalBody, ModalFooter } from '@sveltestrap/sveltestrap'
    import TlsConfiguration from '../../TlsConfiguration.svelte'
    import { stringifyError } from 'common/errors'
    import Alert from 'common/sveltestrap-s5-ports/Alert.svelte'
    import Loadable from 'common/Loadable.svelte'
    import ModalHeader from 'common/sveltestrap-s5-ports/ModalHeader.svelte'
    import TargetSshOptions from './ssh/Options.svelte'

    interface Props {
        params: { id: string };
    }

    let { params }: Props = $props()

    let error: string|undefined = $state()
    let selectedUsername: string|undefined = $state($serverInfo?.username)
    let target: Target | undefined = $state()
    let roleIsAllowed: Record<string, any> = $state({})
    let connectionsInstructionsModalOpen = $state(false)

    async function init () {
        target = await api.getTarget({ id: params.id })
    }

    async function loadRoles () {
        const allRoles = await api.getRoles()
        const allowedRoles = await api.getTargetRoles(target!)
        roleIsAllowed = Object.fromEntries(allowedRoles.map(r => [r.id, true]))
        return allRoles
    }

    async function update () {
        try {
            if (target!.options.kind === 'Http') {
                target!.options.externalHost = target!.options.externalHost || undefined
            }
            target = await api.updateTarget({
                id: params.id,
                targetDataRequest: target!,
            })
        } catch (err) {
            error = await stringifyError(err)
        }
    }

    async function remove () {
        if (confirm(`Delete target ${target!.name}?`)) {
            await api.deleteTarget(target!)
            replace('/config/targets')
        }
    }

    async function toggleRole (role: Role) {
        if (roleIsAllowed[role.id]) {
            await api.deleteTargetRole({
                id: target!.id,
                roleId: role.id,
            })
            roleIsAllowed = { ...roleIsAllowed, [role.id]: false }
        } else {
            await api.addTargetRole({
                id: target!.id,
                roleId: role.id,
            })
            roleIsAllowed = { ...roleIsAllowed, [role.id]: true }
        }
    }
</script>

<div class="container-max-md">
    <Loadable promise={init()}>
    {#if target}
        <Modal isOpen={connectionsInstructionsModalOpen} toggle={() => connectionsInstructionsModalOpen = false}>
            <ModalHeader>
                Access instructions
            </ModalHeader>
            <ModalBody>
                {#if target.options.kind === 'Ssh' || target.options.kind === 'MySql' || target.options.kind === 'Postgres'}
                    <Loadable promise={api.getUsers()}>
                        {#snippet children(users)}
                            <FormGroup floating label="Select a user">
                                <select bind:value={selectedUsername} class="form-control">
                                    {#each users as user (user.id)}
                                        <option value={user.username}>
                                            {user.username}
                                        </option>
                                    {/each}
                                </select>
                            </FormGroup>
                        {/snippet}
                    </Loadable>
                {/if}

                <ConnectionInstructions
                    targetName={target.name}
                    username={selectedUsername}
                    targetKind={{
                        Ssh: TargetKind.Ssh,
                        WebAdmin: TargetKind.WebAdmin,
                        Http: TargetKind.Http,
                        MySql: TargetKind.MySql,
                        Postgres: TargetKind.Postgres,
                    }[target.options.kind ?? '']}
                    targetExternalHost={target.options.kind === 'Http' ? target.options.externalHost : undefined}
                />
            </ModalBody>
            <ModalFooter>
                <Button
                    color="secondary"
                    class="modal-button"
                    block
                    on:click={() => connectionsInstructionsModalOpen = false }
                >
                    Close
                </Button>
            </ModalFooter>
        </Modal>

        <div class="page-summary-bar">
            <div>
                <h1>{target.name}</h1>
                <div class="text-muted">
                    {#if target.options.kind === 'MySql'}
                        MySQL target
                    {/if}
                    {#if target.options.kind === 'Postgres'}
                        PostgreSQL target
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

        <h4 class="mt-4">Configuration</h4>

        <FormGroup floating label="Name">
            <Input class="form-control" bind:value={target.name} />
        </FormGroup>

        <FormGroup floating label="Description">
            <Input bind:value={target.description} />
        </FormGroup>

        {#if target.options.kind === 'Ssh'}
            <TargetSshOptions id={target.id} options={target.options} />
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

        {#if target.options.kind === 'MySql' || target.options.kind === 'Postgres'}
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
        <Loadable promise={loadRoles()}>
            {#snippet children(roles)}
                <div class="list-group list-group-flush mb-3">
                    {#each roles as role (role.id)}
                        <label
                            for="role-{role.id}"
                            class="list-group-item list-group-item-action d-flex align-items-center"
                        >
                            <Input
                                id="role-{role.id}"
                                class="mb-0 me-2"
                                type="switch"
                                on:change={() => toggleRole(role)}
                                checked={roleIsAllowed[role.id]} />
                            <div>
                                <div>{role.name}</div>
                                {#if role.description}
                                    <small class="text-muted">{role.description}</small>
                                {/if}
                            </div>
                        </label>
                    {/each}
                </div>
            {/snippet}
        </Loadable>
    {/if}
    </Loadable>

    {#if error}
        <Alert color="danger">{error}</Alert>
    {/if}

    <div class="d-flex">
        <Button
            color="secondary"
            class="me-3"
            on:click={() => connectionsInstructionsModalOpen = true}
        >Access instructions</Button>

        <AsyncButton
        color="primary"
            class="ms-auto"
            click={update}
        >Update configuration</AsyncButton>

        <AsyncButton
            class="ms-2"
            color="danger"
            click={remove}
        >Remove</AsyncButton>
    </div>
</div>
