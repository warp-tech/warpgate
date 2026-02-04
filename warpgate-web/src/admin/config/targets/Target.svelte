<script lang="ts">
    import { api, type Role, type Target, type TargetGroup } from 'admin/lib/api'
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
    import RateLimitInput from 'common/RateLimitInput.svelte'

    interface Props {
        params: { id: string };
    }

    let { params }: Props = $props()

    let error: string|undefined = $state()
    let selectedUsername: string|undefined = $state($serverInfo?.username)
    let target: Target | undefined = $state()
    let roleIsAllowed: Record<string, any> = $state({})
    let connectionsInstructionsModalOpen = $state(false)
    let groups: TargetGroup[] = $state([])

    async function init () {
        [target, groups] = await Promise.all([
            api.getTarget({ id: params.id }),
            api.listTargetGroups(),
        ])
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
                {#if target.options.kind === 'Ssh' || target.options.kind === 'MySql' || target.options.kind === 'Postgres' || target.options.kind === 'Kubernetes'}
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

                {#key connectionsInstructionsModalOpen} <!-- regenerate examples when modal opens -->
                    <ConnectionInstructions
                        targetName={target.name}
                        username={selectedUsername}
                        targetKind={target.options.kind}
                        targetExternalHost={target.options.kind === TargetKind.Http ? target.options.externalHost : undefined}
                        targetDefaultDatabaseName={
                            (target.options.kind === TargetKind.MySql || target.options.kind === TargetKind.Postgres)
                                ? target.options.defaultDatabaseName : undefined}
                    />
                {/key}
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
                    {#if target.options.kind === 'Kubernetes'}
                        Kubernetes target
                    {/if}
                    {#if target.options.kind === 'WebAdmin'}
                        This web admin interface
                    {/if}
                </div>
            </div>
        </div>

        <h4 class="mt-4">Configuration</h4>

        <div class="row">
            <div class:col-md-8={groups.length > 0} class:col-md-12={!groups.length}>
                <FormGroup floating label="Name">
                    <Input class="form-control" bind:value={target.name} />
                </FormGroup>
            </div>

            {#if groups.length > 0}
            <div class="col-md-4">
                <FormGroup floating label="Group">
                    <select class="form-control" bind:value={target.groupId}>
                        <option value={undefined}>No group</option>
                        {#each groups as group (group.id)}
                            <option value={group.id}>{group.name}</option>
                        {/each}
                    </select>
                </FormGroup>
            </div>
            {/if}
        </div>

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

        {#if target.options.kind === 'Kubernetes'}
            <FormGroup floating label="Cluster URL">
                <input class="form-control" bind:value={target.options.clusterUrl} placeholder="https://kubernetes.example.com:6443" />
            </FormGroup>

            <FormGroup floating label="Namespace">
                <input class="form-control" bind:value={target.options.namespace} placeholder="default" />
            </FormGroup>

            <h5 class="mt-3">Authentication</h5>
            <FormGroup floating label="Auth Type">
                <select class="form-control" bind:value={target.options.auth.kind}>
                    <option value="Certificate">Certificate</option>
                    <option value="Token">Token</option>
                </select>
            </FormGroup>

            {#if target.options.auth.kind === 'Certificate'}
                <FormGroup floating label="Client Certificate">
                    <textarea class="form-control" rows="8" bind:value={target.options.auth.certificate} placeholder="-----BEGIN CERTIFICATE-----"></textarea>
                </FormGroup>
                <FormGroup floating label="Client Private Key">
                    <textarea class="form-control" rows="8" bind:value={target.options.auth.privateKey} placeholder="-----BEGIN PRIVATE KEY-----"></textarea>
                </FormGroup>
            {/if}

            {#if target.options.auth.kind === 'Token'}
                <FormGroup floating label="Bearer Token">
                    <input class="form-control" type="password" autocomplete="off" bind:value={target.options.auth.token} />
                </FormGroup>
            {/if}

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

        <h4 class="mt-4">Advanced</h4>
        {#if target.options.kind === 'Postgres'}
            <FormGroup floating label="Idle timeout">
                <input
                    class="form-control"
                    type="text"
                    placeholder="10m"
                    bind:value={target.options.idleTimeout}
                    title="Human-readable duration (e.g., '30m', '1h', '2h30m'). Default: 10m"
                />
                <small class="form-text text-muted">
                    How long an authenticated session can remain idle before requiring re-authentication. Examples: 30m, 1h, 2h30m. Leave empty for default (10m).
                </small>
            </FormGroup>
        {/if}

        {#if target.options.kind === 'MySql' || target.options.kind === 'Postgres'}
            <FormGroup floating label="Default database name for connection examples">
                <input
                    class="form-control"
                    type="text"
                    placeholder="database-name"
                    bind:value={target.options.defaultDatabaseName}
                />
                <small class="form-text text-muted">
                    Default database name used in connection examples. This is only for display purposes and does not restrict which databases users can access. Leave empty to use the global default.
                </small>
            </FormGroup>
        {/if}

        <FormGroup>
            <label for="rateLimitBytesPerSecond">Global bandwidth limit</label>
            <RateLimitInput
                id="rateLimitBytesPerSecond"
                bind:value={target.rateLimitBytesPerSecond}
            />
        </FormGroup>

        <div class="mb-5"></div>
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
