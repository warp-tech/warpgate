<script lang="ts">
    import { api, type Role, type RoleFileTransferDefaults, type Target, type TargetGroup } from 'admin/lib/api'
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

    // Nullable values mean "inherit from role"
    interface FileTransferPermission {
        allowFileUpload: boolean | null
        allowFileDownload: boolean | null
        allowedPaths: string[] | null
        blockedExtensions: string[] | null
        maxFileSize: number | null
    }

    let { params }: Props = $props()

    let error: string|undefined = $state()
    let selectedUsername: string|undefined = $state($serverInfo?.username)
    let target: Target | undefined = $state()
    let roleIsAllowed: Record<string, any> = $state({})
    let fileTransferPermissions: Record<string, FileTransferPermission> = $state({})
    let roleDefaults: Record<string, RoleFileTransferDefaults> = $state({})
    let connectionsInstructionsModalOpen = $state(false)
    let groups: TargetGroup[] = $state([])
    let expandedFileTransfer: Record<string, boolean> = $state({})

    async function init () {
        [target, groups] = await Promise.all([
            api.getTarget({ id: params.id }),
            api.listTargetGroups(),
        ])
    }

    async function loadRoles (): Promise<Role[]> {
        const allRoles = await api.getRoles()
        const allowedRoles = await api.getTargetRoles(target!)
        roleIsAllowed = Object.fromEntries(allowedRoles.map(r => [r.id, true]))
        // Load file transfer permissions and role defaults for allowed roles
        await loadAllFileTransferPermissions()
        await loadAllRoleDefaults(allRoles)
        return allRoles
    }

    async function loadRoleDefaults(roleId: string) {
        try {
            const defaults = await api.getRoleFileTransferDefaults({ id: roleId })
            roleDefaults = { ...roleDefaults, [roleId]: defaults }
        } catch {
            // Defaults not available
            roleDefaults = { ...roleDefaults, [roleId]: {
                allowFileUpload: true,
                allowFileDownload: true,
                allowedPaths: null,
                blockedExtensions: null,
                maxFileSize: null,
            } }
        }
    }

    async function loadAllRoleDefaults(allRoles: Role[]) {
        for (const role of allRoles) {
            await loadRoleDefaults(role.id)
        }
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
            // Remove file transfer permissions from state
            const { [role.id]: _removed, ...newPerms } = fileTransferPermissions
            void _removed
            fileTransferPermissions = newPerms
        } else {
            await api.addTargetRole({
                id: target!.id,
                roleId: role.id,
            })
            roleIsAllowed = { ...roleIsAllowed, [role.id]: true }
            // Load file transfer permissions for the new role
            await loadFileTransferPermission(role.id)
        }
    }

    async function loadFileTransferPermission (roleId: string) {
        try {
            const perm = await api.getTargetRoleFileTransferPermission({
                id: target!.id,
                roleId: roleId,
            })
            fileTransferPermissions = { ...fileTransferPermissions, [roleId]: perm }
        } catch {
            // Assignment may not have permissions yet - use null (inherit)
            fileTransferPermissions = { ...fileTransferPermissions, [roleId]: {
                allowFileUpload: null,
                allowFileDownload: null,
                allowedPaths: null,
                blockedExtensions: null,
                maxFileSize: null,
            } }
        }
    }

    async function loadAllFileTransferPermissions () {
        for (const roleId of Object.keys(roleIsAllowed).filter(id => roleIsAllowed[id])) {
            await loadFileTransferPermission(roleId)
        }
    }

    async function updateFileTransferPermission (roleId: string, field: keyof FileTransferPermission, value: boolean | null) {
        const current = fileTransferPermissions[roleId] || {
            allowFileUpload: null,
            allowFileDownload: null,
            allowedPaths: null,
            blockedExtensions: null,
            maxFileSize: null,
        }

        const updated = { ...current, [field]: value }

        try {
            const perm = await api.updateTargetRoleFileTransferPermission({
                id: target!.id,
                roleId: roleId,
                fileTransferPermissionData: updated,
            })
            fileTransferPermissions = { ...fileTransferPermissions, [roleId]: perm }
        } catch (err) {
            error = await stringifyError(err)
        }
    }

    function getPermissionState(roleId: string, field: 'allowFileUpload' | 'allowFileDownload'): 'inherit' | 'allow' | 'deny' {
        const value = fileTransferPermissions[roleId]?.[field]
        if (value === null || value === undefined) {
            return 'inherit'
        }
        return value ? 'allow' : 'deny'
    }

    function setPermissionState(roleId: string, field: 'allowFileUpload' | 'allowFileDownload', state: 'inherit' | 'allow' | 'deny') {
        const value = state === 'inherit' ? null : state === 'allow'
        updateFileTransferPermission(roleId, field, value)
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
        {/if}

        <h4 class="mt-4">Allow access for roles</h4>
        <Loadable promise={loadRoles()}>
            {#snippet children(roles: Role[])}
                <div class="list-group list-group-flush mb-3">
                    {#each roles as role (role.id)}
                        <div class="list-group-item">
                            <label
                                for="role-{role.id}"
                                class="d-flex align-items-center"
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
                            {#if roleIsAllowed[role.id] && target?.options.kind === 'Ssh'}
                                <div class="ms-4 mt-1">
                                    <button
                                        type="button"
                                        class="btn btn-link btn-sm text-muted p-0 text-decoration-none"
                                        onclick={() => { expandedFileTransfer[role.id] = !expandedFileTransfer[role.id] }}
                                    >
                                        {expandedFileTransfer[role.id] ? '▼' : '▶'} File Transfer
                                        {#if !expandedFileTransfer[role.id]}
                                            <span class="text-muted small">
                                                (Upload: {getPermissionState(role.id, 'allowFileUpload')}, Download: {getPermissionState(role.id, 'allowFileDownload')})
                                            </span>
                                        {/if}
                                    </button>
                                    {#if expandedFileTransfer[role.id]}
                                        <div class="ps-3 mt-1 border-start">
                                            <div class="row g-2">
                                                <div class="col-auto">
                                                    <div class="input-group input-group-sm">
                                                        <span class="input-group-text">Upload</span>
                                                        <select
                                                            class="form-select form-select-sm"
                                                            value={getPermissionState(role.id, 'allowFileUpload')}
                                                            onchange={(e) => setPermissionState(role.id, 'allowFileUpload', (e.target as HTMLSelectElement).value as 'inherit' | 'allow' | 'deny')}
                                                        >
                                                            <option value="inherit">Inherit ({roleDefaults[role.id]?.allowFileUpload ? 'allow' : 'deny'})</option>
                                                            <option value="allow">Allow</option>
                                                            <option value="deny">Deny</option>
                                                        </select>
                                                    </div>
                                                </div>
                                                <div class="col-auto">
                                                    <div class="input-group input-group-sm">
                                                        <span class="input-group-text">Download</span>
                                                        <select
                                                            class="form-select form-select-sm"
                                                            value={getPermissionState(role.id, 'allowFileDownload')}
                                                            onchange={(e) => setPermissionState(role.id, 'allowFileDownload', (e.target as HTMLSelectElement).value as 'inherit' | 'allow' | 'deny')}
                                                        >
                                                            <option value="inherit">Inherit ({roleDefaults[role.id]?.allowFileDownload ? 'allow' : 'deny'})</option>
                                                            <option value="allow">Allow</option>
                                                            <option value="deny">Deny</option>
                                                        </select>
                                                    </div>
                                                </div>
                                            </div>
                                        </div>
                                    {/if}
                                </div>
                            {/if}
                        </div>
                    {/each}
                </div>
            {/snippet}
        </Loadable>

        <h4 class="mt-4">Traffic</h4>
        <FormGroup class="mb-5">
            <label for="rateLimitBytesPerSecond">Global bandwidth limit</label>
            <RateLimitInput
                id="rateLimitBytesPerSecond"
                bind:value={target.rateLimitBytesPerSecond}
            />
        </FormGroup>
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
