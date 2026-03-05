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
        allowedPaths?: string[] | null
        blockedExtensions?: string[] | null
        maxFileSize?: number | null
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
    let expandedAdvanced: Record<string, boolean> = $state({})
    let sftpPermissionMode: string = $state('strict')

    // UI state for advanced fields per role
    let allowedPathsText: Record<string, string> = $state({})
    let blockedExtensionsText: Record<string, string> = $state({})
    let maxFileSizeValue: Record<string, number | string> = $state({})
    let maxFileSizeUnit: Record<string, string> = $state({})

    // Convert between API format and UI format
    function pathsToText(paths: string[] | undefined | null): string {
        return paths?.join('\n') ?? ''
    }
    function textToPaths(text: string): string[] | undefined {
        const paths = text.split('\n').map(p => p.trim()).filter(p => p.length > 0)
        return paths.length > 0 ? paths : undefined
    }
    function extensionsToText(exts: string[] | undefined | null): string {
        return exts?.join(', ') ?? ''
    }
    function textToExtensions(text: string): string[] | undefined {
        const exts = text.split(',').map(e => e.trim()).filter(e => e.length > 0)
        return exts.length > 0 ? exts : undefined
    }
    function bytesToDisplay(bytes: number | undefined | null): { value: number | string, unit: string } {
        if (bytes === undefined || bytes === null) {
            return { value: '', unit: 'mb' }
        }
        if (bytes >= 1024 * 1024 * 1024) {
            return { value: Math.round(bytes / (1024 * 1024 * 1024)), unit: 'gb' }
        }
        if (bytes >= 1024 * 1024) {
            return { value: Math.round(bytes / (1024 * 1024)), unit: 'mb' }
        }
        if (bytes >= 1024) {
            return { value: Math.round(bytes / 1024), unit: 'kb' }
        }
        return { value: bytes, unit: 'bytes' }
    }
    function displayToBytes(value: number | string, unit: string): number | undefined {
        if (value === '' || value === undefined || value === null) {
            return undefined
        }
        const num = typeof value === 'string' ? parseFloat(value) : value
        if (isNaN(num)) {
            return undefined
        }
        switch (unit) {
            case 'gb': return Math.round(num * 1024 * 1024 * 1024)
            case 'mb': return Math.round(num * 1024 * 1024)
            case 'kb': return Math.round(num * 1024)
            default: return Math.round(num)
        }
    }

    async function loadSftpPermissionMode() {
        try {
            const parameters = await api.getParameters({})
            sftpPermissionMode = parameters.sftpPermissionMode
        } catch {
            // Fallback to strict if we can't load
            sftpPermissionMode = 'strict'
        }
    }

    async function init () {
        await loadSftpPermissionMode();
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
                allowedPaths: undefined,
                blockedExtensions: undefined,
                maxFileSize: undefined,
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
            fileTransferPermissions = { ...fileTransferPermissions, [roleId]: {
                ...perm,
                allowFileUpload: perm.allowFileUpload ?? null,
                allowFileDownload: perm.allowFileDownload ?? null,
            } }
            // Populate UI state for advanced fields
            syncAdvancedFieldsFromPerm(roleId, perm)
        } catch {
            // Assignment may not have permissions yet - use null (inherit)
            fileTransferPermissions = { ...fileTransferPermissions, [roleId]: {
                allowFileUpload: null,
                allowFileDownload: null,
                allowedPaths: undefined,
                blockedExtensions: undefined,
                maxFileSize: undefined,
            } }
            syncAdvancedFieldsFromPerm(roleId, { allowedPaths: undefined, blockedExtensions: undefined, maxFileSize: undefined })
        }
    }

    function syncAdvancedFieldsFromPerm(roleId: string, perm: { allowedPaths?: string[] | null, blockedExtensions?: string[] | null, maxFileSize?: number | null }) {
        allowedPathsText = { ...allowedPathsText, [roleId]: pathsToText(perm.allowedPaths) }
        blockedExtensionsText = { ...blockedExtensionsText, [roleId]: extensionsToText(perm.blockedExtensions) }
        const size = bytesToDisplay(perm.maxFileSize)
        maxFileSizeValue = { ...maxFileSizeValue, [roleId]: size.value }
        maxFileSizeUnit = { ...maxFileSizeUnit, [roleId]: size.unit }
    }

    async function loadAllFileTransferPermissions () {
        for (const roleId of Object.keys(roleIsAllowed).filter(id => roleIsAllowed[id])) {
            await loadFileTransferPermission(roleId)
        }
    }

    async function updateFileTransferPermission (roleId: string, field: keyof FileTransferPermission, value: boolean | null | string[] | number | undefined) {
        const current = fileTransferPermissions[roleId] || {
            allowFileUpload: null,
            allowFileDownload: null,
            allowedPaths: undefined,
            blockedExtensions: undefined,
            maxFileSize: undefined,
        }

        const updated = { ...current, [field]: value }

        try {
            const perm = await api.updateTargetRoleFileTransferPermission({
                id: target!.id,
                roleId: roleId,
                fileTransferPermissionData: {
                    allowFileUpload: updated.allowFileUpload ?? undefined,
                    allowFileDownload: updated.allowFileDownload ?? undefined,
                    allowedPaths: updated.allowedPaths ?? undefined,
                    blockedExtensions: updated.blockedExtensions ?? undefined,
                    maxFileSize: updated.maxFileSize ?? undefined,
                },
            })
            fileTransferPermissions = { ...fileTransferPermissions, [roleId]: {
                ...perm,
                allowFileUpload: perm.allowFileUpload ?? null,
                allowFileDownload: perm.allowFileDownload ?? null,
            } }
            // Sync UI state from response
            syncAdvancedFieldsFromPerm(roleId, perm)
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

    // 3-state helpers for advanced fields: 'inherit' | 'set' | 'clear'
    function getAdvancedState(roleId: string, field: 'allowedPaths' | 'blockedExtensions' | 'maxFileSize'): 'inherit' | 'set' {
        const value = fileTransferPermissions[roleId]?.[field]
        if (value === null || value === undefined) {
            return 'inherit'
        }
        return 'set'
    }

    function getInheritedAdvancedValue(roleId: string, field: 'allowedPaths' | 'blockedExtensions' | 'maxFileSize'): string {
        const defaults = roleDefaults[roleId]
        if (!defaults) {
            return 'none'
        }
        if (field === 'allowedPaths') {
            return defaults.allowedPaths?.join(', ') || 'all paths'
        }
        if (field === 'blockedExtensions') {
            return defaults.blockedExtensions?.join(', ') || 'none'
        }
        if (field === 'maxFileSize') {
            if (!defaults.maxFileSize) {
                return 'no limit'
            }
            const d = bytesToDisplay(defaults.maxFileSize)
            return `${d.value} ${d.unit.toUpperCase()}`
        }
        return 'none'
    }

    async function updateAdvancedField(roleId: string, field: 'allowedPaths' | 'blockedExtensions' | 'maxFileSize') {
        if (field === 'allowedPaths') {
            const paths = textToPaths(allowedPathsText[roleId] ?? '')
            await updateFileTransferPermission(roleId, 'allowedPaths', paths)
        } else if (field === 'blockedExtensions') {
            const exts = textToExtensions(blockedExtensionsText[roleId] ?? '')
            await updateFileTransferPermission(roleId, 'blockedExtensions', exts)
        } else if (field === 'maxFileSize') {
            const bytes = displayToBytes(maxFileSizeValue[roleId] ?? '', maxFileSizeUnit[roleId] ?? 'mb')
            await updateFileTransferPermission(roleId, 'maxFileSize', bytes)
        }
    }

    async function clearAdvancedField(roleId: string, field: 'allowedPaths' | 'blockedExtensions' | 'maxFileSize') {
        if (field === 'allowedPaths') {
            allowedPathsText = { ...allowedPathsText, [roleId]: '' }
        } else if (field === 'blockedExtensions') {
            blockedExtensionsText = { ...blockedExtensionsText, [roleId]: '' }
        } else if (field === 'maxFileSize') {
            maxFileSizeValue = { ...maxFileSizeValue, [roleId]: '' }
            maxFileSizeUnit = { ...maxFileSizeUnit, [roleId]: 'mb' }
        }
        await updateFileTransferPermission(roleId, field, undefined)
    }

    function hasAnyRestrictions(): boolean {
        for (const roleId of Object.keys(fileTransferPermissions)) {
            const perm = fileTransferPermissions[roleId]
            const defaults = roleDefaults[roleId]

            // Calculate effective permission (considering inheritance)
            const effectiveUpload = perm?.allowFileUpload ?? defaults?.allowFileUpload ?? true
            const effectiveDownload = perm?.allowFileDownload ?? defaults?.allowFileDownload ?? true

            if (!effectiveUpload || !effectiveDownload) {
                return true
            }
        }
        return false
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
                    <textarea class="form-control" rows="8" bind:value={target.options.auth.privateKey} placeholder="-----BEGIN RSA PRIVATE KEY-----"></textarea>
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

                                            <!-- Advanced Restrictions Toggle -->
                                            <button
                                                type="button"
                                                class="btn btn-link btn-sm text-muted p-0 mt-2 text-decoration-none"
                                                onclick={() => { expandedAdvanced[role.id] = !expandedAdvanced[role.id] }}
                                            >
                                                {expandedAdvanced[role.id] ? '▼' : '▶'} Advanced Restrictions
                                            </button>

                                            {#if expandedAdvanced[role.id]}
                                                <div class="mt-2 pt-2 border-top">
                                                    <!-- Allowed Paths -->
                                                    <div class="mb-2">
                                                        <div class="d-flex align-items-center gap-2 mb-1">
                                                            <label for="allowedPaths-{role.id}" class="form-label mb-0 small">Allowed Paths</label>
                                                            {#if getAdvancedState(role.id, 'allowedPaths') === 'inherit'}
                                                                <span class="badge bg-secondary">Inherit: {getInheritedAdvancedValue(role.id, 'allowedPaths')}</span>
                                                            {:else}
                                                                <button
                                                                    type="button"
                                                                    class="btn btn-outline-secondary btn-sm py-0 px-1"
                                                                    style="font-size: 0.7rem;"
                                                                    onclick={() => clearAdvancedField(role.id, 'allowedPaths')}
                                                                >Reset to inherit</button>
                                                            {/if}
                                                        </div>
                                                        <textarea
                                                            id="allowedPaths-{role.id}"
                                                            class="form-control form-control-sm"
                                                            rows="2"
                                                            placeholder={getAdvancedState(role.id, 'allowedPaths') === 'inherit' ? `Inherited: ${getInheritedAdvancedValue(role.id, 'allowedPaths')}` : '/home/user/*\n/uploads/**'}
                                                            bind:value={allowedPathsText[role.id]}
                                                            onchange={() => updateAdvancedField(role.id, 'allowedPaths')}
                                                        ></textarea>
                                                        <small class="text-muted">One path per line. Glob patterns supported. Leave empty to inherit.</small>
                                                    </div>

                                                    <!-- Blocked Extensions -->
                                                    <div class="mb-2">
                                                        <div class="d-flex align-items-center gap-2 mb-1">
                                                            <label for="blockedExtensions-{role.id}" class="form-label mb-0 small">Blocked Extensions</label>
                                                            {#if getAdvancedState(role.id, 'blockedExtensions') === 'inherit'}
                                                                <span class="badge bg-secondary">Inherit: {getInheritedAdvancedValue(role.id, 'blockedExtensions')}</span>
                                                            {:else}
                                                                <button
                                                                    type="button"
                                                                    class="btn btn-outline-secondary btn-sm py-0 px-1"
                                                                    style="font-size: 0.7rem;"
                                                                    onclick={() => clearAdvancedField(role.id, 'blockedExtensions')}
                                                                >Reset to inherit</button>
                                                            {/if}
                                                        </div>
                                                        <input
                                                            type="text"
                                                            id="blockedExtensions-{role.id}"
                                                            class="form-control form-control-sm"
                                                            placeholder={getAdvancedState(role.id, 'blockedExtensions') === 'inherit' ? `Inherited: ${getInheritedAdvancedValue(role.id, 'blockedExtensions')}` : '.exe, .sh, .bat'}
                                                            bind:value={blockedExtensionsText[role.id]}
                                                            onchange={() => updateAdvancedField(role.id, 'blockedExtensions')}
                                                        />
                                                        <small class="text-muted">Comma-separated extensions. Leave empty to inherit.</small>
                                                    </div>

                                                    <!-- Max File Size -->
                                                    <div class="mb-2">
                                                        <div class="d-flex align-items-center gap-2 mb-1">
                                                            <label for="maxFileSize-{role.id}" class="form-label mb-0 small">Max File Size</label>
                                                            {#if getAdvancedState(role.id, 'maxFileSize') === 'inherit'}
                                                                <span class="badge bg-secondary">Inherit: {getInheritedAdvancedValue(role.id, 'maxFileSize')}</span>
                                                            {:else}
                                                                <button
                                                                    type="button"
                                                                    class="btn btn-outline-secondary btn-sm py-0 px-1"
                                                                    style="font-size: 0.7rem;"
                                                                    onclick={() => clearAdvancedField(role.id, 'maxFileSize')}
                                                                >Reset to inherit</button>
                                                            {/if}
                                                        </div>
                                                        <div class="row g-1">
                                                            <div class="col-8">
                                                                <input
                                                                    type="number"
                                                                    id="maxFileSize-{role.id}"
                                                                    class="form-control form-control-sm"
                                                                    min="0"
                                                                    placeholder={getAdvancedState(role.id, 'maxFileSize') === 'inherit' ? `Inherited: ${getInheritedAdvancedValue(role.id, 'maxFileSize')}` : 'No limit'}
                                                                    bind:value={maxFileSizeValue[role.id]}
                                                                    onchange={() => updateAdvancedField(role.id, 'maxFileSize')}
                                                                />
                                                            </div>
                                                            <div class="col-4">
                                                                <select
                                                                    class="form-select form-select-sm"
                                                                    bind:value={maxFileSizeUnit[role.id]}
                                                                    onchange={() => updateAdvancedField(role.id, 'maxFileSize')}
                                                                >
                                                                    <option value="bytes">Bytes</option>
                                                                    <option value="kb">KB</option>
                                                                    <option value="mb">MB</option>
                                                                    <option value="gb">GB</option>
                                                                </select>
                                                            </div>
                                                        </div>
                                                        <small class="text-muted">Leave empty to inherit from role.</small>
                                                    </div>
                                                </div>
                                            {/if}
                                        </div>
                                    {/if}
                                </div>
                            {/if}
                        </div>
                    {/each}
                </div>
            {/snippet}
        </Loadable>

        {#if target?.options.kind === 'Ssh' && sftpPermissionMode === 'permissive' && hasAnyRestrictions()}
            <Alert color="warning">
                <strong>Bypass possible:</strong> SFTP restrictions are active for some roles but the instance is in <strong>permissive mode</strong>.
                Users can bypass SFTP restrictions via shell or SCP.
                <a href="#/config/parameters">Change to strict mode</a> to block shell/exec when SFTP restrictions apply.
            </Alert>
        {/if}

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
