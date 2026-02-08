<script lang="ts">
    import { api, type Role, type RoleFileTransferDefaults, type Target, type User } from 'admin/lib/api'
    import AsyncButton from 'common/AsyncButton.svelte'
    import { link, replace } from 'svelte-spa-router'
    import { FormGroup, Input } from '@sveltestrap/sveltestrap'
    import { stringifyError } from 'common/errors'
    import Alert from 'common/sveltestrap-s5-ports/Alert.svelte'
    import Loadable from 'common/Loadable.svelte'
    import ItemList, { type PaginatedResponse } from 'common/ItemList.svelte'
    import * as rx from 'rxjs'

    interface Props {
        params: { id: string };
    }

    let { params }: Props = $props()

    let error: string|null = $state(null)
    let role: Role | undefined = $state()
    let fileTransferDefaults: RoleFileTransferDefaults | undefined = $state()
    let sftpPermissionMode: string = $state('strict')
    const initPromise = init()

    let disabled = $state(false)
    let showAdvanced = $state(false)

    // UI state for advanced fields
    let allowedPathsText = $state('')
    let blockedExtensionsText = $state('')
    let maxFileSizeValue: number | string = $state('')
    let maxFileSizeUnit = $state('mb')

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

    async function init () {
        role = await api.getRole({ id: params.id })
        disabled = role.name === 'warpgate:admin'
        await loadFileTransferDefaults()
        await loadSftpPermissionMode()
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

    async function loadFileTransferDefaults() {
        try {
            fileTransferDefaults = await api.getRoleFileTransferDefaults({ id: params.id })
        } catch {
            // Defaults may not exist yet
            fileTransferDefaults = {
                allowFileUpload: true,
                allowFileDownload: true,
                allowedPaths: undefined,
                blockedExtensions: undefined,
                maxFileSize: undefined,
            }
        }
        // Populate UI state from loaded defaults
        allowedPathsText = pathsToText(fileTransferDefaults.allowedPaths)
        blockedExtensionsText = extensionsToText(fileTransferDefaults.blockedExtensions)
        const size = bytesToDisplay(fileTransferDefaults.maxFileSize)
        maxFileSizeValue = size.value
        maxFileSizeUnit = size.unit
    }

    async function updateFileTransferDefaults() {
        if (!fileTransferDefaults) {
            return
        }

        // Update fileTransferDefaults with advanced fields from UI state
        fileTransferDefaults.allowedPaths = textToPaths(allowedPathsText)
        fileTransferDefaults.blockedExtensions = textToExtensions(blockedExtensionsText)
        fileTransferDefaults.maxFileSize = displayToBytes(maxFileSizeValue, maxFileSizeUnit)

        try {
            fileTransferDefaults = await api.updateRoleFileTransferDefaults({
                id: params.id,
                roleFileTransferDefaults: fileTransferDefaults,
            })
            error = null
        } catch (err) {
            error = await stringifyError(err)
        }
    }

    function loadUsers (): rx.Observable<PaginatedResponse<User>> {
        return rx.from(api.getRoleUsers({
            id: params.id,
        })).pipe(
            rx.map(targets => ({
                items: targets,
                offset: 0,
                total: targets.length,
            })),
        )
    }

    function loadTargets (): rx.Observable<PaginatedResponse<Target>> {
        return rx.from(api.getRoleTargets({
            id: params.id,
        })).pipe(
            rx.map(targets => ({
                items: targets,
                offset: 0,
                total: targets.length,
            })),
        )
    }

    async function update () {
        try {
            role = await api.updateRole({
                id: params.id,
                roleDataRequest: role!,
            })
        } catch (err) {
            error = await stringifyError(err)
        }
    }

    async function remove () {
        if (confirm(`Delete role ${role!.name}?`)) {
            await api.deleteRole(role!)
            replace('/config/roles')
        }
    }
</script>

<div class="container-max-md">
    <Loadable promise={initPromise}>
        <div class="page-summary-bar">
            <div>
                <h1>{role!.name}</h1>
                <div class="text-muted">role</div>
            </div>
        </div>

        <FormGroup floating label="Name">
            <Input
                bind:value={role!.name}
                disabled={disabled}
            />
        </FormGroup>

        <FormGroup floating label="Description">
            <Input
                bind:value={role!.description}
                disabled={disabled}
            />
        </FormGroup>

        <h4 class="mt-4">File Transfer Defaults</h4>
        <p class="text-muted small">
            These are the default file transfer permissions for SSH targets. Targets can override these settings.
        </p>

        {#if fileTransferDefaults}
            <div class="card mb-3">
                <div class="card-body">
                    <div class="row">
                        <div class="col-md-6">
                            <div class="form-check form-switch mb-2">
                                <input
                                    class="form-check-input"
                                    type="checkbox"
                                    id="allowUpload"
                                    bind:checked={fileTransferDefaults.allowFileUpload}
                                    disabled={disabled}
                                    onchange={updateFileTransferDefaults}
                                />
                                <label class="form-check-label" for="allowUpload">
                                    Allow file upload (SFTP)
                                </label>
                            </div>
                        </div>
                        <div class="col-md-6">
                            <div class="form-check form-switch mb-2">
                                <input
                                    class="form-check-input"
                                    type="checkbox"
                                    id="allowDownload"
                                    bind:checked={fileTransferDefaults.allowFileDownload}
                                    disabled={disabled}
                                    onchange={updateFileTransferDefaults}
                                />
                                <label class="form-check-label" for="allowDownload">
                                    Allow file download (SFTP)
                                </label>
                            </div>
                        </div>
                    </div>

                    <!-- Advanced Restrictions Toggle -->
                    <button
                        type="button"
                        class="btn btn-link btn-sm text-muted p-0 mt-2 text-decoration-none"
                        onclick={() => { showAdvanced = !showAdvanced }}
                    >
                        {showAdvanced ? '▼' : '▶'} Advanced Restrictions
                    </button>

                    {#if showAdvanced}
                        <div class="mt-3 pt-3 border-top">
                            <!-- Allowed Paths -->
                            <div class="mb-3">
                                <label for="allowedPaths" class="form-label">Allowed Paths</label>
                                <textarea
                                    id="allowedPaths"
                                    class="form-control"
                                    rows="3"
                                    placeholder="/home/user/*&#10;/uploads/**&#10;/shared/docs/*"
                                    bind:value={allowedPathsText}
                                    disabled={disabled}
                                    onchange={updateFileTransferDefaults}
                                ></textarea>
                                <small class="text-muted">
                                    One path per line. Glob patterns: <code>/*</code> matches one level, <code>/**</code> matches all subdirectories.
                                    Leave empty to allow all paths.
                                </small>
                            </div>

                            <!-- Blocked Extensions -->
                            <div class="mb-3">
                                <label for="blockedExtensions" class="form-label">Blocked Extensions</label>
                                <input
                                    type="text"
                                    id="blockedExtensions"
                                    class="form-control"
                                    placeholder=".exe, .sh, .bat, .cmd"
                                    bind:value={blockedExtensionsText}
                                    disabled={disabled}
                                    onchange={updateFileTransferDefaults}
                                />
                                <small class="text-muted">
                                    Comma-separated file extensions to block (case-insensitive). Leave empty to allow all extensions.
                                </small>
                            </div>

                            <!-- Max File Size -->
                            <div class="mb-3">
                                <label for="maxFileSize" class="form-label">Max File Size</label>
                                <div class="row g-2">
                                    <div class="col-8">
                                        <input
                                            type="number"
                                            id="maxFileSize"
                                            class="form-control"
                                            min="0"
                                            placeholder="No limit"
                                            bind:value={maxFileSizeValue}
                                            disabled={disabled}
                                            onchange={updateFileTransferDefaults}
                                        />
                                    </div>
                                    <div class="col-4">
                                        <select
                                            class="form-select"
                                            bind:value={maxFileSizeUnit}
                                            disabled={disabled}
                                            onchange={updateFileTransferDefaults}
                                        >
                                            <option value="bytes">Bytes</option>
                                            <option value="kb">KB</option>
                                            <option value="mb">MB</option>
                                            <option value="gb">GB</option>
                                        </select>
                                    </div>
                                </div>
                                <small class="text-muted">
                                    Maximum file size for uploads. Leave empty for no limit.
                                </small>
                            </div>
                        </div>
                    {/if}
                </div>
            </div>

            {#if sftpPermissionMode === 'permissive' && (!fileTransferDefaults.allowFileUpload || !fileTransferDefaults.allowFileDownload)}
                <Alert color="warning">
                    <strong>Bypass possible:</strong> SFTP restrictions are active but the instance is in <strong>permissive mode</strong>.
                    Users can bypass SFTP restrictions via shell or SCP.
                    <a href="#/config/parameters">Change to strict mode</a> to block shell/exec when SFTP restrictions apply.
                </Alert>
            {/if}
        {/if}
    </Loadable>

    {#if error}
        <Alert color="danger">{error}</Alert>
    {/if}

    <div class="d-flex">
        <AsyncButton
        color="primary"
            disabled={disabled}
            class="ms-auto"
            click={update}
        >Update</AsyncButton>

        <AsyncButton
            class="ms-2"
            disabled={disabled}
            color="danger"
            click={remove}
        >Remove</AsyncButton>
    </div>


    <h4 class="mt-4">Assigned users</h4>

    <ItemList load={loadUsers}>
        {#snippet item(user)}
            <a
                class="list-group-item list-group-item-action"
                href="/config/users/{user.id}"
                use:link>
                <div>
                    <strong class="me-auto">
                        {user.username}
                    </strong>
                    {#if user.description}
                        <small class="d-block text-muted">{user.description}</small>
                    {/if}
                </div>
            </a>
        {/snippet}
        {#snippet empty()}
            <Alert color="info">This role has no users assigned to it</Alert>
        {/snippet}
    </ItemList>

    <h4 class="mt-4">Assigned targets</h4>

    <ItemList load={loadTargets}>
        {#snippet item(target)}
            <a
                class="list-group-item list-group-item-action"
                href="/config/targets/{target.id}"
                use:link>
                <div class="me-auto">
                    <strong>
                        {target.name}
                    </strong>
                    {#if target.description}
                        <small class="d-block text-muted">{target.description}</small>
                    {/if}
                </div>
            </a>
        {/snippet}
        {#snippet empty()}
            <Alert color="info">This role has no targets assigned to it</Alert>
        {/snippet}
    </ItemList>
</div>
