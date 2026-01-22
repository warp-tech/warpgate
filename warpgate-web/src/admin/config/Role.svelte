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
    const initPromise = init()

    let disabled = $state(false)

    async function init () {
        role = await api.getRole({ id: params.id })
        disabled = role.name === 'warpgate:admin'
        await loadFileTransferDefaults()
    }

    async function loadFileTransferDefaults() {
        try {
            fileTransferDefaults = await api.getRoleFileTransferDefaults({ id: params.id })
        } catch {
            // Defaults may not exist yet
            fileTransferDefaults = {
                allowFileUpload: true,
                allowFileDownload: true,
                allowedPaths: null,
                blockedExtensions: null,
                maxFileSize: null,
            }
        }
    }

    async function updateFileTransferDefaults() {
        if (!fileTransferDefaults) {
            return
        }

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
                                    Allow file upload (SCP/SFTP)
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
                                    Allow file download (SCP/SFTP)
                                </label>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
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
