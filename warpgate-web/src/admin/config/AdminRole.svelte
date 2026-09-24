<script lang="ts">
    import { type AdminRole, api, type User } from 'admin/lib/api'
    import { stringifyError } from 'common/errors'
    import ItemList, { type PaginatedResponse } from 'common/ItemList.svelte'
    import Loadable from 'common/Loadable.svelte'
    import * as rx from 'rxjs'
    import { link, replace } from 'svelte-spa-router'
    import Button from 'ui/Button.svelte'
    import Callout from 'ui/Callout.svelte'
    import ConfirmDialog from 'ui/ConfirmDialog.svelte'
    import Input from 'ui/Input.svelte'
    import StatusMarker from 'ui/StatusMarker.svelte'
    import Tooltip from 'ui/Tooltip.svelte'
    import {
        ADMIN_PERMISSIONS,
        type AdminPermissionDef,
        type AdminRolePermissionKey,
        adminPermissions,
    } from '../lib/store'

    interface Props {
        params: { id: string }
    }

    let { params }: Props = $props()

    let error: string | null = $state(null)
    let role: AdminRole | undefined = $state()
    const initPromise = init()

    let disabled = $state(false)

    async function init() {
        role = await api.getAdminRole({ id: params.id })
        disabled =
            role.name === 'warpgate:admin' ||
            !$adminPermissions.adminRolesManage
        return role
    }

    function loadUsers(): rx.Observable<PaginatedResponse<User>> {
        return rx.from(api.getAdminRoleUsers({ id: params.id })).pipe(
            rx.map(users => ({
                items: users,
                offset: 0,
                total: users.length,
            })),
        )
    }

    // build grouped permission list by category for rendering
    interface PermGroup {
        category: string
        perms: AdminPermissionDef[]
    }
    const permGroups: PermGroup[] = []

    const map: Record<string, AdminPermissionDef[]> = {}
    for (const p of ADMIN_PERMISSIONS) {
        const cat = p.category ?? 'Other'
        map[cat] ??= []
        map[cat].push(p)
    }
    for (const [cat, perms] of Object.entries(map)) {
        permGroups.push({ category: cat, perms })
    }

    // recursively enables a permission and all of its parent dependencies
    function enablePermissionDependenciesRecursive(
        obj: AdminRole,
        key: AdminRolePermissionKey,
    ) {
        obj[key] = true
        const def = ADMIN_PERMISSIONS.find(p => p.key === key)
        if (def?.deps) {
            for (const parent of def.deps) {
                enablePermissionDependenciesRecursive(obj, parent)
            }
        }
    }

    // recursively disables a permission and any children that depend on it
    function disablePermissionDependantsRecursive(
        obj: AdminRole,
        key: AdminRolePermissionKey,
    ) {
        obj[key] = false
        // find all permissions that list this key as a dependency
        for (const p of ADMIN_PERMISSIONS) {
            if (p.deps?.includes(key)) {
                disablePermissionDependantsRecursive(obj, p.key)
            }
        }
    }

    // fallback normalization used on save to guarantee consistency
    function normalizePermissions(obj: AdminRole) {
        // build dependency map from definitions (child -> parents)
        const deps = new Map<AdminRolePermissionKey, AdminRolePermissionKey[]>()
        for (const p of ADMIN_PERMISSIONS) {
            if (p.deps) {
                deps.set(p.key, p.deps)
            }
        }
        let changed = true
        while (changed) {
            changed = false
            for (const [child, parents] of deps.entries()) {
                // if child is granted, ensure all parents granted
                if (obj[child]) {
                    for (const parent of parents) {
                        if (!obj[parent]) {
                            obj[parent] = true
                            changed = true
                        }
                    }
                }
                // if any parent is revoked, child must be revoked as well
                if (obj[child] && parents.some(p => !obj[p])) {
                    obj[child] = false
                    changed = true
                }
            }
        }
    }

    async function update() {
        if (!role) return
        try {
            normalizePermissions(role)
            role = await api.updateAdminRole({
                id: params.id,
                adminRoleDataRequest: role,
            })
        } catch (err) {
            error = await stringifyError(err)
        }
    }

    let removing = $state(false)

    async function confirmRemove() {
        if (!role) {
            return
        }
        await api.deleteAdminRole(role)
        replace('/config/admin-roles')
    }
</script>

<div class="container-max-md">
    <Loadable promise={initPromise} bind:value={role}>
        {#snippet children(role)}
            <div class="page-summary-bar">
                <div>
                    <h1>{role.name}</h1>
                    <div class="text-muted">admin role</div>
                </div>
            </div>

            <Input label="Name" bind:value={role.name} {disabled} />

            <Input
                label="Description"
                bind:value={role.description}
                {disabled}
            />

            <h4 class="mt-4">Permissions</h4>
            <div class="row g-3">
                {#each permGroups as { category, perms }}
                    <div class="col-6">
                        <h5 class="mt-3">{category}</h5>
                        {#each perms as { key, label } (key)}
                            <label class="form-check">
                                <input
                                    class="form-check-input"
                                    type="checkbox"
                                    bind:checked={role[key]}
                                    {disabled}
                                    onchange={e => {
                                const checked = (e.target as HTMLInputElement).checked
                                if (checked) {
                                    enablePermissionDependenciesRecursive(role, key)
                                } else {
                                    disablePermissionDependantsRecursive(role, key)
                                }
                            }}
                                >
                                <span class="form-check-label">
                                    {label}
                                    {#if ADMIN_PERMISSIONS.find(p=>p.key===key)?.dangerous}
                                        <Tooltip
                                            text="Grants the ability to manage admin roles; use with care."
                                            delay={250}
                                        >
                                            <StatusMarker
                                                kind="pending"
                                                label="Use with care"
                                                bare
                                            />
                                        </Tooltip>
                                    {/if}
                                </span>
                            </label>
                        {/each}
                    </div>
                {/each}
            </div>
            {#if error}
                <Callout tone="danger" title="Something went wrong"
                    >{error}</Callout
                >
            {/if}

            <div class="d-flex mt-3">
                <a
                    href="/log/admin-role/{params.id}"
                    use:link
                    class="btn btn-secondary"
                >
                    Audit log
                </a>

                <Button
                    variant="primary"
                    {disabled}
                    class="ms-auto"
                    click={update}
                >
                    Update
                </Button>

                <Button
                    class="ms-2"
                    {disabled}
                    variant="destructive"
                    onclick={() => (removing = true)}
                >
                    Remove
                </Button>
            </div>

            <h4 class="mt-4">Assigned users</h4>
            <ItemList load={loadUsers}>
                {#snippet item(user)}
                    <a
                        class="list-group-item list-group-item-action"
                        href="/config/users/{user.id}"
                        use:link
                    >
                        <div>
                            <strong class="me-auto">
                                {user.username}
                            </strong>
                            {#if user.description}
                                <small class="d-block text-muted"
                                    >{user.description}</small
                                >
                            {/if}
                        </div>
                    </a>
                {/snippet}
                {#snippet empty()}
                    <Callout>
                        This admin role has no users assigned to it
                    </Callout>
                {/snippet}
            </ItemList>
        {/snippet}
    </Loadable>
</div>

<ConfirmDialog
    bind:open={removing}
    title="Delete {role?.name ?? 'this admin role'}?"
    confirmLabel="Delete admin role"
    confirmText={role?.name}
    confirmTextLabel="role name"
    onconfirm={confirmRemove}
    oncancel={() => (removing = false)}
>
    <p>
        Every administrator holding this role loses the permissions it grants,
        immediately. If it is the only role granting someone admin access, they
        lose that access — and this screen does not list who holds it.
    </p>
</ConfirmDialog>
