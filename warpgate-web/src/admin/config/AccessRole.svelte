<script lang="ts">
    import { api, type Role, type Target, type User } from 'admin/lib/api'
    import { stringifyError } from 'common/errors'
    import ItemList, { type PaginatedResponse } from 'common/ItemList.svelte'
    import Loadable from 'common/Loadable.svelte'
    import * as rx from 'rxjs'
    import { link, replace } from 'svelte-spa-router'
    import Button from 'ui/Button.svelte'
    import Callout from 'ui/Callout.svelte'
    import ConfirmDialog from 'ui/ConfirmDialog.svelte'
    import Input from 'ui/Input.svelte'
    import Toggle from 'ui/Toggle.svelte'
    import { adminPermissions } from '../lib/store'

    interface Props {
        params: { id: string }
    }

    let { params }: Props = $props()

    let error: string | null = $state(null)
    let role: Role | undefined = $state()
    const initPromise = init()

    async function init() {
        role = await api.getRole({ id: params.id })
        return role
    }

    function loadUsers(): rx.Observable<PaginatedResponse<User>> {
        return rx
            .from(
                api.getRoleUsers({
                    id: params.id,
                }),
            )
            .pipe(
                rx.map(targets => ({
                    items: targets,
                    offset: 0,
                    total: targets.length,
                })),
            )
    }

    function loadTargets(): rx.Observable<PaginatedResponse<Target>> {
        return rx
            .from(
                api.getRoleTargets({
                    id: params.id,
                }),
            )
            .pipe(
                rx.map(targets => ({
                    items: targets,
                    offset: 0,
                    total: targets.length,
                })),
            )
    }

    async function update() {
        if (!role) return
        try {
            role = await api.updateRole({
                id: params.id,
                roleDataRequest: role,
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
        await api.deleteRole(role)
        replace('/config/access-roles')
    }
</script>

<div class="container-max-md">
    <Loadable promise={initPromise} bind:value={role}>
        {#snippet children(role)}
            <div class="page-summary-bar">
                <div>
                    <h1>{role.name}</h1>
                    <div class="text-muted">role</div>
                </div>
            </div>

            <Input label="Name" bind:value={role.name} />

            <Input label="Description" bind:value={role.description} />

            <div class="mb-4">
                <Toggle
                    id="isDefault"
                    label="Automatically assign to all new users"
                    bind:checked={role.isDefault}
                />
            </div>
        {/snippet}
    </Loadable>

    {#if error}
        <Callout tone="danger" title="Something went wrong">{error}</Callout>
    {/if}

    <div class="d-flex">
        <a
            href="/log/access-role/{params.id}"
            use:link
            class="btn btn-secondary"
        >
            Audit log
        </a>

        <Button
            variant="primary"
            disabled={!$adminPermissions.accessRolesEdit}
            class="ms-auto"
            click={update}
        >
            Update
        </Button>

        <Button
            class="ms-2"
            disabled={!$adminPermissions.accessRolesDelete}
            variant="destructive"
            onclick={() => (removing = true)}
        >
            Remove
        </Button>
    </div>

    <h4 class="mt-5">Assigned users</h4>

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
            <Callout>This role has no users assigned to it</Callout>
        {/snippet}
    </ItemList>

    <h4 class="mt-4">Assigned targets</h4>

    <ItemList load={loadTargets}>
        {#snippet item(target)}
            <a
                class="list-group-item list-group-item-action"
                href="/config/targets/{target.id}"
                use:link
            >
                <div class="me-auto">
                    <strong>
                        {target.name}
                    </strong>
                    {#if target.description}
                        <small class="d-block text-muted"
                            >{target.description}</small
                        >
                    {/if}
                </div>
            </a>
        {/snippet}
        {#snippet empty()}
            <Callout>This role has no targets assigned to it</Callout>
        {/snippet}
    </ItemList>
</div>

<ConfirmDialog
    bind:open={removing}
    title="Delete {role?.name ?? 'this role'}?"
    confirmLabel="Delete role"
    confirmText={role?.name}
    confirmTextLabel="role name"
    onconfirm={confirmRemove}
    oncancel={() => (removing = false)}
>
    <p class="panel">
        Every user holding this role loses it, and every target that grants
        access through it stops granting that access. Neither list is shown
        here, so there is no way to see from this screen how many are affected.
    </p>
</ConfirmDialog>
