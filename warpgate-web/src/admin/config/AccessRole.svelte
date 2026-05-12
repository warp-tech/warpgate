<script lang="ts">
    import { api, type Role, type Target, type User } from 'admin/lib/api'
    import AsyncButton from 'common/AsyncButton.svelte'
    import { link, replace } from 'svelte-spa-router'
    import { FormGroup, Input } from '@sveltestrap/sveltestrap'
    import { stringifyError } from 'common/errors'
    import Alert from 'common/sveltestrap-s5-ports/Alert.svelte'
    import Loadable from 'common/Loadable.svelte'
    import ItemList, { type PaginatedResponse } from 'common/ItemList.svelte'
    import * as rx from 'rxjs'
    import { adminPermissions } from '../lib/store'

    interface Props {
        params: { id: string };
    }

    let { params }: Props = $props()

    let error: string|null = $state(null)
    let role: Role | undefined = $state()
    const initPromise = init()

    async function init () {
        role = await api.getRole({ id: params.id })
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
            replace('/config/access-roles')
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
            <Input bind:value={role!.name} />
        </FormGroup>

        <FormGroup floating label="Description">
            <Input bind:value={role!.description} />
        </FormGroup>

        <div class="form-check mb-3">
            <input
                id="isDefault"
                class="form-check-input"
                type="checkbox"
                bind:checked={role!.isDefault}
            />
            <label class="form-check-label" for="isDefault">
                Default role
            </label>
        </div>
    </Loadable>

    {#if error}
        <Alert color="danger">{error}</Alert>
    {/if}

    <div class="d-flex">
        <a href="/log/access-role/{params.id}" use:link class="btn btn-secondary">
            Audit log
        </a>

        <AsyncButton
        color="primary"
            disabled={!$adminPermissions.accessRolesEdit}
            class="ms-auto"
            click={update}
        >Update</AsyncButton>

        <AsyncButton
            class="ms-2"
            disabled={!$adminPermissions.accessRolesDelete}
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
