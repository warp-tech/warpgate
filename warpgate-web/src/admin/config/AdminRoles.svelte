<script lang="ts">
    import { api, type AdminRole } from 'admin/lib/api'
    import { link } from 'svelte-spa-router'
    import Alert from 'common/sveltestrap-s5-ports/Alert.svelte'
    import ItemList, { type PaginatedResponse } from 'common/ItemList.svelte'
    import * as rx from 'rxjs'
    import { adminPermissions } from '../lib/store'
    import PermissionGate from 'admin/lib/PermissionGate.svelte'
    import AdminRolePermissionsBadge from './AdminRolePermissionsBadge.svelte'

    function loadRoles (): rx.Observable<PaginatedResponse<AdminRole>> {
        if (!$adminPermissions.adminRolesManage) {
            return rx.from([])
        }
        return rx.from(api.getAdminRoles()).pipe(
            rx.map(targets => ({
                items: targets,
                offset: 0,
                total: targets.length,
            })),
        )
    }

</script>

<div class="container-max-md">
    <PermissionGate perm="adminRolesManage" message="You have no permission to manage admin roles.">
        <div class="page-summary-bar">
            <div>
                <h1>admin roles</h1>
                <div class="text-muted">permissions for administrators</div>
            </div>
            <a class="btn btn-primary ms-auto" href="/config/admin-roles/create" use:link>Create</a>
        </div>

        <ItemList load={loadRoles} showSearch={true}>
        {#snippet item(role)}
            <a
                class="list-group-item list-group-item-action d-flex align-items-center"
                href="/config/admin-roles/{role.id}"
                use:link>
                <div>
                    <strong class="me-auto">
                        {role.name}
                    </strong>
                    {#if role.description}
                        <small class="d-block text-muted">{role.description}</small>
                    {/if}
                </div>
                <span class="ms-auto">
                    <AdminRolePermissionsBadge {role} />
                </span>
            </a>
        {/snippet}
        {#snippet empty()}
            <Alert color="info">No admin roles defined</Alert>
        {/snippet}
        </ItemList>
    </PermissionGate>
</div>
