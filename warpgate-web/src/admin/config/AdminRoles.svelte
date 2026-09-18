<script lang="ts">
    /**
     * Admin roles — screen 15-23 sweep. Restyled in place.
     *
     * No mockup exists for this screen, so per the derive-don't-invent rule it
     * keeps its structure — permission gate, searchable list, create link —
     * and only the chrome moves onto the primitives.
     */
    import { type AdminRole, api } from 'admin/lib/api'
    import PermissionGate from 'admin/lib/PermissionGate.svelte'
    import ItemList, { type PaginatedResponse } from 'common/ItemList.svelte'
    import * as rx from 'rxjs'
    import { link } from 'svelte-spa-router'
    import Button from 'ui/Button.svelte'
    import EmptyState from 'ui/EmptyState.svelte'
    import 'ui/layout.css'
    import { push } from 'svelte-spa-router'
    import { adminPermissions } from '../lib/store'
    import AdminRolePermissionsBadge from './AdminRolePermissionsBadge.svelte'

    function loadRoles(): rx.Observable<PaginatedResponse<AdminRole>> {
        if (!$adminPermissions.adminRolesManage) {
            return rx.from([])
        }
        return rx.from(api.getAdminRoles()).pipe(
            rx.map(roles => ({
                items: roles,
                offset: 0,
                total: roles.length,
            })),
        )
    }
</script>

<PermissionGate
    perm="adminRolesManage"
    message="You have no permission to manage admin roles."
>
    <div class="wg-page-head">
        <div>
            <h1>Admin roles</h1>
            <p class="wg-page-lede">Permissions for administrators.</p>
        </div>
        <Button
            variant="primary"
            size="compact"
            onclick={() => push('/config/admin-roles/create')}
        >
            Create
        </Button>
    </div>

    <ItemList load={loadRoles} showSearch={true}>
        {#snippet item(role)}
            <li>
                <a
                    class="wg-row-link"
                    href="/config/admin-roles/{role.id}"
                    use:link
                >
                    <span class="role-text">
                        <strong>{role.name}</strong>
                        {#if role.description}
                            <small>{role.description}</small>
                        {/if}
                    </span>
                    <span class="role-badge">
                        <AdminRolePermissionsBadge {role} />
                    </span>
                </a>
            </li>
        {/snippet}
        {#snippet container(rows)}
            <ul class="wg-rows">
                {@render rows()}
            </ul>
        {/snippet}
        {#snippet empty()}
            <EmptyState
                title="No admin roles defined"
                hint="An admin role is a set of permissions you can assign to administrators."
            />
        {/snippet}
    </ItemList>
</PermissionGate>

<style>
    .role-text {
        display: flex;
        flex-direction: column;
        gap: 2px;
        min-width: 0;
        margin-right: auto;
    }

    .role-text small {
        color: var(--wg-text-muted);
        font: var(--wg-text-label-sm);
    }

    .role-badge {
        flex: none;
    }
</style>
