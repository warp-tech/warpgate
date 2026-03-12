<script lang="ts">
    import type { AdminRole } from 'admin/lib/api'
    import { ADMIN_PERMISSIONS } from '../lib/store'
    import Tooltip from 'common/sveltestrap-s5-ports/Tooltip.svelte'

    export let role: AdminRole

    // unique id for tooltip target
    const id = `role-${role.id}`

    function permissionCount(role: AdminRole): number {
        return ADMIN_PERMISSIONS.reduce(
            (n, p) => n + (role[p.key] ? 1 : 0),
            0,
        )
    }

    function permissionLists(role: AdminRole): [string, string][] {
        const categories = [...new Set(
            ADMIN_PERMISSIONS.filter(p => role[p.key]).map(p => p.category),
        )]
        return categories
            .map(cat => {
                const perms = ADMIN_PERMISSIONS
                    .filter(p => p.category === cat && role[p.key])
                    .map(p => p.label)
                if (!perms.length) {
                    return null
                }
                return [cat, perms.join(', ')] as [string, string]
            })
            .filter((x): x is [string, string] => !!x)
    }
</script>

<span class="badge bg-secondary" id={id}>
    {permissionCount(role)} {permissionCount(role) === 1 ? 'permission' : 'permissions'}
</span>
<Tooltip target={id} delay="250">
    <div class="text-start">
        {#each permissionLists(role) as [category, perms] ([category, perms])}
            <div>{category}: <span class="text-muted">{perms}</span></div>
        {/each}
    </div>
</Tooltip>
