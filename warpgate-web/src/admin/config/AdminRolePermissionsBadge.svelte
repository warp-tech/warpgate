<script lang="ts">
    /**
     * "N permissions", with the breakdown by category on hover.
     *
     * Behaviour preserved: the count, the singular/plural, and the
     * category -> comma-joined-labels grouping, which is derived from
     * ADMIN_PERMISSIONS exactly as before.
     *
     * The tooltip wraps the badge rather than targeting a generated id, so the
     * `role-${id}` element id is gone.
     */
    import type { AdminRole } from 'admin/lib/api'
    import Badge from 'ui/Badge.svelte'
    import Tooltip from 'ui/Tooltip.svelte'
    import { ADMIN_PERMISSIONS } from '../lib/store'

    interface Props {
        role: AdminRole
    }

    let { role }: Props = $props()

    const count = $derived(
        ADMIN_PERMISSIONS.reduce((n, p) => n + (role[p.key] ? 1 : 0), 0),
    )

    const summary = $derived.by(() => {
        const categories = [
            ...new Set(
                ADMIN_PERMISSIONS.filter(p => role[p.key]).map(p => p.category),
            ),
        ]
        return categories
            .map(cat => {
                const perms = ADMIN_PERMISSIONS.filter(
                    p => p.category === cat && role[p.key],
                ).map(p => p.label)
                return perms.length ? `${cat}: ${perms.join(', ')}` : null
            })
            .filter(Boolean)
            .join(' — ')
    })
</script>

{#if summary}
    <Tooltip text={summary} delay={250}>
        <Badge>{count} {count === 1 ? 'permission' : 'permissions'}</Badge>
    </Tooltip>
{:else}
    <Badge>No permissions</Badge>
{/if}
