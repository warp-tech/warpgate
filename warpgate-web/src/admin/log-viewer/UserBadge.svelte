<script lang="ts">
    /**
     * User reference inside a log entry or a session header — screen 10.
     *
     * Chrome only: sveltestrap Badge and svelte-fa become ui/Badge and an
     * inline SVG. The permission gate is unchanged and load-bearing — without
     * `usersEdit` the badge is plain text, because the link would lead to a
     * page the viewer cannot open.
     */
    import { adminPermissions } from 'admin/lib/store'
    import Badge from 'ui/Badge.svelte'

    interface Props {
        id: string | undefined
        name: string
    }

    let { id, name }: Props = $props()

    const href = $derived(
        $adminPermissions.usersEdit && id ? `#/config/users/${id}` : undefined,
    )
</script>

<Badge tone="success" {href} class="wg-log-badge">
    <svg viewBox="0 0 16 16" width="11" height="11" aria-hidden="true">
        <circle
            cx="8"
            cy="5.25"
            r="2.5"
            fill="none"
            stroke="currentColor"
            stroke-width="1.4"
        />
        <path
            d="M3 13.25a5 5 0 0 1 10 0"
            fill="none"
            stroke="currentColor"
            stroke-width="1.4"
            stroke-linecap="round"
        />
    </svg>
    <span>{name}</span>
</Badge>

<style>
    :global(.wg-log-badge) {
        display: inline-flex;
        align-items: center;
        gap: var(--wg-space-xs);
    }
</style>
