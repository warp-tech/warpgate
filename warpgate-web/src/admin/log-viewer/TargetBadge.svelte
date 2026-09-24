<script lang="ts">
    /**
     * Target reference inside a log entry or a session header — screen 10.
     *
     * Chrome only: sveltestrap Badge and svelte-fa become ui/Badge and an
     * inline SVG. The permission gate is unchanged and load-bearing — without
     * `targetsEdit` the badge is plain text, because the link would lead to a
     * page the viewer cannot open.
     *
     * `info` has no equivalent in the Badge tone set (neutral / primary /
     * success / warning / danger). `primary` is the closest, and keeps targets
     * distinct from the `success` used for users, which is the only job the
     * colour was doing.
     */
    import { adminPermissions } from 'admin/lib/store'
    import Badge from 'ui/Badge.svelte'

    interface Props {
        id: string | undefined
        name: string
    }

    let { id, name }: Props = $props()

    const href = $derived(
        $adminPermissions.targetsEdit && id
            ? `#/config/targets/${id}`
            : undefined,
    )
</script>

<Badge tone="primary" {href} class="wg-log-badge">
    <svg viewBox="0 0 16 16" width="11" height="11" aria-hidden="true">
        <rect
            x="1.75"
            y="2.75"
            width="12.5"
            height="8.5"
            rx="1.25"
            fill="none"
            stroke="currentColor"
            stroke-width="1.4"
        />
        <path
            d="M5.5 13.75h5"
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
