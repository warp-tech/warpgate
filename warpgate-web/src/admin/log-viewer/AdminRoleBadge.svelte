<script lang="ts">
    /**
     * Admin role reference inside a log entry — screen 10.
     *
     * Chrome only. `info` had no equivalent in the Badge tone set, which is
     * neutral / primary / success / warning / danger; `primary` is the
     * closest and keeps admin roles visually distinct from access roles,
     * which is the only job the colour was doing.
     */
    import Badge from 'ui/Badge.svelte'

    interface Props {
        id: string | undefined
        name: string
    }

    let { id, name }: Props = $props()
</script>

<Badge
    tone="primary"
    href={id ? `#/config/admin-roles/${id}` : undefined}
    class="wg-log-badge"
>
    <svg viewBox="0 0 16 16" width="11" height="11" aria-hidden="true">
        <circle
            cx="8"
            cy="8"
            r="2.25"
            fill="none"
            stroke="currentColor"
            stroke-width="1.5"
        />
        <path
            d="M8 1.5v1.6M8 12.9v1.6M14.5 8h-1.6M3.1 8H1.5M12.6 3.4l-1.1 1.1M4.5 11.5l-1.1 1.1M12.6 12.6l-1.1-1.1M4.5 4.5L3.4 3.4"
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
