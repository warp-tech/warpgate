<script lang="ts">
    /**
     * "N user requests awaiting your action" — shown in both shells.
     *
     * Behaviour preserved: both permission gates, the combined session +
     * ticket count, the watch that restarts when permissions change and tears
     * the old one down, and the transient-failure rule that keeps the last
     * known counts rather than flashing the indicator away.
     */
    import { serverInfo } from 'gateway/lib/store'
    import {
        loadPendingRequests,
        watchPendingRequests,
    } from './approvalRequests'

    const { collapsed = false, class: className = '' } = $props()

    // Absolute so this works from either app shell
    const PAGE_URL = '/@warpgate/admin#/status/requests'

    let sessionCount = $state(0)
    let ticketCount = $state(0)

    const canSeeSessions = $derived(
        $serverInfo?.adminPermissions?.approveSessions ?? false,
    )
    const canManageTickets = $derived(
        $serverInfo?.adminPermissions?.ticketRequestsManage ?? false,
    )
    const canSeeAny = $derived(canSeeSessions || canManageTickets)
    const count = $derived(sessionCount + ticketCount)

    async function reload() {
        try {
            const { sessions, tickets } = await loadPendingRequests({
                canSeeSessions,
                canManageTickets,
            })
            sessionCount = sessions.length
            ticketCount = tickets.length
        } catch {
            // A transient failure leaves the last known counts in place rather
            // than flashing the indicator away.
        }
    }

    // The permissions arrive with the server info, so the watch starts once
    // they have been granted. Returning the cleanup ties it to this effect run,
    // so a permission change tears the old watch down instead of leaking it.
    $effect(() => {
        sessionCount = 0
        ticketCount = 0
        // No-ops when no permission is held, so no guard is needed here.
        return watchPendingRequests(
            { canSeeSessions, canManageTickets },
            () => {
                void reload()
            },
        )
    })
</script>

{#if canSeeAny && count > 0}
    <a class="requests {className}" class:collapsed href={PAGE_URL}>
        <span class="marker" aria-hidden="true"></span>
        <span>
            {count}
            user request{count === 1 ? '' : 's'}
            {#if !collapsed}
                awaiting your action
            {/if}
        </span>
    </a>
{/if}

<style>
    .requests {
        display: inline-flex;
        align-items: center;
        gap: var(--wg-space-sm);
        padding: var(--wg-space-sm) var(--wg-space-md);
        background: var(
            --wg-tertiary-container,
            var(--wg-surface-container-high)
        );
        border: var(--wg-border-width) solid var(--wg-border-strong);
        border-radius: var(--wg-radius-control);
        color: var(--wg-text);
        font: var(--wg-text-label-md);
        text-decoration: none;
    }

    .requests.collapsed {
        padding: var(--wg-space-xs) var(--wg-space-sm);
        font: var(--wg-text-label-sm);
    }

    .requests:hover {
        background: var(--wg-surface-container-highest);
    }

    .requests:focus-visible {
        outline: var(--wg-focus-ring);
        outline-offset: var(--wg-focus-ring-offset);
    }

    /* Deliberately not a StatusMarker: this is a call to action, not a state,
       and StatusMarker requires a label of its own. */
    .marker {
        flex: none;
        width: var(--wg-marker-size);
        height: var(--wg-marker-size);
        border-radius: 50%;
        background: var(--wg-tertiary);
    }
</style>
