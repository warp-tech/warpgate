<script lang="ts">
    import { faHand } from '@fortawesome/free-regular-svg-icons'
    import { Button } from '@sveltestrap/sveltestrap'
    import { serverInfo } from 'gateway/lib/store'
    import Fa from 'svelte-fa'
    import {
        loadPendingRequests,
        watchPendingRequests,
    } from './approvalRequests'
    import { classnames } from './helpers'

    const { collapsed = false, class: className = '' } = $props()

    // Absolute so this works from either app shell
    const PAGE_URL = '/@warpgate/admin#/status/requests'

    let sessionCount = $state(0)
    let ticketCount = $state(0)

    // Each kind of request has its own permission, so an admin only ever counts
    // what they are allowed to act on.
    let canSeeSessions = $derived(
        $serverInfo?.adminPermissions?.sessionsView ?? false,
    )
    let canManageTickets = $derived(
        $serverInfo?.adminPermissions?.ticketRequestsManage ?? false,
    )
    let canSeeAny = $derived(canSeeSessions || canManageTickets)
    let count = $derived(sessionCount + ticketCount)

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
        if (!canSeeAny) {
            sessionCount = 0
            ticketCount = 0
            return
        }
        return watchPendingRequests(
            { canSeeSessions, canManageTickets },
            () => {
                void reload()
            },
        )
    })
</script>

{#if canSeeAny && count > 0}
    <Button
        href={PAGE_URL}
        color="success"
        size={collapsed ? 'sm' : undefined}
        class={classnames("d-flex align-items-center gap-2", className)}
    >
        <Fa icon={faHand} />
        <span>
            {count}
            user request{count === 1 ? '' : 's'}
            {#if !collapsed}
                awaiting your action
            {/if}
        </span>
    </Button>
{/if}
