<script lang="ts">
    import { faHand } from '@fortawesome/free-regular-svg-icons'
    import { Button } from '@sveltestrap/sveltestrap'
    import { api, TicketRequestStatus } from 'admin/lib/api'
    import { serverInfo } from 'gateway/lib/store'
    import { onDestroy } from 'svelte'
    import Fa from 'svelte-fa'
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

    let socket: WebSocket | undefined
    let interval: ReturnType<typeof setInterval> | undefined

    async function reload() {
        try {
            const [sessions, tickets] = await Promise.all([
                canSeeSessions
                    ? api.getSessionApprovals().then(r => r.length)
                    : 0,
                canManageTickets
                    ? api
                          .getTicketRequests({
                              status: TicketRequestStatus.Pending,
                          })
                          .then(r => r.length)
                    : 0,
            ])
            sessionCount = sessions
            ticketCount = tickets
        } catch {
            // A transient failure leaves the last known counts in place rather
            // than flashing the indicator away.
        }
    }

    function stopWatching() {
        socket?.close()
        socket = undefined
        if (interval) {
            clearInterval(interval)
        }
        interval = undefined
    }

    // The permissions arrive with the server info, so the watch starts once
    // they have been granted.
    $effect(() => {
        if (!canSeeAny) {
            stopWatching()
            sessionCount = 0
            ticketCount = 0
            return
        }
        if (interval) {
            return
        }
        void reload()
        // Held sessions are pushed; ticket requests are not, so the poll below
        // covers those (and requests resolved by another admin).
        if (canSeeSessions) {
            socket = new WebSocket(
                `wss://${location.host}/@warpgate/admin/api/session-approvals/changes`,
            )
            socket.addEventListener('message', reload)
        }
        interval = setInterval(reload, 30000)
    })

    onDestroy(stopWatching)
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
