<script lang="ts">
    /**
     * Tickets — screen 8.
     *
     * ── Enumeration of admin/config/Tickets.svelte, asserted present ─────
     * Data:   getTickets; getTicketRequests gated on ticketRequestsManage;
     *         pendingRequestCount; request-history filter (all/approved/denied);
     *         deleteTicket then reload; error surface.
     * Ticket: target, username, selfService badge, description, expiry with
     *         past/future distinction, usesLeft > 0, usesLeft === 0 "Used up",
     *         created (relative), Delete gated on ticketsDelete.
     * Request: status icon+colour, username -> targetName, description,
     *         requested duration as humantime, resolved-by, "awaiting user
     *         activation" when approved with no ticketId, deny reason,
     *         created (relative).
     * Chrome: Create gated on ticketsCreate; pending-requests pointer to
     *         /status/requests; both empty states.
     *
     * ── Tabs, not one scrolling page ─────────────────────────────────────
     * DESIGN.md: tabs when the areas have different state, different actions
     * and different reasons to be there. Live tickets and resolved request
     * history share only the word "ticket" — different models, different
     * permission, nothing gained by reading them in order. The history tab is
     * absent entirely without ticketRequestsManage, so an admin who cannot see
     * it never meets an empty tab either.
     *
     * ── What the mockup shows that the API does not have ─────────────────
     * Omitted rather than faked, per the standing rule:
     *   Role column        Ticket carries no role; access is via the target.
     *   Created By column  `username` is the ticket's SUBJECT, not its issuer.
     *                      There is no issuer field. Shown as "User" instead.
     *   "1 of 3" uses      Only `usesLeft` survives; the original
     *                      `numberOfUses` is not returned. Uses left only.
     *   Revoked status     Not a state — deleteTicket removes the row.
     *   Historical quota / Would need deleted tickets and a time series.
     *   Velocity (24h)
     *   Issuer filter /    No backing field, no export endpoint.
     *   Export button
     *   Payload scaffolding panel (TOKEN_AUTH / FINGERPRINT / POLICY_EVAL):
     *                      invented wholesale, no such API.
     */
    import {
        api,
        type Ticket,
        type TicketRequest,
        TicketRequestStatus,
    } from 'admin/lib/api'
    import { formatDurationAsHumantime } from 'common/duration'
    import { stringifyError } from 'common/errors'
    import type { LoadOptions, PaginatedResponse } from 'common/ItemList.svelte'
    import { from, type Observable } from 'rxjs'
    import { link, push } from 'svelte-spa-router'
    import Badge from 'ui/Badge.svelte'
    import Button from 'ui/Button.svelte'
    import Callout from 'ui/Callout.svelte'
    import ConfirmDialog from 'ui/ConfirmDialog.svelte'
    import EmptyState from 'ui/EmptyState.svelte'
    import RelativeDate from 'ui/RelativeDate.svelte'
    import SegmentedControl from 'ui/SegmentedControl.svelte'
    import StatCard from 'ui/StatCard.svelte'
    import StatusMarker, { type StatusKind } from 'ui/StatusMarker.svelte'
    import Table, { type Column } from 'ui/Table.svelte'
    import Tabs, { type Tab } from 'ui/Tabs.svelte'
    import { adminPermissions } from '../../lib/store'

    const DAY_MS = 24 * 60 * 60 * 1000

    type TicketState = 'active' | 'expiring' | 'used' | 'expired'
    type TicketFilter = 'all' | TicketState
    type TabValue = 'tickets' | 'history'

    let error: string | undefined = $state()
    let tickets: Ticket[] = $state([])
    let requests: TicketRequest[] = $state([])
    let filter: TicketFilter = $state('all')
    let historyFilter: 'all' | TicketRequestStatus = $state('all')
    let tab: TabValue = $state('tickets')
    let reloadToken = $state(0)
    let deleting: Ticket | undefined = $state()

    /**
     * Derived, not stored. A ticket is finished when it runs out of uses OR
     * when it passes its expiry, whichever comes first — the two limits are
     * independent and either one ends it.
     */
    function stateOf(ticket: Ticket, now: number): TicketState {
        if (ticket.usesLeft === 0) {
            return 'used'
        }
        if (ticket.expiry) {
            const remaining = ticket.expiry.getTime() - now
            if (remaining <= 0) {
                return 'expired'
            }
            if (remaining < DAY_MS) {
                return 'expiring'
            }
        }
        return 'active'
    }

    // Classified once per load, so a ticket cannot land in one bucket for the
    // stat cards and a different one for the table.
    let states: Map<string, TicketState> = $state(new Map())

    const counts = $derived.by(() => {
        const c = {
            all: tickets.length,
            active: 0,
            expiring: 0,
            used: 0,
            expired: 0,
        }
        for (const s of states.values()) {
            c[s]++
        }
        return c
    })

    const pendingRequestCount = $derived(
        requests.filter(r => r.status === TicketRequestStatus.Pending).length,
    )

    async function loadRequests() {
        if (!$adminPermissions.ticketRequestsManage) {
            requests = []
            return
        }
        requests = await api.getTicketRequests({})
    }

    function loadTickets(
        options: LoadOptions,
    ): Observable<PaginatedResponse<Ticket>> {
        return from(
            Promise.all([api.getTickets(), loadRequests()]).then(([all]) => {
                const clock = Date.now()
                tickets = all
                states = new Map(all.map(t => [t.id, stateOf(t, clock)]))

                const search = options.search?.trim().toLowerCase()
                const visible = all.filter(t => {
                    if (filter !== 'all' && states.get(t.id) !== filter) {
                        return false
                    }
                    if (!search) {
                        return true
                    }
                    // getTickets takes no search parameter, so the filter is
                    // applied here over the fields the row actually shows.
                    return [t.description, t.target, t.username].some(v =>
                        v?.toLowerCase().includes(search),
                    )
                })

                return { items: visible, offset: 0, total: visible.length }
            }),
        )
    }

    async function confirmDelete() {
        const ticket = deleting
        if (!ticket) {
            return
        }
        try {
            await api.deleteTicket({ id: ticket.id })
            error = undefined
            reloadToken++
        } catch (err) {
            error = await stringifyError(err)
        } finally {
            deleting = undefined
        }
    }

    // Both terminal states share the `ended` geometry — a spent ticket and a
    // lapsed one are equally unusable — and the label says which.
    const MARKER: Record<TicketState, { kind: StatusKind; label: string }> = {
        active: { kind: 'online', label: 'Active' },
        expiring: { kind: 'pending', label: 'Expiring soon' },
        used: { kind: 'ended', label: 'Used up' },
        expired: { kind: 'ended', label: 'Expired' },
    }

    const columns: Column[] = [
        { key: 'status', label: 'Status', width: '10rem' },
        { key: 'description', label: 'Description' },
        { key: 'target', label: 'Target' },
        { key: 'user', label: 'User', width: '10rem' },
        { key: 'uses', label: 'Uses left', width: '7rem', align: 'end' },
        { key: 'expiry', label: 'Expires', width: '11rem' },
        { key: 'created', label: 'Created', width: '10rem' },
        { key: 'actions', label: '', width: '5rem', align: 'end' },
    ]

    const segments = $derived([
        { value: 'all' as const, label: `All (${counts.all})` },
        { value: 'active' as const, label: `Active (${counts.active})` },
        { value: 'expiring' as const, label: `Expiring (${counts.expiring})` },
        { value: 'used' as const, label: `Used (${counts.used})` },
        { value: 'expired' as const, label: `Expired (${counts.expired})` },
    ])

    const historySegments = [
        { value: 'all' as const, label: 'All' },
        { value: TicketRequestStatus.Approved, label: 'Approved' },
        { value: TicketRequestStatus.Denied, label: 'Denied' },
    ]

    const filteredHistory = $derived.by(() => {
        const resolved = requests.filter(
            r => r.status !== TicketRequestStatus.Pending,
        )
        return historyFilter === 'all'
            ? resolved
            : resolved.filter(r => r.status === historyFilter)
    })

    const tabs: Tab<TabValue>[] = $derived([
        { value: 'tickets', label: 'Tickets', badge: counts.all || undefined },
        ...($adminPermissions.ticketRequestsManage
            ? [
                  {
                      value: 'history' as const,
                      label: 'Request history',
                      badge: filteredHistory.length || undefined,
                  },
              ]
            : []),
    ])
</script>

<div class="head">
    <div>
        <h1>Tickets</h1>
        <p class="lede">
            Single-purpose, time-bound access credentials for contractors and
            automated pipelines.
        </p>
    </div>
    <Button
        variant="primary"
        size="compact"
        disabled={!$adminPermissions.ticketsCreate}
        onclick={() => push('/config/tickets/create')}
    >
        Issue ticket
    </Button>
</div>

{#if error}
    <Callout tone="danger" title="Something went wrong">{error}</Callout>
{/if}

{#if $adminPermissions.ticketRequestsManage && pendingRequestCount}
    <div class="pointer">
        <Callout
            title="{pendingRequestCount} pending request{pendingRequestCount ===
            1
                ? ''
                : 's'} awaiting action"
        >
            Review {pendingRequestCount === 1 ? 'it' : 'them'} in
            <a href="/status/requests" use:link>Status &rarr; Requests</a>.
        </Callout>
    </div>
{/if}

{#if tabs.length > 1}
    <Tabs bind:value={tab} {tabs} label="Ticket views" />
{/if}

{#if tab === 'tickets'}
    <div class="stats">
        <StatCard
            label="Active credentials"
            value={counts.active}
            note="usable now"
        />
        <StatCard
            label="Expiring < 24h"
            value={counts.expiring}
            tone={counts.expiring ? 'warning' : 'neutral'}
            note={counts.expiring ? 'action required' : 'none'}
        />
        <StatCard
            label="Spent or lapsed"
            value={counts.used + counts.expired}
            note="no longer usable"
        />
    </div>

    <div class="filters">
        <SegmentedControl
            label="Filter by state"
            size="compact"
            {segments}
            value={filter}
            onchange={v => {
                filter = v
                reloadToken++
            }}
        />
    </div>

    {#key `${filter}:${reloadToken}`}
        <Table
            caption="Tickets"
            {columns}
            load={loadTickets}
            rowKey={t => t.id}
            showSearch
            searchPlaceholder="Search tickets…"
        >
            {#snippet row(ticket: Ticket)}
                {@const s = states.get(ticket.id) ?? 'active'}
                <td>
                    <StatusMarker
                        kind={MARKER[s].kind}
                        label={MARKER[s].label}
                        bare
                    />
                </td>
                <td>
                    {#if ticket.description}
                        {ticket.description}
                    {:else}
                        <span class="muted">No description</span>
                    {/if}
                    {#if ticket.selfService}
                        <Badge tone="primary">self-service</Badge>
                    {/if}
                </td>
                <td class="wg-mono">{ticket.target}</td>
                <td class="wg-mono muted">{ticket.username}</td>
                <td class="num">
                    {#if ticket.usesLeft == null}
                        <span class="muted" title="No use limit">&infin;</span>
                    {:else}
                        <span class:spent={ticket.usesLeft === 0}>
                            {ticket.usesLeft}
                        </span>
                    {/if}
                </td>
                <td>
                    {#if ticket.expiry}
                        <span
                            class:urgent={s === 'expiring'}
                            class:muted={s === 'expired'}
                        >
                            <RelativeDate date={ticket.expiry} />
                        </span>
                    {:else}
                        <span class="muted">Never</span>
                    {/if}
                </td>
                <td class="muted"><RelativeDate date={ticket.created} /></td>
                <td class="num">
                    <Button
                        variant="ghost"
                        size="compact"
                        disabled={!$adminPermissions.ticketsDelete}
                        onclick={() => (deleting = ticket)}
                    >
                        Delete
                    </Button>
                </td>
            {/snippet}

            {#snippet empty()}
                <EmptyState
                    size="compact"
                    title={filter === 'all'
                        ? 'No tickets yet'
                        : 'No tickets in this state'}
                    hint={filter === 'all'
                        ? 'Tickets are secret keys that allow access to one specific target without any additional authentication.'
                        : undefined}
                >
                    {#snippet action()}
                        {#if filter === 'all'}
                            <Button
                                variant="primary"
                                size="compact"
                                disabled={!$adminPermissions.ticketsCreate}
                                onclick={() => push('/config/tickets/create')}
                            >
                                Issue ticket
                            </Button>
                        {:else}
                            <Button
                                size="compact"
                                onclick={() => {
                                    filter = 'all'
                                    reloadToken++
                                }}
                            >
                                Show all tickets
                            </Button>
                        {/if}
                    {/snippet}
                </EmptyState>
            {/snippet}
        </Table>
    {/key}
{:else}
    <div class="filters">
        <SegmentedControl
            label="Filter request history"
            size="compact"
            segments={historySegments}
            bind:value={historyFilter}
        />
    </div>

    {#if filteredHistory.length}
        <ul class="history">
            {#each filteredHistory as request (request.id)}
                <li>
                    <StatusMarker
                        kind={request.status === TicketRequestStatus.Approved
                            ? 'online'
                            : 'failed'}
                        label={request.status === TicketRequestStatus.Approved
                            ? 'Approved'
                            : 'Denied'}
                        bare
                    />
                    <div class="history-body">
                        <strong>
                            {request.username ?? request.userId}
                            &rarr;
                            {request.targetName ?? request.targetId}
                        </strong>
                        {#if request.description}
                            <span class="muted">{request.description}</span>
                        {/if}
                        {#if request.requestedDurationSeconds}
                            <span class="muted">
                                Duration:
                                {formatDurationAsHumantime(
                                    request.requestedDurationSeconds,
                                )}
                            </span>
                        {/if}
                        {#if request.resolvedByUserId}
                            <span class="muted">
                                {request.status === TicketRequestStatus.Approved
                                    ? 'Approved'
                                    : 'Denied'}
                                by
                                {request.resolvedByUsername ??
                                    request.resolvedByUserId}
                            </span>
                        {/if}
                        {#if request.status === TicketRequestStatus.Approved && !request.ticketId}
                            <span class="awaiting">
                                Awaiting user activation
                            </span>
                        {/if}
                        {#if request.denyReason}
                            <span class="reason">
                                Reason: {request.denyReason}
                            </span>
                        {/if}
                    </div>
                    <span class="muted history-when">
                        <RelativeDate date={request.created} />
                    </span>
                </li>
            {/each}
        </ul>
    {:else}
        <EmptyState
            title={historyFilter === 'all'
                ? 'No request history'
                : 'No matching requests'}
            hint={historyFilter === 'all'
                ? 'Resolved ticket requests will appear here.'
                : undefined}
        />
    {/if}
{/if}

<ConfirmDialog
    open={!!deleting}
    title="Delete this ticket?"
    confirmLabel="Delete ticket"
    onconfirm={confirmDelete}
    oncancel={() => (deleting = undefined)}
>
    {#if deleting}
        {@const d = deleting}
        <p class="panel">
            Access to <strong>{d.target}</strong> as
            <strong>{d.username}</strong>
            stops working immediately for anyone holding this ticket's secret.
            The secret cannot be reinstated — issue a new ticket instead.
        </p>
    {/if}
</ConfirmDialog>

<style>
    .head {
        display: flex;
        align-items: flex-start;
        justify-content: space-between;
        gap: var(--wg-space-lg);
        flex-wrap: wrap;
        margin-bottom: var(--wg-space-lg);
    }

    h1 {
        margin: 0;
        font: var(--wg-text-headline-lg);
    }

    .lede {
        margin: var(--wg-space-xs) 0 0;
        color: var(--wg-text-muted);
        font: var(--wg-text-body-md);
        max-width: 60ch;
    }

    .pointer {
        margin-bottom: var(--wg-space-lg);
    }

    .stats {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(13rem, 1fr));
        gap: var(--wg-space-md);
        margin: var(--wg-space-lg) 0;
    }

    .filters {
        margin-bottom: var(--wg-space-md);
    }

    .muted {
        color: var(--wg-text-muted);
    }

    .num {
        text-align: right;
    }

    .spent {
        color: var(--wg-error);
    }

    .urgent {
        color: var(--wg-secondary);
    }

    .history {
        list-style: none;
        margin: 0;
        padding: 0;
    }

    .history li {
        display: flex;
        align-items: flex-start;
        gap: var(--wg-space-md);
        padding: var(--wg-space-md) 0;
        border-bottom: var(--wg-border-width) solid var(--wg-border);
    }

    .history li:last-child {
        border-bottom: 0;
    }

    .history-body {
        display: flex;
        flex-direction: column;
        gap: 2px;
        min-width: 0;
        flex: 1 1 auto;
    }

    .history-body span {
        font: var(--wg-text-label-sm);
    }

    .history-when {
        flex: none;
        font: var(--wg-text-label-sm);
    }

    .awaiting {
        color: var(--wg-primary);
    }

    .reason {
        color: var(--wg-error);
    }

    .panel {
        margin: 0;
        color: var(--wg-text-muted);
    }

    @media (max-width: 640px) {
        h1 {
            font: var(--wg-text-headline-lg-mobile);
        }
    }
</style>
