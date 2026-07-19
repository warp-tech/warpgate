<script lang="ts">
    import {
        faCalendarCheck,
        faCalendarXmark,
        faSquareCheck,
        faSquareXmark,
    } from '@fortawesome/free-solid-svg-icons'
    import { Alert, Button, FormGroup } from '@sveltestrap/sveltestrap'
    import {
        api,
        type Ticket,
        type TicketRequest,
        TicketRequestStatus,
    } from 'admin/lib/api'
    import { adminPermissions } from 'admin/lib/store'
    import { formatDurationAsHumantime } from 'common/duration'
    import EmptyState from 'common/EmptyState.svelte'
    import { stringifyError } from 'common/errors'
    import Loadable from 'common/Loadable.svelte'
    import RelativeDate from 'common/RelativeDate.svelte'
    import { statusColor, statusIcon } from 'common/ticketRequestStatus'
    import Fa from 'svelte-fa'
    import { link } from 'svelte-spa-router'

    let error: string | undefined = $state()
    let tickets: Ticket[] | undefined = $state()
    let requests: TicketRequest[] | undefined = $state()
    let requestHistoryFilter: TicketRequestStatus | undefined = $state()

    let pendingRequestCount = $derived(
        requests?.filter(r => r.status === TicketRequestStatus.Pending)
            .length ?? 0,
    )
    let filteredHistory = $derived.by(() => {
        if (!requests) {
            return []
        }
        const nonPending = requests.filter(
            r => r.status !== TicketRequestStatus.Pending,
        )
        if (!requestHistoryFilter) {
            return nonPending
        }
        return nonPending.filter(r => r.status === requestHistoryFilter)
    })

    async function loadTickets() {
        tickets = await api.getTickets()
    }

    async function loadRequests() {
        if (!$adminPermissions.ticketRequestsManage) {
            return
        }
        requests = await api.getTicketRequests({})
    }

    async function load() {
        await Promise.all([loadTickets(), loadRequests()])
    }

    const initPromise = load()

    async function deleteTicket(ticket: Ticket) {
        try {
            await api.deleteTicket({ id: ticket.id })
            await loadTickets()
        } catch (err) {
            error = await stringifyError(err)
        }
    }
</script>

<div class="container-max-lg">
    {#if error}
        <Alert color="danger">{error}</Alert>
    {/if}

    <div class="page-summary-bar">
        <h1>Tickets</h1>
        <a
            class="btn btn-primary ms-auto"
            href="/config/tickets/create"
            class:disabled={!$adminPermissions.ticketsCreate}
            use:link
        >
            Create a ticket
        </a>
    </div>

    <Loadable promise={initPromise}>
        {#if $adminPermissions.ticketRequestsManage && pendingRequestCount}
            <div class="mt-4 mb-4 text-muted">
                {pendingRequestCount}
                pending request{pendingRequestCount === 1
                    ? ''
                    : 's'}
                awaiting action in
                <a use:link href="/status/requests">Status &rarr; Requests</a>.
            </div>
        {/if}

        {#if tickets}
            <h5 class="mt-4 mb-3">
                Active tickets
                {#if tickets.length}
                    <span class="badge bg-secondary">{tickets.length}</span>
                {/if}
            </h5>
            {#if tickets.length}
                <div class="list-group list-group-flush mb-4">
                    {#each tickets as ticket (ticket.id)}
                        <div class="list-group-item gap-3">
                            <div>
                                <strong>
                                    Access to {ticket.target} as
                                    {ticket.username}
                                </strong>
                                {#if ticket.selfService}
                                    <span class="badge bg-info ms-2"
                                        >self-service</span
                                    >
                                {/if}
                                {#if ticket.description}
                                    <small class="d-block text-muted">
                                        {ticket.description}
                                    </small>
                                {/if}
                                {#if ticket.expiry}
                                    <small
                                        class="text-muted d-flex align-items-center gap-2"
                                    >
                                        <Fa
                                            icon={ticket.expiry > new Date() ? faCalendarCheck : faCalendarXmark}
                                        />
                                        Until {ticket.expiry?.toLocaleString()}
                                    </small>
                                {/if}
                            </div>
                            {#if ticket.usesLeft != null}
                                {#if ticket.usesLeft > 0}
                                    <small
                                        class="text-muted d-flex align-items-center gap-2"
                                    >
                                        <Fa icon={faSquareCheck} />
                                        Uses left: {ticket.usesLeft}
                                    </small>
                                {/if}
                                {#if ticket.usesLeft === 0}
                                    <small
                                        class="text-danger d-flex align-items-center gap-2"
                                    >
                                        <Fa icon={faSquareXmark} />
                                        Used up
                                    </small>
                                {/if}
                            {/if}
                            <small class="text-muted ms-auto">
                                <RelativeDate date={ticket.created} />
                            </small>
                            <Button
                                color="link"
                                onclick={e => {
                                deleteTicket(ticket)
                                e.preventDefault()
                            }}
                                disabled={!$adminPermissions.ticketsDelete}
                                >Delete</Button
                            >
                        </div>
                    {/each}
                </div>
            {:else}
                <EmptyState
                    title="No active tickets"
                    hint="Tickets are secret keys that allow access to one specific target without any additional authentication"
                />
            {/if}
        {/if}

        {#if $adminPermissions.ticketRequestsManage && requests}
            <h5 class="mt-4 mb-3 d-flex align-items-center">
                Request history
                <FormGroup class="ms-auto mb-0">
                    <select
                        class="form-control form-control-sm"
                        value={requestHistoryFilter ?? ''}
                        onchange={e => {
                    const v = e.currentTarget.value
                    requestHistoryFilter = v ? v as TicketRequestStatus : undefined
                }}
                    >
                        <option value="">All</option>
                        <option value={TicketRequestStatus.Approved}>
                            Approved
                        </option>
                        <option value={TicketRequestStatus.Denied}>
                            Denied
                        </option>
                    </select>
                </FormGroup>
            </h5>
            {#if filteredHistory.length || requestHistoryFilter}
                <div class="list-group list-group-flush">
                    {#each filteredHistory as request (request.id)}
                        <div class="list-group-item">
                            <span
                                class={statusColor(request.status)}
                                title={request.status}
                            >
                                <Fa icon={statusIcon(request.status)} fw />
                            </span>
                            <div class="ms-2 me-auto">
                                <strong>
                                    {request.username}
                                    &rarr;
                                    {request.targetName}
                                </strong>
                                {#if request.description}
                                    <small class="d-block text-muted"
                                        >{request.description}</small
                                    >
                                {/if}
                                {#if request.requestedDurationSeconds}
                                    <small class="d-block text-muted">
                                        Duration:
                                        {formatDurationAsHumantime(request.requestedDurationSeconds)}
                                    </small>
                                {/if}
                                {#if request.resolvedByUserId}
                                    <small class="d-block text-muted">
                                        {request.status === TicketRequestStatus.Approved ? 'Approved' : 'Denied'}
                                        by
                                        {request.resolvedByUsername}
                                    </small>
                                {/if}
                                {#if request.status === TicketRequestStatus.Approved && !request.ticketId}
                                    <small class="d-block text-info">
                                        Awaiting user activation
                                    </small>
                                {/if}
                                {#if request.denyReason}
                                    <small class="d-block text-danger">
                                        Reason: {request.denyReason}
                                    </small>
                                {/if}
                            </div>
                            <small class="text-muted mx-3">
                                <RelativeDate date={request.created} />
                            </small>
                        </div>
                    {/each}
                    {#if !filteredHistory.length}
                        <EmptyState title="No matching requests" />
                    {/if}
                </div>
            {:else}
                <EmptyState
                    title="No request history"
                    hint="Resolved ticket requests will appear here"
                />
            {/if}
        {/if}
    </Loadable>
</div>

<style lang="scss">
    .list-group-item {
        display: flex;
        align-items: center;
    }
</style>
