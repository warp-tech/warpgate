<script lang="ts">
    import { api, type Ticket, TicketRequestStatus, type TicketRequest } from 'admin/lib/api'
    import { link } from 'svelte-spa-router'
    import RelativeDate from '../RelativeDate.svelte'
    import Fa from 'svelte-fa'
    import { faCalendarXmark, faCalendarCheck, faSquareXmark, faSquareCheck } from '@fortawesome/free-solid-svg-icons'
    import { stringifyError } from 'common/errors'
    import Alert from 'common/sveltestrap-s5-ports/Alert.svelte'
    import EmptyState from 'common/EmptyState.svelte'
    import AsyncButton from 'common/AsyncButton.svelte'
    import { Button, FormGroup, Modal, ModalBody, ModalFooter } from '@sveltestrap/sveltestrap'
    import { adminPermissions } from 'admin/lib/store'
    import { statusIcon, statusColor } from 'common/ticketRequestStatus'
    import { formatDuration } from 'common/duration'
    import Loadable from 'common/Loadable.svelte'

    let error: string|undefined = $state()
    let success: string|undefined = $state()
    let tickets: Ticket[]|undefined = $state()
    let requests: TicketRequest[]|undefined = $state()
    let requestHistoryFilter: TicketRequestStatus|undefined = $state()
    let userMap: Map<string, string> = $state(new Map())
    let targetMap: Map<string, string> = $state(new Map())

    let denyModalRequest: TicketRequest|undefined = $state()
    let denyReason = $state('')
    let denyError: string|undefined = $state()

    let pendingRequests = $derived(requests?.filter(r => r.status === TicketRequestStatus.Pending) ?? [])
    let filteredHistory = $derived.by(() => {
        if (!requests) return []
        const nonPending = requests.filter(r => r.status !== TicketRequestStatus.Pending)
        if (!requestHistoryFilter) return nonPending
        return nonPending.filter(r => r.status === requestHistoryFilter)
    })

    async function loadTickets () {
        tickets = await api.getTickets()
    }

    async function loadRequests () {
        if (!$adminPermissions.ticketRequestsManage) return
        requests = await api.getTicketRequests({})
    }

    async function loadLookups () {
        const [users, targets] = await Promise.all([
            api.getUsers({}),
            api.getTargets({}),
        ])
        userMap = new Map(users.map(u => [u.id, u.username]))
        targetMap = new Map(targets.map(t => [t.id, t.name]))
    }

    async function load () {
        await Promise.all([loadTickets(), loadRequests(), loadLookups()])
    }

    const initPromise = load()

    async function deleteTicket (ticket: Ticket) {
        try {
            await api.deleteTicket({ id: ticket.id })
            await loadTickets()
        } catch (err: any) {
            error = await stringifyError(err)
        }
    }

    async function approve (request: TicketRequest) {
        error = undefined
        success = undefined
        try {
            const result = await api.approveTicketRequest({ id: request.id })
            const userName = userMap.get(result.userId) ?? result.userId
            const targetName = targetMap.get(result.targetId) ?? result.targetId
            success = `Approved ticket request for ${userName} to ${targetName}. The user can now activate it.`
            await loadRequests()
        } catch (err: any) {
            error = await stringifyError(err)
            throw err
        }
    }

    async function deny () {
        if (!denyModalRequest) return
        denyError = undefined
        success = undefined
        try {
            await api.denyTicketRequest({
                id: denyModalRequest.id,
                denyTicketRequestBody: {
                    reason: denyReason || undefined,
                },
            })
            success = `Denied ticket request from ${userMap.get(denyModalRequest.userId) ?? denyModalRequest.userId}.`
            denyModalRequest = undefined
            denyReason = ''
            await loadRequests()
        } catch (err: any) {
            denyError = await stringifyError(err)
            throw err
        }
    }
</script>

<div class="container-max-lg">
    {#if error}
    <Alert color="danger">{error}</Alert>
    {/if}

    {#if success}
    <Alert color="success">{success}</Alert>
    {/if}

    <div class="page-summary-bar">
        <h1>Tickets</h1>
        <a
            class="btn btn-primary ms-auto"
            href="/config/tickets/create"
            class:disabled={!$adminPermissions.ticketsCreate}
            use:link>
            Create a ticket
        </a>
    </div>

    <Loadable promise={initPromise}>

    {#if $adminPermissions.ticketRequestsManage && pendingRequests.length}
    <h5 class="mt-4 mb-3">Pending requests <span class="badge bg-warning text-dark">{pendingRequests.length}</span></h5>
    <div class="list-group list-group-flush mb-4">
        {#each pendingRequests as request (request.id)}
            <div class="list-group-item">
                <span class={statusColor(request.status)} title={request.status}>
                    <Fa icon={statusIcon(request.status)} fw />
                </span>
                <div class="ms-2 me-auto">
                    <strong>
                        {userMap.get(request.userId) ?? request.userId} &rarr; {targetMap.get(request.targetId) ?? request.targetId}
                    </strong>
                    {#if request.description}
                        <small class="d-block text-muted">{request.description}</small>
                    {/if}
                    {#if request.requestedDurationSeconds}
                        <small class="d-block text-muted">
                            Duration: {formatDuration(request.requestedDurationSeconds)}
                        </small>
                    {/if}
                </div>
                <small class="text-muted mx-3">
                    <RelativeDate date={request.created} />
                </small>
                <AsyncButton
                    color="success"
                    class="me-1"
                    click={() => approve(request)}
                >Approve</AsyncButton>
                <Button
                    color="danger"
                    size="sm"
                    onclick={() => {
                        denyModalRequest = request
                        denyReason = ''
                        denyError = undefined
                    }}
                >Deny</Button>
            </div>
        {/each}
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
                    <div class="list-group-item">
                        <div>
                            <strong>
                                Access to {ticket.targetName} as {ticket.username}
                            </strong>
                            {#if ticket.selfService}
                                <span class="badge bg-info ms-2">self-service</span>
                            {/if}
                            {#if ticket.description}
                                <small class="d-block text-muted">
                                    {ticket.description}
                                </small>
                            {/if}
                        </div>
                        {#if ticket.expiry}
                            <small class="text-muted ms-4 d-flex align-items-center">
                                <Fa icon={ticket.expiry > new Date() ? faCalendarCheck : faCalendarXmark} fw /> Until {ticket.expiry?.toLocaleString()}
                            </small>
                        {/if}
                        {#if ticket.usesLeft != null}
                            {#if ticket.usesLeft > 0}
                                <small class="text-muted ms-4 d-flex align-items-center">
                                    <Fa icon={faSquareCheck} fw /> Uses left: {ticket.usesLeft}
                                </small>
                            {/if}
                            {#if ticket.usesLeft === 0}
                                <small class="text-danger ms-4">
                                    <Fa icon={faSquareXmark} fw /> Used up
                                </small>
                            {/if}
                        {/if}
                        <small class="text-muted me-4 ms-auto">
                            <RelativeDate date={ticket.created} />
                        </small>
                        <Button
                            color="link"
                            onclick={e => {
                                deleteTicket(ticket)
                                e.preventDefault()
                            }}
                            disabled={!$adminPermissions.ticketsDelete}
                        >Delete</Button>
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
                <option value={TicketRequestStatus.Approved}>Approved</option>
                <option value={TicketRequestStatus.Denied}>Denied</option>
                <option value={TicketRequestStatus.Expired}>Expired</option>
            </select>
        </FormGroup>
    </h5>
    {#if filteredHistory.length || requestHistoryFilter}
    <div class="list-group list-group-flush">
        {#each filteredHistory as request (request.id)}
            <div class="list-group-item">
                <span class={statusColor(request.status)} title={request.status}>
                    <Fa icon={statusIcon(request.status)} fw />
                </span>
                <div class="ms-2 me-auto">
                    <strong>
                        {userMap.get(request.userId) ?? request.userId} &rarr; {targetMap.get(request.targetId) ?? request.targetId}
                    </strong>
                    {#if request.description}
                        <small class="d-block text-muted">{request.description}</small>
                    {/if}
                    {#if request.requestedDurationSeconds}
                        <small class="d-block text-muted">
                            Duration: {formatDuration(request.requestedDurationSeconds)}
                        </small>
                    {/if}
                    {#if request.resolvedByUserId}
                        <small class="d-block text-muted">
                            {request.status === TicketRequestStatus.Approved ? 'Approved' : 'Denied'} by {userMap.get(request.resolvedByUserId) ?? request.resolvedByUserId}
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

<Modal isOpen={!!denyModalRequest} toggle={() => denyModalRequest = undefined}>
    <ModalBody>
        <h5 class="modal-title mb-3">Deny ticket request</h5>
        {#if denyError}
        <Alert color="danger">{denyError}</Alert>
        {/if}
        {#if denyModalRequest}
        <p>
            Deny request from <strong>{userMap.get(denyModalRequest.userId) ?? denyModalRequest.userId}</strong> to <strong>{targetMap.get(denyModalRequest.targetId) ?? denyModalRequest.targetId}</strong>?
        </p>
        <FormGroup floating label="Reason (optional)">
            <input type="text" bind:value={denyReason} class="form-control" placeholder="Why is this being denied?" maxlength="2000"/>
        </FormGroup>
        {/if}
    </ModalBody>
    <ModalFooter>
        <AsyncButton color="danger" click={deny}>Deny</AsyncButton>
        <Button color="secondary" onclick={() => denyModalRequest = undefined}>Cancel</Button>
    </ModalFooter>
</Modal>

<style lang="scss">
    .list-group-item {
        display: flex;
        align-items: center;
    }
</style>
