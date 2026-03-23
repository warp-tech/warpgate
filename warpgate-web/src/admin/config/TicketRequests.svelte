<script lang="ts">
    import { api, TicketRequestStatus, type TicketRequest } from 'admin/lib/api'
    import RelativeDate from '../RelativeDate.svelte'
    import Fa from 'svelte-fa'
    import { stringifyError } from 'common/errors'
    import Alert from 'common/sveltestrap-s5-ports/Alert.svelte'
    import EmptyState from 'common/EmptyState.svelte'
    import AsyncButton from 'common/AsyncButton.svelte'
    import { Button, FormGroup, Modal, ModalBody, ModalFooter } from '@sveltestrap/sveltestrap'
    import PermissionGate from 'admin/lib/PermissionGate.svelte'
    import { statusIcon, statusColor } from 'common/ticketRequestStatus'
    import { formatDuration } from 'common/duration'
    import Loadable from 'common/Loadable.svelte'

    let error: string|undefined = $state()
    let success: string|undefined = $state()
    let requests: TicketRequest[]|undefined = $state()
    let statusFilter: TicketRequestStatus|undefined = $state()

    let denyModalRequest: TicketRequest|undefined = $state()
    let denyReason = $state('')
    let denyError: string|undefined = $state()

    async function load () {
        requests = await api.getTicketRequests({
            status: statusFilter,
        })
    }

    const initPromise = load()

    async function approve (request: TicketRequest) {
        error = undefined
        success = undefined
        try {
            const result = await api.approveTicketRequest({ id: request.id })
            success = `Approved ticket request for ${result.username} to ${result.targetName}. The user can now activate it.`
            await load()
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
            success = `Denied ticket request from ${denyModalRequest.username}.`
            denyModalRequest = undefined
            denyReason = ''
            await load()
        } catch (err: any) {
            denyError = await stringifyError(err)
            throw err
        }
    }
</script>

<div class="container-max-lg">
    <PermissionGate perm="ticketRequestsManage" message="You have no permission to manage ticket requests.">
        {#if error}
        <Alert color="danger">{error}</Alert>
        {/if}

        {#if success}
        <Alert color="success">{success}</Alert>
        {/if}

        <div class="page-summary-bar">
            <h1>ticket requests</h1>
            <FormGroup class="ms-auto mb-0">
                <select
                    class="form-control form-control-sm"
                    value={statusFilter ?? ''}
                    onchange={e => {
                        const v = e.currentTarget.value
                        statusFilter = v ? v as TicketRequestStatus : undefined
                        load().catch(async err => { error = await stringifyError(err) })
                    }}
                >
                    <option value="">All</option>
                    <option value={TicketRequestStatus.Pending}>Pending</option>
                    <option value={TicketRequestStatus.Approved}>Approved</option>
                    <option value={TicketRequestStatus.Denied}>Denied</option>
                    <option value={TicketRequestStatus.Expired}>Expired</option>
                </select>
            </FormGroup>
        </div>

        <Loadable promise={initPromise}>
        {#if requests}
            {#if requests.length}
            <div class="list-group list-group-flush">
                {#each requests as request (request.id)}
                    <div class="list-group-item">
                        <span class={statusColor(request.status)} title={request.status}>
                            <Fa icon={statusIcon(request.status)} fw />
                        </span>
                        <div class="ms-2 me-auto">
                            <strong>
                                {request.username} &rarr; {request.targetName}
                            </strong>
                            {#if request.description}
                                <small class="d-block text-muted">{request.description}</small>
                            {/if}
                            {#if request.requestedDurationSeconds}
                                <small class="d-block text-muted">
                                    Duration: {formatDuration(request.requestedDurationSeconds)}
                                </small>
                            {/if}
                            {#if request.requestedUses}
                                <small class="d-block text-muted">
                                    Uses: {request.requestedUses}
                                </small>
                            {/if}
                            {#if request.resolvedByUsername}
                                <small class="d-block text-muted">
                                    {request.status === TicketRequestStatus.Approved ? 'Approved' : 'Denied'} by {request.resolvedByUsername}
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
                        {#if request.status === TicketRequestStatus.Pending}
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
                        {/if}
                    </div>
                {/each}
            </div>
            {:else}
            <EmptyState
                title="No ticket requests"
                hint="Ticket requests will appear here when users request self-service tickets"
            />
            {/if}
        {/if}
        </Loadable>
    </PermissionGate>
</div>

<Modal isOpen={!!denyModalRequest} toggle={() => denyModalRequest = undefined}>
    <ModalBody>
        <h5 class="modal-title mb-3">Deny ticket request</h5>
        {#if denyError}
        <Alert color="danger">{denyError}</Alert>
        {/if}
        {#if denyModalRequest}
        <p>
            Deny request from <strong>{denyModalRequest.username}</strong> to <strong>{denyModalRequest.targetName}</strong>?
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
