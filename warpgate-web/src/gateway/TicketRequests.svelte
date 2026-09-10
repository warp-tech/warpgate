<script lang="ts">
    import { faEyeSlash, faTicket } from '@fortawesome/free-solid-svg-icons'
    import {
        Alert,
        Button,
        FormGroup,
        Modal,
        ModalBody,
        ModalFooter,
    } from '@sveltestrap/sveltestrap'
    import AsyncButton from 'common/AsyncButton.svelte'
    import ConnectionInstructions from 'common/ConnectionInstructions.svelte'
    import {
        formatDurationAsHumantime,
        parseHumantimeDuration,
    } from 'common/duration'
    import EmptyState from 'common/EmptyState.svelte'
    import { stringifyError } from 'common/errors'
    import { routeQueryParams } from 'common/helpers'
    import InfoBox from 'common/InfoBox.svelte'
    import Loadable from 'common/Loadable.svelte'
    import RelativeDate from 'common/RelativeDate.svelte'
    import { statusColor, statusIcon } from 'common/ticketRequestStatus'
    import {
        type ActivatedTicketTargetInfo,
        api,
        type MyTicketModel,
        type TicketRequestModel,
        TicketRequestStatus,
        type TicketRequestTarget,
    } from 'gateway/lib/api'
    import { serverInfo } from 'gateway/lib/store'
    import Fa from 'svelte-fa'

    // Matches the server-side limit in warpgate-core/src/ticket_requests.rs
    const DESCRIPTION_MAX_LENGTH = 2000

    // Prefill from #/ticket-requests?target=x&description=y&duration=8h
    // `target` is what makes such a link meaningful; the other params are only
    // honoured alongside it, so a link can't open a plausible-looking prefilled
    // request against whichever target happens to be first in the dropdown.
    const urlParams = routeQueryParams()
    const paramTarget = urlParams.get('target')
    const paramDescription = paramTarget ? urlParams.get('description') : null
    const paramDuration = paramTarget ? urlParams.get('duration') : null

    let error: string | undefined = $state()
    let success: string | undefined = $state()
    let lastSecret: string | undefined = $state()
    let lastTarget: ActivatedTicketTargetInfo | undefined = $state()
    let requests: TicketRequestModel[] | undefined = $state()
    let tickets: MyTicketModel[] | undefined = $state()
    let ticketRequestTargets: TicketRequestTarget[] | undefined = $state()
    let showForm = $state(!!paramTarget)
    let showAllRequests = $state(false)

    const REQUEST_PAGE_SIZE = 25
    let visibleRequests = $derived.by(() => {
        if (!requests) {
            return []
        }
        if (showAllRequests) {
            return requests
        }
        return requests.slice(0, REQUEST_PAGE_SIZE)
    })

    let selectedTarget = $state(paramTarget ?? '')
    let description = $state(
        [...(paramDescription ?? '')].slice(0, DESCRIPTION_MAX_LENGTH).join(''),
    )
    let descriptionTouched = $state(false)
    let durationText = $state(paramDuration || '8h')

    let maxDurationSeconds = $derived($serverInfo?.ticketMaxDurationSeconds)

    let unavailableTarget = $derived.by(() => {
        if (!selectedTarget || !ticketRequestTargets) {
            return undefined
        }
        return ticketRequestTargets.some(t => t.name === selectedTarget)
            ? undefined
            : selectedTarget
    })

    let durationSeconds = $derived(parseHumantimeDuration(durationText))

    let durationError = $derived.by(() => {
        if (durationText.trim() && !durationSeconds) {
            return 'Invalid duration. Examples: 30m, 8h, 1d, 2h30m'
        }
        if (!durationSeconds || !maxDurationSeconds) {
            return undefined
        }
        if (durationSeconds > maxDurationSeconds) {
            return `Maximum duration: ${formatDurationAsHumantime(maxDurationSeconds)}`
        }
        return undefined
    })

    let descriptionRequired = $derived(
        $serverInfo?.ticketRequireDescription ?? false,
    )
    let descriptionMissing = $derived(
        descriptionRequired && !description.trim(),
    )

    let formInvalid = $derived(
        !!durationError || descriptionMissing || !!unavailableTarget,
    )

    async function load() {
        const [r, t, trt] = await Promise.all([
            api.getMyTicketRequests(),
            api.getMyTickets(),
            api.getTicketRequestTargets(),
        ])
        requests = r
        tickets = t
        ticketRequestTargets = trt
        // Never override an explicit selection
        if (ticketRequestTargets[0] && !selectedTarget) {
            selectedTarget = ticketRequestTargets[0].name
        }
    }

    const initPromise = load()

    async function createRequest() {
        if (formInvalid) {
            return
        }
        error = undefined
        success = undefined
        lastSecret = undefined
        lastTarget = undefined
        try {
            const result = await api.createTicketRequest({
                createTicketRequestBody: {
                    targetName: selectedTarget,
                    durationSeconds: durationSeconds || undefined,
                    description: description || undefined,
                },
            })
            if (result.autoApprovedTicketSecret) {
                success = 'Ticket was auto-approved'
                lastSecret = result.autoApprovedTicketSecret
                lastTarget = result.target
            } else {
                success = 'Request submitted and is pending admin approval'
            }
            showForm = false
            description = ''
            descriptionTouched = false
            await load()
        } catch (err) {
            error = await stringifyError(err)
            throw err
        }
    }

    function openRequestForm() {
        showForm = true
        error = undefined
        success = undefined
        lastSecret = undefined
        lastTarget = undefined
        descriptionTouched = false
    }

    async function activateRequest(request: TicketRequestModel) {
        error = undefined
        success = undefined
        lastSecret = undefined
        lastTarget = undefined
        try {
            const result = await api.activateTicketRequest({ id: request.id })
            if (result.secret) {
                success = 'Ticket activated'
                lastSecret = result.secret
                lastTarget = result.target
            }
            showForm = false
            await load()
        } catch (err) {
            error = await stringifyError(err)
            throw err
        }
    }

    async function deleteTicket(ticket: MyTicketModel) {
        try {
            await api.deleteMyTicket({ id: ticket.id })
            await load()
        } catch (err) {
            error = await stringifyError(err)
        }
    }
</script>

<div class="page-summary-bar">
    <h1>Ticket requests</h1>
    <button
        type="button"
        class="btn btn-primary ms-auto"
        onclick={openRequestForm}
    >
        Request a ticket
    </button>
</div>

{#if error}
    <Alert color="danger">{error}</Alert>
{/if}

{#if success}
    <Alert color="success" fade={false}>
        {success}
    </Alert>
    {#if lastSecret && lastTarget}
        <div class="my-5">
            <InfoBox class="mb-2" variant="warning">
                <strong>Personal use only</strong>
                &mdash; do not share this secret. It grants access as your
                account.
            </InfoBox>
            <InfoBox class="mb-3" icon={faEyeSlash}>
                The secret is only shown once &mdash; you won't be able to see
                it again.
            </InfoBox>
            <ConnectionInstructions
                targetName={lastTarget.name}
                targetKind={lastTarget.kind}
                username={$serverInfo?.username}
                ticketSecret={lastSecret}
                targetExternalHost={lastTarget.externalHost}
                targetDefaultDatabaseName={lastTarget.defaultDatabaseName}
            />
        </div>
    {/if}
{/if}

<Loadable promise={initPromise}>
    <Modal isOpen={showForm} toggle={() => showForm = false}>
        <ModalBody>
            <h4 class="mb-3">Request a ticket</h4>

            {#if ticketRequestTargets?.length}
                {#if unavailableTarget}
                    <Alert color="warning" fade={false}>
                        <strong>{unavailableTarget}</strong>
                        is not available for ticket requests. Select a target
                        below.
                    </Alert>
                {/if}

                <form onsubmit={e => e.preventDefault()}>
                    <FormGroup floating label="Target">
                        <select
                            bind:value={selectedTarget}
                            class="form-control"
                            required
                        >
                            {#each ticketRequestTargets as target (target.name)}
                                <option value={target.name}>
                                    {target.name}
                                </option>
                            {/each}
                        </select>
                    </FormGroup>

                    <FormGroup
                        floating
                        label={descriptionRequired ? 'Description (required)' : 'Description'}
                    >
                        <input
                            type="text"
                            bind:value={description}
                            class="form-control"
                            class:is-invalid={descriptionMissing && descriptionTouched}
                            placeholder="Why do you need access?"
                            maxlength="2000"
                            onblur={() => descriptionTouched = true}
                        >
                        {#if descriptionMissing}
                            <small class="form-text text-muted">
                                A description is required for ticket requests.
                            </small>
                        {/if}
                    </FormGroup>

                    <FormGroup floating label="Duration">
                        <input
                            type="text"
                            bind:value={durationText}
                            class="form-control"
                            class:is-invalid={!!durationError}
                            placeholder="e.g. 8h, 30m, 1d"
                        >
                        {#if durationError}
                            <div class="invalid-feedback">{durationError}</div>
                        {:else if maxDurationSeconds}
                            <small class="form-text text-muted">
                                Maximum:
                                {formatDurationAsHumantime(maxDurationSeconds)}
                            </small>
                        {:else}
                            <small class="form-text text-muted">
                                Examples: 30m, 8h, 1d, 2h30m
                            </small>
                        {/if}
                    </FormGroup>
                </form>
            {:else if ticketRequestTargets}
                <EmptyState
                    title="No targets available"
                    hint={unavailableTarget ? `${unavailableTarget} is not available for ticket requests.` : ''}
                />
            {/if}
        </ModalBody>
        <ModalFooter>
            <AsyncButton
                color="primary"
                class="modal-button"
                click={createRequest}
                disabled={formInvalid || !ticketRequestTargets?.length}
            >
                Request ticket
            </AsyncButton>

            <Button
                class="modal-button"
                color="secondary"
                onclick={() => showForm = false}
            >
                Close
            </Button>
        </ModalFooter>
    </Modal>

    {#if requests}
        <h4 class="mt-4">My requests</h4>
        {#if requests.length}
            <div class="list-group list-group-flush mb-4">
                {#each visibleRequests as request (request.id)}
                    <div class="list-group-item gap-3">
                        <span
                            class={statusColor(request.status)}
                            title={request.status}
                        >
                            <Fa icon={statusIcon(request.status)} fw />
                        </span>
                        <div class="me-auto">
                            <strong>{request.targetName}</strong>
                            <small class="d-block text-muted">
                                {request.status}
                                {#if request.denyReason}
                                    &mdash; {request.denyReason}
                                {/if}
                            </small>
                            {#if request.description}
                                <small class="d-block text-muted"
                                    >{request.description}</small
                                >
                            {/if}
                        </div>
                        {#if request.status === TicketRequestStatus.Approved && !request.ticketId}
                            <AsyncButton
                                color="success"
                                click={() => activateRequest(request)}
                            >
                                Activate
                            </AsyncButton>
                        {/if}
                        <small class="text-muted flex-shrink-0">
                            <RelativeDate date={request.created} />
                        </small>
                    </div>
                {/each}
            </div>
            {#if !showAllRequests && requests.length > REQUEST_PAGE_SIZE}
                <Button color="link" onclick={() => showAllRequests = true}>
                    Show all {requests.length} requests
                </Button>
            {/if}
        {:else}
            <EmptyState title="No ticket requests yet" />
        {/if}
    {/if}

    {#if tickets}
        <h4 class="mt-4">Active tickets</h4>
        {#if tickets.length}
            <div class="list-group list-group-flush">
                {#each tickets as ticket (ticket.id)}
                    <div class="list-group-item gap-3">
                        <Fa icon={faTicket} fw class="text-success" />
                        <div class="me-auto">
                            <strong>{ticket.targetName}</strong>
                            {#if ticket.description}
                                <small class="d-block text-muted"
                                    >{ticket.description}</small
                                >
                            {/if}
                            {#if ticket.expiry}
                                <small class="d-block text-muted">
                                    Expires
                                    <RelativeDate date={ticket.expiry} />
                                </small>
                            {/if}
                            {#if ticket.usesLeft != null}
                                <small class="d-block text-muted">
                                    {ticket.usesLeft}
                                    uses left
                                </small>
                            {/if}
                        </div>
                        <small class="text-muted flex-shrink-0">
                            <RelativeDate date={ticket.created} />
                        </small>
                        <Button
                            color="link"
                            size="sm"
                            onclick={() => deleteTicket(ticket)}
                        >
                            Revoke
                        </Button>
                    </div>
                {/each}
            </div>
        {:else}
            <EmptyState title="No active self-service tickets" />
        {/if}
    {/if}
</Loadable>

<style lang="scss">
    .list-group-item {
        display: flex;
        align-items: center;
    }
</style>
