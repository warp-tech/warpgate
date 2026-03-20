<script lang="ts">
    import { api, TargetKind, type TicketRequest, type Ticket, type TargetSnapshot } from 'gateway/lib/api'
    import { serverInfo } from 'gateway/lib/store'
    import AsyncButton from 'common/AsyncButton.svelte'
    import RelativeDate from 'admin/RelativeDate.svelte'
    import ConnectionInstructions from 'common/ConnectionInstructions.svelte'
    import Fa from 'svelte-fa'
    import { faTicket } from '@fortawesome/free-solid-svg-icons'
    import { stringifyError } from 'common/errors'
    import Alert from 'common/sveltestrap-s5-ports/Alert.svelte'
    import { FormGroup, Button } from '@sveltestrap/sveltestrap'
    import EmptyState from 'common/EmptyState.svelte'
    import Loadable from 'common/Loadable.svelte'
    import { statusIcon, statusColor } from 'common/ticketRequestStatus'

    let error: string|undefined = $state()
    let success: string|undefined = $state()
    let lastSecret: string|undefined = $state()
    let lastTargetName: string|undefined = $state()
    let requests: TicketRequest[]|undefined = $state()
    let tickets: Ticket[]|undefined = $state()
    let targets: TargetSnapshot[]|undefined = $state()

    let selectedTarget = $state('')
    let description = $state('')
    let durationMinutes: number|undefined = $state(480)
    let uses: number|undefined = $state()

    let selectedTargetData = $derived(targets?.find(t => t.name === selectedTarget))

    let maxDurationSeconds = $derived(
        selectedTargetData?.ticketMaxDurationSeconds
        ?? $serverInfo?.ticketMaxDurationSeconds
        ?? undefined
    )

    let maxDurationMinutes = $derived(
        maxDurationSeconds ? Math.floor(maxDurationSeconds / 60) : undefined
    )

    let durationError = $derived.by(() => {
        if (!durationMinutes || !maxDurationMinutes) return undefined
        if (durationMinutes > maxDurationMinutes) {
            return `Maximum duration for this target is ${maxDurationMinutes} minutes`
        }
        return undefined
    })

    async function load () {
        const [r, t, tgts] = await Promise.all([
            api.getMyTicketRequests(),
            api.getMyTickets(),
            api.getTargets({ search: '' }),
        ])
        requests = r
        tickets = t
        targets = tgts
        if (targets.length && !selectedTarget) {
            selectedTarget = targets[0]!.name
        }
    }

    const initPromise = load()

    async function createRequest () {
        if (durationError) return
        error = undefined
        success = undefined
        lastSecret = undefined
        lastTargetName = undefined
        try {
            const result = await api.createTicketRequest({
                createTicketRequestBody: {
                    targetName: selectedTarget,
                    durationSeconds: durationMinutes ? durationMinutes * 60 : undefined,
                    uses: uses || undefined,
                    description: description || undefined,
                },
            })
            if (result.secret) {
                success = 'Ticket auto-approved!'
                lastSecret = result.secret
                lastTargetName = selectedTarget
            } else {
                success = 'Request submitted and is pending admin approval.'
            }
            description = ''
            uses = undefined
            await load()
        } catch (err: any) {
            error = await stringifyError(err)
        }
    }

    async function deleteTicket (ticket: Ticket) {
        try {
            await api.deleteMyTicket({ id: ticket.id })
            await load()
        } catch (err: any) {
            error = await stringifyError(err)
        }
    }
</script>

<div class="page-summary-bar">
    <h1>Ticket requests</h1>
</div>

{#if error}
<Alert color="danger">{error}</Alert>
{/if}

{#if success}
<Alert color="success" fade={false}>
    {success}
    {#if lastSecret && lastTargetName}
        {@const targetData = targets?.find(t => t.name === lastTargetName)}
        {#if targetData}
            <div class="mt-3">
                <Alert color="warning" fade={false} class="mb-2">
                    The secret is only shown once &mdash; you won't be able to see it again.
                </Alert>
                <ConnectionInstructions
                    targetName={lastTargetName}
                    targetKind={targetData.kind}
                    username={$serverInfo?.username}
                    ticketSecret={lastSecret}
                    targetExternalHost={targetData.kind === TargetKind.Http ? targetData.externalHost : undefined}
                    targetDefaultDatabaseName={
                        (targetData.kind === TargetKind.MySql || targetData.kind === TargetKind.Postgres)
                            ? targetData.defaultDatabaseName : undefined}
                />
            </div>
        {/if}
    {/if}
</Alert>
{/if}

<Loadable promise={initPromise}>
<h4 class="mt-4">Request a ticket</h4>

{#if targets && targets.length}
<form onsubmit={e => e.preventDefault()}>
<div class="card p-3 mb-4">
    <FormGroup floating label="Target">
        <select bind:value={selectedTarget} class="form-control" required>
            {#each targets as target (target.name)}
                <option value={target.name}>
                    {target.name}
                </option>
            {/each}
        </select>
    </FormGroup>

    <FormGroup floating label="Description">
        <input type="text" bind:value={description} class="form-control" placeholder="Why do you need access?" maxlength="2000"/>
    </FormGroup>

    <FormGroup floating label="Duration (minutes)">
        <input
            type="number"
            min="1"
            max={maxDurationMinutes ?? undefined}
            bind:value={durationMinutes}
            class="form-control"
            class:is-invalid={!!durationError}
        />
        {#if durationError}
            <div class="invalid-feedback">{durationError}</div>
        {:else if maxDurationMinutes}
            <small class="form-text text-muted">Maximum: {maxDurationMinutes} minutes</small>
        {/if}
    </FormGroup>

    <FormGroup floating label="Number of uses (optional)">
        <input type="number" min="1" bind:value={uses} class="form-control"/>
    </FormGroup>

    <AsyncButton
        color="primary"
        click={createRequest}
        disabled={!!durationError}
    >Request ticket</AsyncButton>
</div>
</form>
{:else if targets}
<EmptyState title="No targets available" />
{/if}

{#if requests}
<h4 class="mt-4">My requests</h4>
{#if requests.length}
<div class="list-group list-group-flush mb-4">
    {#each requests as request (request.id)}
        <div class="list-group-item d-flex align-items-center">
            <span class={statusColor(request.status)} title={request.status}>
                <Fa icon={statusIcon(request.status)} fw />
            </span>
            <div class="ms-2">
                <strong>{request.targetName}</strong>
                <small class="d-block text-muted">
                    {request.status}
                    {#if request.denyReason}
                        &mdash; {request.denyReason}
                    {/if}
                </small>
                {#if request.description}
                    <small class="d-block text-muted">{request.description}</small>
                {/if}
            </div>
            <small class="text-muted ms-auto">
                <RelativeDate date={request.created} />
            </small>
        </div>
    {/each}
</div>
{:else}
<EmptyState title="No ticket requests yet" />
{/if}
{/if}

{#if tickets}
<h4 class="mt-4">My active tickets</h4>
{#if tickets.length}
<div class="list-group list-group-flush">
    {#each tickets as ticket (ticket.id)}
        <div class="list-group-item d-flex align-items-center">
            <Fa icon={faTicket} fw class="text-success" />
            <div class="ms-2">
                <strong>{ticket.target}</strong>
                {#if ticket.description}
                    <small class="d-block text-muted">{ticket.description}</small>
                {/if}
            </div>
            {#if ticket.expiry}
                <small class="text-muted ms-4">
                    Expires {ticket.expiry.toLocaleString()}
                </small>
            {/if}
            {#if ticket.usesLeft != null}
                <small class="text-muted ms-4">
                    {ticket.usesLeft} uses left
                </small>
            {/if}
            <small class="text-muted ms-auto me-2">
                <RelativeDate date={ticket.created} />
            </small>
            <Button
                color="link"
                size="sm"
                onclick={() => deleteTicket(ticket)}
            >Revoke</Button>
        </div>
    {/each}
</div>
{:else}
<EmptyState title="No active self-service tickets" />
{/if}
{/if}
</Loadable>
