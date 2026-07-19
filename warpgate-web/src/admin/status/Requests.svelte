<script lang="ts">
    import {
        faComputer,
        faEllipsisVertical,
        faTicket,
    } from '@fortawesome/free-solid-svg-icons'
    import {
        Alert,
        Button,
        ButtonGroup,
        Dropdown,
        DropdownItem,
        DropdownMenu,
        DropdownToggle,
        FormGroup,
        Modal,
        ModalBody,
        ModalFooter,
    } from '@sveltestrap/sveltestrap'
    import {
        api,
        type SessionApprovalItem,
        SessionApprovalScope,
        type TicketRequest,
        TicketRequestStatus,
    } from 'admin/lib/api'
    import { adminPermissions } from 'admin/lib/store'
    import AsyncButton from 'common/AsyncButton.svelte'
    import { formatDurationAsHumantime } from 'common/duration'
    import { stringifyError } from 'common/errors'
    import Loadable from 'common/Loadable.svelte'
    import RelativeDate from 'common/RelativeDate.svelte'
    import { onDestroy, onMount } from 'svelte'
    import Fa from 'svelte-fa'

    /// One inbox entry, whichever kind of request produced it. `at` is the
    /// shared sort key so both kinds interleave chronologically.
    type Entry =
        | {
              kind: 'session'
              id: string
              at: Date
              session: SessionApprovalItem
          }
        | { kind: 'ticket'; id: string; at: Date; ticket: TicketRequest }

    let sessions: SessionApprovalItem[] = $state([])
    let tickets: TicketRequest[] = $state([])
    let error: string | undefined = $state()
    let denyModalRequest: TicketRequest | undefined = $state()
    let denyReason = $state('')
    let denyError: string | undefined = $state()

    let canSeeSessions = $derived($adminPermissions.sessionsView)
    let canManageTickets = $derived($adminPermissions.ticketRequestsManage)

    // Oldest first: the longest-waiting request is the one to action next.
    let entries: Entry[] = $derived(
        [
            ...sessions.map(
                session =>
                    ({
                        kind: 'session',
                        id: session.id,
                        at: session.started,
                        session,
                    }) as Entry,
            ),
            ...tickets.map(
                ticket =>
                    ({
                        kind: 'ticket',
                        id: ticket.id,
                        at: ticket.created,
                        ticket,
                    }) as Entry,
            ),
        ].sort((a, b) => a.at.getTime() - b.at.getTime()),
    )

    async function reload() {
        const [loadedSessions, loadedTickets] = await Promise.all([
            canSeeSessions ? api.getSessionApprovals() : Promise.resolve([]),
            canManageTickets
                ? api.getTicketRequests({ status: TicketRequestStatus.Pending })
                : Promise.resolve([]),
        ])
        sessions = loadedSessions
        tickets = loadedTickets
    }

    $effect(() => {
        if (!canSeeSessions) {
            return
        }
        const ws = new WebSocket(
            `wss://${location.host}/@warpgate/admin/api/session-approvals/changes`,
        )
        ws.addEventListener('message', reload)
        onDestroy(() => ws.close())
    })

    $effect(() => {
        if (!canManageTickets) {
            return
        }

        // Ticket requests are not pushed, so poll for those (which also catches
        // requests resolved by another admin).
        const interval = setInterval(reload, 30000)
        onDestroy(() => clearInterval(interval))
    })

    async function approveSession(
        item: SessionApprovalItem,
        scope: SessionApprovalScope,
    ) {
        await api.approveSession({ id: item.id, scope })
        await reload()
    }

    async function rejectSession(item: SessionApprovalItem) {
        await api.rejectSession({ id: item.id })
        await reload()
    }

    async function approveTicket(request: TicketRequest) {
        error = undefined
        try {
            await api.approveTicketRequest({ id: request.id })
            await reload()
        } catch (err) {
            error = await stringifyError(err)
            throw err
        }
    }

    async function denyTicket() {
        if (!denyModalRequest) {
            return
        }
        denyError = undefined
        try {
            await api.denyTicketRequest({
                id: denyModalRequest.id,
                denyTicketRequestBody: { reason: denyReason || undefined },
            })
            denyModalRequest = undefined
            denyReason = ''
            await reload()
        } catch (err) {
            denyError = await stringifyError(err)
            throw err
        }
    }
</script>

<div class="page-summary-bar">
    <h1>requests</h1>
</div>

{#if !canSeeSessions && !canManageTickets}
    <Alert color="warning">You have no permission to view requests.</Alert>
{:else}
    {#if error}
        <Alert color="danger">{error}</Alert>
    {/if}

    <Loadable promise={reload()}>
        {#if !entries.length}
            <div class="text-muted">Nothing is awaiting your action.</div>
        {/if}

        <div class="list-group list-group-flush">
            {#each entries as entry (entry.id)}
                <div class="list-group-item d-flex align-items-center gap-4">
                    {#if entry.kind === 'session'}
                        <Fa icon={faComputer} fw />
                        <div>
                            <div>
                                <strong>{entry.session.username}</strong>
                                <span class="text-muted">
                                    is connecting to
                                </span>
                                <strong>{entry.session.target}</strong>
                            </div>
                            <div class="meta text-muted">
                                {#if entry.session.address}
                                    {entry.session.address}
                                    ·
                                {/if}
                                key {entry.session.identificationString} ·
                                <RelativeDate date={entry.session.started} />
                            </div>
                        </div>

                        <div class="ms-auto d-flex align-items-center">
                            <ButtonGroup>
                                {#if entry.session.cachingGraceSeconds}
                                    <AsyncButton
                                        color="success"
                                        click={() =>
                                        approveSession(
                                            entry.session,
                                            SessionApprovalScope.Target,
                                        )}
                                    >
                                        Approve for
                                        {formatDurationAsHumantime(
                                            entry.session.cachingGraceSeconds,
                                        )}
                                    </AsyncButton>
                                    <Dropdown class="btn-group">
                                        <DropdownToggle
                                            color="success"
                                            class="px-3"
                                        >
                                            <Fa icon={faEllipsisVertical} />
                                        </DropdownToggle>

                                        <DropdownMenu end>
                                            <DropdownItem
                                                onclick={() => approveSession(
                                                    entry.session,
                                                    SessionApprovalScope.AllTargets,
                                                )}
                                            >
                                                Approve for all targets for
                                                {formatDurationAsHumantime(
                                                    entry.session.cachingGraceSeconds,
                                                )}
                                            </DropdownItem>
                                            <DropdownItem
                                                onclick={() => approveSession(
                                                    entry.session,
                                                    SessionApprovalScope.Once,
                                                )}
                                            >
                                                Approve this time only
                                            </DropdownItem>
                                        </DropdownMenu>
                                    </Dropdown>
                                {:else}
                                    <AsyncButton
                                        color="success"
                                        click={() =>
                                        approveSession(
                                            entry.session,
                                            SessionApprovalScope.Once,
                                        )}
                                    >
                                        Approve
                                    </AsyncButton>
                                {/if}
                                <AsyncButton
                                    color="danger"
                                    click={() => rejectSession(entry.session)}
                                >
                                    Reject
                                </AsyncButton>
                            </ButtonGroup>
                        </div>
                    {:else}
                        <Fa icon={faTicket} fw />
                        <div>
                            <div>
                                <strong
                                    >{entry.ticket.username ?? '(deleted)'}</strong
                                >
                                <span class="text-muted">
                                    needs a ticket for
                                </span>
                                <strong>
                                    {entry.ticket.targetName ?? '(deleted)'}
                                </strong>
                            </div>
                            <div class="meta text-muted">
                                {#if entry.ticket.requestedDurationSeconds}
                                    valid for
                                    {formatDurationAsHumantime(
                                        entry.ticket.requestedDurationSeconds,
                                    )}
                                    ·
                                {/if}
                                <RelativeDate date={entry.ticket.created} />
                                {#if entry.ticket.description}
                                    <div>{entry.ticket.description}</div>
                                {/if}
                            </div>
                        </div>

                        <ButtonGroup class="ms-auto">
                            <AsyncButton
                                color="success"
                                click={() => approveTicket(entry.ticket)}
                            >
                                Approve
                            </AsyncButton>
                            <Button
                                color="danger"
                                onclick={() => {
                                    denyModalRequest = entry.ticket
                                    denyReason = ''
                                    denyError = undefined
                                }}
                            >
                                Reject
                            </Button>
                        </ButtonGroup>
                    {/if}
                </div>
            {/each}
        </div>
    </Loadable>
{/if}

<Modal
    isOpen={!!denyModalRequest}
    toggle={() => (denyModalRequest = undefined)}
>
    <ModalBody>
        {#if denyError}
            <Alert color="danger">{denyError}</Alert>
        {/if}
        {#if denyModalRequest}
            <p>
                Deny request from
                <strong>{denyModalRequest.username}</strong>
                to
                <strong>{denyModalRequest.targetName}</strong>?
            </p>
            <FormGroup floating label="Reason (optional)">
                <input
                    type="text"
                    bind:value={denyReason}
                    class="form-control"
                    placeholder="Why is this being denied?"
                    maxlength="2000"
                >
            </FormGroup>
        {/if}
    </ModalBody>
    <ModalFooter>
        <AsyncButton class="modal-button" color="danger" click={denyTicket}>
            Deny
        </AsyncButton>
        <Button
            class="modal-button"
            color="secondary"
            onclick={() => (denyModalRequest = undefined)}
        >
            Cancel
        </Button>
    </ModalFooter>
</Modal>

<style lang="scss">
    .meta {
        font-size: .75rem;
    }
</style>
