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
        ApprovalScope,
        api,
        type SessionApprovalItem,
        type TicketRequest,
    } from 'admin/lib/api'
    import { adminPermissions } from 'admin/lib/store'
    import AsyncButton from 'common/AsyncButton.svelte'
    import {
        loadPendingRequests,
        watchPendingRequests,
    } from 'common/approvalRequests'
    import DelayedSpinner from 'common/DelayedSpinner.svelte'
    import { formatDurationAsHumantime } from 'common/duration'
    import { stringifyError } from 'common/errors'
    import RelativeDate from 'common/RelativeDate.svelte'
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
    /// Gates the first render only; the watch drives every refresh after it.
    let loaded = $state(false)
    let denyModalRequest: TicketRequest | undefined = $state()
    let denyReason = $state('')
    let denyError: string | undefined = $state()

    let canSeeSessions = $derived($adminPermissions.approveSessions)
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
        const result = await loadPendingRequests({
            canSeeSessions,
            canManageTickets,
        })
        sessions = result.sessions
        tickets = result.tickets
    }

    /// Swallows the error so a failed background refresh leaves the last known
    /// list on screen instead of blanking the inbox; actions surface their own.
    ///
    /// `keepError` is for the refresh that follows a failed action: the list
    /// needs reloading either way, but the message saying why the action failed
    /// is the only thing telling the admin anything happened at all.
    async function refresh(keepError = false) {
        try {
            await reload()
            if (!keepError) {
                error = undefined
            }
        } catch (err) {
            error = await stringifyError(err)
        }
        loaded = true
    }

    // Returned from the effect, not registered with onDestroy: re-running the
    // effect must tear down the previous watch, which onDestroy (scoped to the
    // component) would defer until unmount, leaking a socket per run.
    $effect(() =>
        watchPendingRequests({ canSeeSessions, canManageTickets }, () => {
            void refresh()
        }),
    )

    /// A 404 means someone else already resolved it, or the held session gave
    /// up waiting — the entry is simply gone, so reload either way.
    async function resolveSession(action: () => Promise<void>) {
        error = undefined
        let failed = false
        try {
            await action()
        } catch (err) {
            error = await stringifyError(err)
            failed = true
        }
        await refresh(failed)
    }

    // The target is echoed with the decision so it lands on the question this
    // list rendered — a request reopened for another target since then reads
    // as already gone (404) rather than getting an answer meant for this one.
    async function approveSession(
        item: SessionApprovalItem,
        scope: ApprovalScope,
    ) {
        await resolveSession(() =>
            api.approveSession({ id: item.id, scope, target: item.target }),
        )
    }

    async function rejectSession(item: SessionApprovalItem) {
        await resolveSession(() =>
            api.rejectSession({ id: item.id, target: item.target }),
        )
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

    {#if !loaded}
        <DelayedSpinner />
    {:else}
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
                            <div class="small text-muted">
                                {#if entry.session.address}
                                    {entry.session.address}
                                    ·
                                {/if}
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
                                            ApprovalScope.Target,
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
                                                    ApprovalScope.AllTargets,
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
                                                    ApprovalScope.Once,
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
                                            ApprovalScope.Once,
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
                                <strong>
                                    {entry.ticket.username ?? entry.ticket.userId}
                                </strong>
                                <span class="text-muted">
                                    needs a ticket for
                                </span>
                                <strong>
                                    {entry.ticket.targetName ?? entry.ticket.targetId}
                                </strong>
                            </div>
                            <div class="small text-muted">
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
    {/if}
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
                <strong>
                    {denyModalRequest.username ?? denyModalRequest.userId}
                </strong>
                to
                <strong>
                    {denyModalRequest.targetName ?? denyModalRequest.targetId}
                </strong
                >?
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
