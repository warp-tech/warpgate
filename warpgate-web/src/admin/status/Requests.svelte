<script lang="ts">
    import Menu from 'ui/Menu.svelte'
    import 'ui/layout.css'
    import {
        faComputer,
        faEllipsisVertical,
        faTicket,
    } from '@fortawesome/free-solid-svg-icons'
    import {
        ApprovalScope,
        api,
        type SessionApprovalItem,
        type TicketRequest,
    } from 'admin/lib/api'
    import { adminPermissions } from 'admin/lib/store'
    import {
        loadPendingRequests,
        watchPendingRequests,
    } from 'common/approvalRequests'
    import DelayedSpinner from 'common/DelayedSpinner.svelte'
    import { formatDurationAsHumantime } from 'common/duration'
    import EmptyState from 'common/EmptyState.svelte'
    import { errorStatus, stringifyError } from 'common/errors'
    import RelativeDate from 'ui/RelativeDate.svelte'
    import Fa from 'svelte-fa'
    import Button from 'ui/Button.svelte'
    import Callout from 'ui/Callout.svelte'
    import Modal from 'ui/Modal.svelte'

    // One inbox entry, whichever kind of request produced it. `at` is the
    // shared sort key so both kinds interleave chronologically, and `key`
    // identifies the entry in the list: a session holds a question per gated
    // target it reaches, so its id alone does not distinguish them.
    type Entry = { key: string; at: Date } & (
        | { kind: 'session'; session: SessionApprovalItem }
        | { kind: 'ticket'; ticket: TicketRequest }
    )

    let sessions: SessionApprovalItem[] = $state([])
    let tickets: TicketRequest[] = $state([])
    // Separate slots: a background refresh must not eat the message telling
    // the admin their action failed, and an action must not hide a list that
    // has stopped loading.
    let loadError: string | undefined = $state()
    let actionError: string | undefined = $state()
    let error = $derived(actionError ?? loadError)
    // Gates the first render only; the watch drives every refresh after it.
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
                (session): Entry => ({
                    kind: 'session',
                    key: `session:${session.id}:${session.target}`,
                    at: session.started,
                    session,
                }),
            ),
            ...tickets.map(
                (ticket): Entry => ({
                    kind: 'ticket',
                    key: `ticket:${ticket.id}`,
                    at: ticket.created,
                    ticket,
                }),
            ),
        ].sort((a, b) => a.at.getTime() - b.at.getTime()),
    )

    // Swallows the error so a failed background refresh leaves the last known
    // list on screen instead of blanking the inbox.
    async function refresh() {
        try {
            const result = await loadPendingRequests({
                canSeeSessions,
                canManageTickets,
            })
            sessions = result.sessions
            tickets = result.tickets
            loadError = undefined
        } catch (err) {
            loadError = await stringifyError(err)
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

    // A 404 means someone else already resolved it, or the held session gave
    // up waiting — the entry is simply gone. It answers with no body, so it
    // needs saying here; a shared queue produces it routinely and "API error:"
    // with nothing after it explains nothing.
    async function describeFailure(err: unknown): Promise<string> {
        return errorStatus(err) === 404
            ? 'This request is no longer waiting — someone else answered it, or the session gave up.'
            : await stringifyError(err)
    }

    // Rethrows so the button that ran it marks the failure, and reloads either
    // way: a failed action usually means the entry has moved on without us.
    async function runAction(action: () => Promise<unknown>): Promise<void> {
        actionError = undefined
        try {
            await action()
        } catch (err) {
            actionError = await describeFailure(err)
            throw err
        } finally {
            await refresh()
        }
    }

    // The target is echoed with the decision so it lands on the question this
    // list rendered — a request reopened for another target since then reads
    // as already gone (404) rather than getting an answer meant for this one.
    async function approveSession(
        item: SessionApprovalItem,
        scope: ApprovalScope,
    ) {
        await runAction(() =>
            api.approveSession({
                id: item.id,
                approveSessionRequest: { scope, target: item.target },
            }),
        )
    }

    async function rejectSession(item: SessionApprovalItem) {
        await runAction(() =>
            api.rejectSession({
                id: item.id,
                rejectSessionRequest: { target: item.target },
            }),
        )
    }

    async function approveTicket(request: TicketRequest) {
        await runAction(() => api.approveTicketRequest({ id: request.id }))
    }

    // Reports into the modal it is run from, not the page behind it.
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
        } catch (err) {
            denyError = await describeFailure(err)
            throw err
        }
        denyModalRequest = undefined
        denyReason = ''
        await refresh()
    }
</script>

<div class="page-summary-bar">
    <h1>requests</h1>
</div>

{#if !canSeeSessions && !canManageTickets}
    <Callout tone="warning">You have no permission to view requests.</Callout>
{:else}
    {#if error}
        <Callout tone="danger" title="Something went wrong">{error}</Callout>
    {/if}

    {#if !loaded}
        <DelayedSpinner />
    {:else}
        {#if !entries.length}
            <EmptyState title="Nothing right now" />
        {/if}

        <div class="list-group list-group-flush">
            {#each entries as entry (entry.key)}
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
                            <div class="btn-row">
                                {#if entry.session.cachingGraceSeconds}
                                    <Button
                                        variant="primary"
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
                                    </Button>
                                    <Menu
                                        label="More approve options"
                                        align="end"
                                        groups={[
                                            {
                                                items: [
                                                    {
                                                        id: 'all',
                                                        label: `Approve for all targets for ${formatDurationAsHumantime(entry.session.cachingGraceSeconds)}`,
                                                        onselect: () =>
                                                            approveSession(
                                                                entry.session,
                                                                ApprovalScope.AllTargets,
                                                            ),
                                                    },
                                                    {
                                                        id: 'once',
                                                        label: 'Approve this time only',
                                                        onselect: () =>
                                                            approveSession(
                                                                entry.session,
                                                                ApprovalScope.Once,
                                                            ),
                                                    },
                                                ],
                                            },
                                        ]}
                                    />
                                {:else}
                                    <Button
                                        variant="primary"
                                        click={() =>
                                        approveSession(
                                            entry.session,
                                            ApprovalScope.Once,
                                        )}
                                    >
                                        Approve
                                    </Button>
                                {/if}
                                <Button
                                    variant="destructive"
                                    click={() => rejectSession(entry.session)}
                                >
                                    Reject
                                </Button>
                            </div>
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

                        <div class="btn-row ms-auto">
                            <Button
                                variant="primary"
                                click={() => approveTicket(entry.ticket)}
                            >
                                Approve
                            </Button>
                            <Button
                                variant="destructive"
                                onclick={() => {
                                    denyModalRequest = entry.ticket
                                    denyReason = ''
                                    denyError = undefined
                                }}
                            >
                                Reject
                            </Button>
                        </div>
                    {/if}
                </div>
            {/each}
        </div>
    {/if}
{/if}

<Modal
    open={!!denyModalRequest}
    title="Deny this ticket request?"
    size="sm"
    onclose={() => (denyModalRequest = undefined)}
>
    {#if denyError}
        <Callout tone="danger" title="Something went wrong"
            >{denyError}</Callout
        >
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
        <div class="wg-field-group">
            <span class="wg-field-label">Reason (optional)</span>

            <input
                type="text"
                bind:value={denyReason}
                class="form-control"
                placeholder="Why is this being denied?"
                maxlength="2000"
            >
        </div>
    {/if}

    {#snippet footer()}
        <Button onclick={() => (denyModalRequest = undefined)}>Cancel</Button>
        <Button variant="destructive" click={denyTicket}>Deny</Button>
    {/snippet}
</Modal>

<style>
    .btn-row {
        display: flex;
        align-items: center;
        gap: var(--wg-space-sm);
    }
</style>
