<script lang="ts">
    /**
     * Session detail — screen 2.
     *
     * A timeline, not a table: connection, authentication, approvals, target
     * connections, recordings and disconnect, in the order they happened. The
     * shape follows the data rather than warpgate_session_replay, which draws
     * the *player* — that is the recording route, not this one.
     *
     * Behaviour preserved from admin/status/Session.svelte:
     *   - 1s polling, so a live session's timeline grows while you watch
     *   - target sessions sorted newest-first
     *   - recordings matched to their target session by sessionId
     *   - recording links gated on recordingsView
     *   - close gated on PROTOCOL_PROPERTIES[...].sessionsCanBeClosed, which
     *     is why HTTP sessions have no close button
     *   - the embedded LogViewer, filtered to this session
     *
     * Dropped: `getTargetAddress()`, which was defined and never called.
     */
    import {
        ApprovalRequestStatus,
        api,
        type Recording,
        type TargetSessionSnapshot,
        type UserSessionSnapshot,
    } from 'admin/lib/api'
    import { adminPermissions } from 'admin/lib/store'
    import TargetBadge from 'admin/log-viewer/TargetBadge.svelte'
    import UserBadge from 'admin/log-viewer/UserBadge.svelte'
    import { stringifyError } from 'common/errors'
    import { PROTOCOL_PROPERTIES } from 'common/protocols'
    import {
        recordingMetadataToFieldSet,
        recordingTypeLabel,
    } from 'common/recordings'
    import { formatDistanceStrict } from 'date-fns'
    import { onDestroy } from 'svelte'
    import firstBy from 'thenby'
    import Badge from 'ui/Badge.svelte'
    import Button from 'ui/Button.svelte'
    import Callout from 'ui/Callout.svelte'
    import ConfirmDialog from 'ui/ConfirmDialog.svelte'
    import RelativeDate from 'ui/RelativeDate.svelte'
    import SkeletonRow from 'ui/SkeletonRow.svelte'
    import StatusMarker from 'ui/StatusMarker.svelte'
    import { toast } from 'ui/toasts.svelte'
    import LogViewer from '../log-viewer/LogViewer.svelte'

    interface Props {
        params: { id: string }
    }

    let { params = { id: '' } }: Props = $props()

    let error: string | null = $state(null)
    let session: UserSessionSnapshot | null = $state(null)
    let recordings: Recording[] | null = $state(null)
    let closeOpen = $state(false)

    async function load() {
        const loaded = await api.getSession(params)
        loaded.targetSessions.sort(firstBy(x => x.started, 'desc'))
        session = loaded
        recordings = await api.getSessionRecordings(params)
    }

    async function closeSession() {
        if (!session) {
            return
        }
        await api.closeSession(session)
        toast.success('Session closed')
        await load()
    }

    function recordingsFor(s: TargetSessionSnapshot): Recording[] {
        return recordings?.filter(x => x.sessionId === s.id) ?? []
    }

    load().catch(async e => {
        error = await stringifyError(e)
    })

    const interval = setInterval(load, 1000)
    onDestroy(() => clearInterval(interval))

    // Bound to a local first: narrowing `session` inside a $derived expression
    // does not survive, and the chained access resolves to `never`.
    const canClose = $derived.by(() => {
        const s = session
        if (!s || s.ended) {
            return false
        }
        return !!PROTOCOL_PROPERTIES[s.protocol]?.sessionsCanBeClosed
    })
</script>

{#if error}
    <Callout tone="danger" title="Something went wrong">{error}</Callout>
{:else if !session}
    <SkeletonRow rows={6} columns={[1, 4, 2]} />
{:else}
    <div class="head">
        <div class="head-title">
            <h1>{session.protocol} session</h1>
            {#if session.ended}
                <StatusMarker kind="ended" label="Ended" />
            {:else}
                <StatusMarker kind="live" />
            {/if}
        </div>

        <p class="head-meta">
            {#if session.ended}
                {formatDistanceStrict(
                    new Date(session.started),
                    new Date(session.ended),
                )}
                long
            {/if}
            {#if session.nodeHostname}
                <span class="wg-mono">· {session.nodeHostname}</span>
            {/if}
        </p>
    </div>

    <ol class="timeline">
        <li>
            <span class="tl-dot" aria-hidden="true"></span>
            <span class="tl-label">Connected from</span>
            <span class="wg-mono">{session.remoteAddress}</span>
            <span class="tl-time"><RelativeDate date={session.started} /></span>
        </li>

        <li>
            <span class="tl-dot" aria-hidden="true"></span>
            {#if session.username}
                <span class="tl-label">Authenticated as</span>
                <UserBadge id={session.userId} name={session.username} />
            {:else}
                <span class="tl-label">
                    {session.ended
                        ? 'Not authenticated'
                        : 'Not authenticated yet'}
                </span>
            {/if}
        </li>

        {#each session.adminApprovals as approval (approval)}
            <li>
                <StatusMarker
                    kind={approval.status === ApprovalRequestStatus.Pending
                        ? 'pending'
                        : approval.status === ApprovalRequestStatus.Approved
                          ? 'online'
                          : 'failed'}
                    label={approval.status === ApprovalRequestStatus.Pending
                        ? 'Awaiting approval'
                        : approval.status === ApprovalRequestStatus.Approved
                          ? 'Approved'
                          : approval.status === ApprovalRequestStatus.Rejected
                            ? 'Rejected'
                            : 'Timed out'}
                />
                <span class="tl-label">for</span>
                <TargetBadge id={approval.targetId} name={approval.target} />
                {#if approval.resolvedAt}
                    {#if approval.resolvedByUsername}
                        <span class="tl-label">by</span>
                        <UserBadge
                            id={approval.resolvedByUserId}
                            name={approval.resolvedByUsername}
                        />
                    {/if}
                    <span class="tl-time">
                        <RelativeDate date={approval.resolvedAt} />
                    </span>
                {/if}
            </li>
        {/each}

        {#each session.targetSessions as targetSession (targetSession.id)}
            <li>
                <StatusMarker
                    kind={targetSession.ended ? 'ended' : 'live'}
                    label={targetSession.ended ? 'Closed' : 'Live'}
                />
                <span class="tl-label">on</span>
                {#if targetSession.target}
                    <TargetBadge
                        id={targetSession.targetId}
                        name={targetSession.target.name}
                    />
                {:else}
                    <span class="tl-label">a now deleted target</span>
                {/if}
                {#if targetSession.nodeHostname}
                    <span class="tl-time wg-mono">
                        via {targetSession.nodeHostname}
                    </span>
                {/if}
            </li>

            {#each recordingsFor(targetSession) as recording (recording.id)}
                {@const metadata = JSON.parse(recording.metadata)}
                <li class="tl-nested">
                    <StatusMarker
                        kind={session.ended || recording.ended
                            ? 'ended'
                            : 'live'}
                        label={session.ended || recording.ended
                            ? 'Recorded'
                            : 'Recording'}
                    />
                    {#if $adminPermissions.recordingsView}
                        <a
                            class="tl-recording"
                            href="#/status/recordings/{recording.id}"
                        >
                            <Badge tone="warning">
                                {recordingTypeLabel(recording)}
                            </Badge>
                        </a>
                    {:else}
                        <Badge tone="warning">
                            {recordingTypeLabel(recording)}
                        </Badge>
                    {/if}

                    {#if metadata}
                        <span class="tl-fields">
                            {#each recordingMetadataToFieldSet(metadata) as item (item[0])}
                                <span class="tl-field">
                                    <span class="tl-label">{item[0]}:</span>
                                    <span class="wg-mono">{item[1]}</span>
                                </span>
                            {/each}
                        </span>
                    {/if}
                    <span class="tl-time">
                        <RelativeDate date={recording.started} />
                    </span>
                </li>
            {/each}
        {/each}

        {#if session.ended && session.protocol !== 'HTTP'}
            <li>
                <span class="tl-dot" aria-hidden="true"></span>
                <span class="tl-label">Disconnected</span>
                <span class="tl-time"
                    ><RelativeDate date={session.ended} /></span
                >
            </li>
        {/if}
    </ol>

    <h2>Log</h2>
    <LogViewer filters={{ sessionId: session.id }} />

    {#if canClose}
        <div class="action-bar">
            <Button variant="destructive" onclick={() => (closeOpen = true)}>
                Close session now
            </Button>
        </div>
    {/if}
{/if}

<ConfirmDialog
    bind:open={closeOpen}
    title="Close this session?"
    confirmLabel="Close session"
    onconfirm={closeSession}
>
    <p>
        This disconnects the user immediately. Recordings already written are
        kept.
    </p>
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

    .head-title {
        display: flex;
        align-items: center;
        gap: var(--wg-space-md);
    }

    h1 {
        margin: 0;
        font: var(--wg-text-headline-lg);
    }

    h2 {
        margin: var(--wg-space-2xl) 0 var(--wg-space-md);
        font: var(--wg-text-headline-md);
    }

    .head-meta {
        margin: 0;
        font: var(--wg-text-body-md);
        color: var(--wg-text-muted);
    }

    .timeline {
        list-style: none;
        margin: 0;
        padding: 0;
        border: var(--wg-border-width) solid var(--wg-border);
        border-radius: var(--wg-radius-panel);
        overflow: hidden;
    }

    .timeline li {
        display: flex;
        align-items: center;
        flex-wrap: wrap;
        gap: var(--wg-space-sm);
        min-height: var(--wg-row-height);
        padding: var(--wg-space-xs) var(--wg-space-md);
        border-bottom: var(--wg-border-width) solid var(--wg-border);
        font: var(--wg-text-body-md);
    }

    .timeline li:last-child {
        border-bottom: 0;
    }

    .tl-nested {
        padding-left: var(--wg-space-2xl);
        background: var(--wg-surface-container-low);
    }

    .tl-dot {
        flex: none;
        width: 6px;
        height: 6px;
        border-radius: var(--wg-radius-full);
        background: var(--wg-text-subtle);
    }

    /* Keeps a label and its value together as one unit inside the
       wrapping .tl-fields row. */
    .tl-field {
        display: inline-flex;
        gap: var(--wg-space-xs);
        min-width: 0;
    }

    .tl-label {
        color: var(--wg-text-muted);
    }

    .tl-time {
        margin-left: auto;
        font: var(--wg-text-label-sm);
        color: var(--wg-text-subtle);
    }

    .tl-fields {
        display: flex;
        flex-wrap: wrap;
        gap: var(--wg-space-md);
        font: var(--wg-text-label-sm);
    }

    .tl-recording {
        text-decoration: none;
    }

    .tl-recording:focus-visible {
        outline: var(--wg-focus-ring);
        outline-offset: var(--wg-focus-ring-offset);
        border-radius: var(--wg-radius-badge);
    }

    .action-bar {
        position: sticky;
        bottom: 0;
        display: flex;
        justify-content: flex-end;
        margin-top: var(--wg-space-xl);
        padding: var(--wg-space-md) 0;
        background: var(--wg-surface);
        border-top: var(--wg-border-width) solid var(--wg-border);
    }

    @media (max-width: 640px) {
        h1 {
            font: var(--wg-text-headline-lg-mobile);
        }
    }
</style>
