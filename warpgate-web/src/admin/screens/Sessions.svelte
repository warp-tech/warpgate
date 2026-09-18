<script lang="ts">
    /**
     * Sessions list — screen 1.
     *
     * Behaviour preserved verbatim from admin/status/Sessions.svelte:
     *   - the WebSocket to /admin/api/sessions/changes drives live refresh,
     *     merged with a 60s timer so a dropped socket degrades to polling
     *   - activeOnly / loggedInOnly persist through common/autosave
     *   - the active-session count is a separate limit:1 query, so the badge
     *     is right regardless of which page of results is showing
     *   - "Close all" stays gated on sessionsTerminate
     *   - GettingStarted still renders while setupState is set
     *
     * Columns follow warpgate_sessions_list. "Duration" is computed from
     * started/ended, which the API does provide; nothing here is derived from
     * data that does not exist.
     */
    import { api, type UserSessionSnapshot } from 'admin/lib/api'
    import { autosave } from 'common/autosave'
    import GettingStarted from 'common/GettingStarted.svelte'
    import type { LoadOptions, PaginatedResponse } from 'common/ItemList.svelte'
    import { formatDistanceStrict } from 'date-fns'
    import { serverInfo } from 'gateway/lib/store'
    import {
        combineLatest,
        from,
        fromEvent,
        merge,
        type Observable,
        switchMap,
        timer,
    } from 'rxjs'
    import { onDestroy } from 'svelte'
    import { push } from 'svelte-spa-router'
    import Button from 'ui/Button.svelte'
    import ConfirmDialog from 'ui/ConfirmDialog.svelte'
    import EmptyState from 'ui/EmptyState.svelte'
    import RelativeDate from 'ui/RelativeDate.svelte'
    import StatusMarker from 'ui/StatusMarker.svelte'
    import Table, { type Column } from 'ui/Table.svelte'
    import Toggle from 'ui/Toggle.svelte'
    import { toast } from 'ui/toasts.svelte'
    import PermissionGate from '../lib/PermissionGate.svelte'
    import { adminPermissions } from '../lib/store'

    let [showActiveOnly, showActiveOnly$] = autosave(
        'sessions-list:show-active-only',
        false,
    )
    let [showLoggedInOnly, showLoggedInOnly$] = autosave(
        'sessions-list:show-logged-in-only',
        true,
    )

    let activeSessionCount: number | undefined = $state()
    let closeAllOpen = $state(false)

    const socket = new WebSocket(
        `wss://${location.host}/@warpgate/admin/api/sessions/changes`,
    )
    const sessionChanges$ = fromEvent(socket, 'message')
    onDestroy(() => socket.close())

    function loadSessions(
        opt: LoadOptions,
    ): Observable<PaginatedResponse<UserSessionSnapshot>> {
        if (!$adminPermissions.sessionsView) {
            return from(Promise.resolve({ items: [], offset: 0, total: 0 }))
        }
        return combineLatest([
            showActiveOnly$,
            showLoggedInOnly$,
            merge(timer(0, 60000), sessionChanges$),
        ]).pipe(
            switchMap(([activeOnly, loggedInOnly]) => {
                api.getSessions({ activeOnly: true, limit: 1 }).then(
                    response => {
                        activeSessionCount = response.total
                    },
                )
                return from(
                    api.getSessions({ activeOnly, loggedInOnly, ...opt }),
                )
            }),
        )
    }

    async function reloadCount(): Promise<void> {
        activeSessionCount = (await api.getSessions({ activeOnly: true })).total
    }

    async function closeAllSessions() {
        await api.closeAllSessions()
        toast.success('All sessions closed')
        await reloadCount()
    }

    const columns: Column[] = [
        { key: 'status', label: 'Status', width: '10rem' },
        { key: 'user', label: 'User', sortable: true },
        { key: 'target', label: 'Target' },
        { key: 'protocol', label: 'Protocol', width: '7rem' },
        { key: 'source', label: 'Source IP', width: '11rem' },
        { key: 'started', label: 'Started', width: '11rem' },
        { key: 'duration', label: 'Duration', width: '8rem', align: 'end' },
    ]

    function userOf(session: UserSessionSnapshot): string {
        return (
            session.username ??
            (session.ended ? 'Not logged in' : 'Logging in…')
        )
    }

    function targetsOf(session: UserSessionSnapshot): string {
        const active = session.targetSessions.filter(t => !t.ended)
        const list = active.length ? active : session.targetSessions
        return (
            list
                .map(t => t.target?.name)
                .filter(Boolean)
                .join(', ') || '—'
        )
    }

    function durationOf(session: UserSessionSnapshot): string {
        const end = session.ended ? new Date(session.ended) : new Date()
        return formatDistanceStrict(new Date(session.started), end)
    }

    reloadCount()
    // Matches the existing screen's slow safety-net refresh; the socket and the
    // 60s timer above are what actually keep this current.
    const interval = setInterval(reloadCount, 1000000)
    onDestroy(() => clearInterval(interval))
</script>

{#if $serverInfo?.setupState}
    <GettingStarted setupState={$serverInfo.setupState} />
{/if}

<PermissionGate
    perm="sessionsView"
    message="You have no permission to view sessions."
>
    <div class="head">
        <div class="head-title">
            <h1>Sessions</h1>
            {#if activeSessionCount !== undefined}
                <p class="head-count">
                    <span class="count">{activeSessionCount}</span>
                    active
                </p>
            {/if}
        </div>

        {#if $adminPermissions.sessionsTerminate && activeSessionCount}
            <Button
                variant="destructive"
                size="compact"
                onclick={() => (closeAllOpen = true)}
            >
                Close all
            </Button>
        {/if}
    </div>

    <Table
        caption="Sessions"
        {columns}
        load={loadSessions}
        rowKey={s => s.id}
        pageSize={100}
        onrowactivate={s => push(`/status/sessions/${s.id}`)}
    >
        {#snippet toolbar()}
            <Toggle
                label="Active only"
                size="compact"
                bind:checked={$showActiveOnly}
            />
            <Toggle
                label="Logged in only"
                size="compact"
                bind:checked={$showLoggedInOnly}
            />
        {/snippet}

        {#snippet row(session)}
            <td>
                {#if session.ended}
                    <StatusMarker kind="ended" bare label="Ended" />
                {:else}
                    <StatusMarker kind="live" bare />
                {/if}
            </td>
            <td class="wg-mono">{userOf(session)}</td>
            <td class="wg-mono">{targetsOf(session)}</td>
            <td>{session.protocol}</td>
            <td class="wg-mono">{session.remoteAddress ?? '—'}</td>
            <td><RelativeDate date={session.started} /></td>
            <td class="num">{durationOf(session)}</td>
        {/snippet}

        {#snippet empty()}
            <EmptyState
                size="compact"
                title="No sessions"
                hint="Connections appear here as soon as a user opens one."
            />
        {/snippet}
    </Table>
</PermissionGate>

<ConfirmDialog
    bind:open={closeAllOpen}
    title="Close all sessions?"
    confirmLabel="Close all sessions"
    onconfirm={closeAllSessions}
>
    <p>
        This disconnects every active session immediately. Recordings already
        written are kept.
    </p>
</ConfirmDialog>

<style>
    .head {
        display: flex;
        align-items: flex-start;
        justify-content: space-between;
        gap: var(--wg-space-lg);
        margin-bottom: var(--wg-space-lg);
    }

    .head-title {
        display: flex;
        align-items: baseline;
        gap: var(--wg-space-md);
    }

    h1 {
        margin: 0;
        font: var(--wg-text-headline-lg);
    }

    .head-count {
        margin: 0;
        font: var(--wg-text-body-md);
        color: var(--wg-text-muted);
    }

    .count {
        font-variant-numeric: tabular-nums;
        color: var(--wg-text);
    }

    .num {
        text-align: right;
    }

    @media (max-width: 640px) {
        h1 {
            font: var(--wg-text-headline-lg-mobile);
        }
    }
</style>
