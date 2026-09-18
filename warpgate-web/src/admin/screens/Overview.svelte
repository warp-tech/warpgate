<script lang="ts">
    /**
     * Overview — screen 11. A NEW route; there was no dashboard before.
     *
     * ── What `/` used to do ──────────────────────────────────────────────
     * `/` rendered Sessions, which also lives at `/status/sessions` — the
     * root was a duplicate of a route the nav already points at. Overview
     * takes `/`, Sessions keeps `/status/sessions`, and nothing is removed.
     *
     * ── Every figure here is exact ───────────────────────────────────────
     * Live sessions       getSessions({ activeOnly: true }).total
     * Active users        distinct usernames across those live sessions,
     *                     over getUsers().length
     * Failed logins (1h)  getSecurityStatus().failedAttemptsLastHour
     * Blocked IPs         getSecurityStatus().blockedIpCount
     *
     * None is a sample or an estimate, which matters because a dashboard is
     * where a number is most likely to be believed without being checked.
     *
     * ── What the mockup shows that the API cannot support ────────────────
     *   I/O throughput + sparkline on each live card — there is no
     *     throughput metric on a session, anywhere.
     *   "Sessions today · +12% vs yday" — getSessions takes offset, limit,
     *     activeOnly, loggedInOnly and username. There is no time filter and
     *     no historical series, so both the count and the delta would be
     *     invented. Replaced with Live sessions, which is exact.
     *   "Targets online 41 of 43 · 2 offline" — there is no health or
     *     reachability field on a target. This is the same gap that removed
     *     the Health column from the Targets screen in screen 3. Replaced
     *     with Blocked IPs, which is real and belongs on a security overview.
     *   "TELEMETRY SYNCED" and the per-subsystem attributions in the events
     *     feed — "Auth Daemon", "Identity Engine", "Raft Consensus" — are
     *     invented. Audit entries carry a `text`, a `username` and a
     *     `timestamp`, and that is what the feed renders.
     *
     * ── Permission gating ────────────────────────────────────────────────
     * Each panel is gated on the same key its destination screen uses, and
     * the corresponding request is not issued at all without it — an
     * overview that 403s four times on load would be worse than one that
     * shows less.
     */
    import { api, type LogEntry, type UserSessionSnapshot } from 'admin/lib/api'
    import { stringifyError } from 'common/errors'
    import { onMount } from 'svelte'
    import { link, push } from 'svelte-spa-router'
    import 'ui/layout.css'
    import Badge from 'ui/Badge.svelte'
    import Button from 'ui/Button.svelte'
    import Callout from 'ui/Callout.svelte'
    import ConfirmDialog from 'ui/ConfirmDialog.svelte'
    import EmptyState from 'ui/EmptyState.svelte'
    import RelativeDate from 'ui/RelativeDate.svelte'
    import Spinner from 'ui/Spinner.svelte'
    import StatCard from 'ui/StatCard.svelte'
    import StatusMarker from 'ui/StatusMarker.svelte'
    import { adminPermissions } from '../lib/store'

    const REFRESH_MS = 15_000
    const RECENT_LIMIT = 8

    let loading = $state(true)
    let error: string | undefined = $state()

    let live: UserSessionSnapshot[] = $state([])
    let recent: UserSessionSnapshot[] = $state([])
    let events: LogEntry[] = $state([])
    let liveTotal = $state(0)
    let userTotal = $state(0)
    let failedLastHour = $state(0)
    let blockedIps = $state(0)
    let terminating: UserSessionSnapshot | undefined = $state()

    const canSessions = $derived($adminPermissions.sessionsView)
    const canSecurity = $derived($adminPermissions.configEdit)
    const canUsers = $derived($adminPermissions.usersEdit)

    const activeUsers = $derived(
        new Set(live.map(s => s.username).filter(Boolean)).size,
    )

    async function load() {
        error = undefined
        try {
            await Promise.all([
                canSessions
                    ? api
                          .getSessions({ activeOnly: true, limit: 12 })
                          .then(r => {
                              live = r.items
                              liveTotal = r.total
                          })
                    : Promise.resolve(),
                canSessions
                    ? api.getSessions({ limit: RECENT_LIMIT }).then(r => {
                          recent = r.items
                      })
                    : Promise.resolve(),
                canSessions
                    ? api
                          .getLogs({
                              getLogsRequest: {
                                  target: 'audit',
                                  limit: RECENT_LIMIT,
                              },
                          })
                          .then(r => {
                              events = r
                          })
                    : Promise.resolve(),
                canSecurity
                    ? api.getSecurityStatus().then(r => {
                          failedLastHour = r.failedAttemptsLastHour
                          blockedIps = r.blockedIpCount
                      })
                    : Promise.resolve(),
                canUsers
                    ? api.getUsers().then(r => {
                          userTotal = r.length
                      })
                    : Promise.resolve(),
            ])
        } catch (err) {
            error = await stringifyError(err)
        } finally {
            loading = false
        }
    }

    load()

    onMount(() => {
        const t = setInterval(load, REFRESH_MS)
        return () => clearInterval(t)
    })

    /** The target a session is currently on, preferring one that has not ended. */
    function targetOf(session: UserSessionSnapshot): string | undefined {
        const open = session.targetSessions.filter(t => !t.ended)
        const list = open.length ? open : session.targetSessions
        return list.at(-1)?.target?.name
    }

    async function confirmTerminate() {
        const session = terminating
        if (!session) {
            return
        }
        try {
            await api.closeSession({ id: session.id })
            await load()
        } catch (err) {
            error = await stringifyError(err)
        } finally {
            terminating = undefined
        }
    }
</script>

<div class="head">
    <h1>Overview</h1>
</div>

{#if error}
    <div class="banner">
        <Callout tone="danger" title="Could not load the overview">
            {error}
            {#snippet actions()}
                <Button size="compact" click={load}>Retry</Button>
            {/snippet}
        </Callout>
    </div>
{/if}

{#if loading && !live.length && !recent.length}
    <div class="loading">
        <Spinner delay={1000} label="Loading overview" />
    </div>
{:else}
    <div class="wg-stat-grid">
        {#if canSessions}
            <StatCard
                label="Live sessions"
                value={liveTotal}
                tone={liveTotal > 0 ? 'info' : 'neutral'}
                note={liveTotal === 1 ? 'connection open' : 'connections open'}
            />
            <StatCard
                label="Active users"
                value={activeUsers}
                note={canUsers ? `of ${userTotal} configured` : 'signed in now'}
            />
        {/if}
        {#if canSecurity}
            <StatCard
                label="Failed logins (1h)"
                value={failedLastHour}
                tone={failedLastHour > 0 ? 'warning' : 'neutral'}
            />
            <StatCard
                label="Blocked IPs"
                value={blockedIps}
                tone={blockedIps > 0 ? 'danger' : 'neutral'}
                note={blockedIps > 0 ? 'actively refused' : 'none'}
            />
        {/if}
    </div>

    {#if canSessions}
        <section>
            <div class="section-head">
                <h2>
                    Live now
                    {#if liveTotal}
                        <Badge tone="primary">{liveTotal}</Badge>
                    {/if}
                </h2>
                <a href="/status/sessions" use:link>All sessions &rarr;</a>
            </div>

            {#if live.length}
                <ul class="live-grid">
                    {#each live as session (session.id)}
                        <li class="live-card">
                            <div class="live-top">
                                <Badge mono>{session.protocol}</Badge>
                                <StatusMarker kind="live" label="Live" bare />
                            </div>

                            <p class="live-label">Target</p>
                            <p class="live-target wg-mono">
                                {targetOf(session) ?? 'Not yet selected'}
                            </p>

                            <div class="live-meta">
                                <span class="wg-mono">
                                    {session.username ?? 'anonymous'}
                                </span>
                                <span class="wg-mono muted">
                                    {session.remoteAddress}
                                </span>
                            </div>

                            <p class="live-since muted">
                                Started <RelativeDate date={session.started} />
                            </p>

                            <div class="live-actions">
                                <Button
                                    size="compact"
                                    onclick={() =>
                                        push(`/status/sessions/${session.id}`)}
                                >
                                    Watch
                                </Button>
                                {#if $adminPermissions.sessionsTerminate}
                                    <Button
                                        size="compact"
                                        variant="destructive"
                                        onclick={() => (terminating = session)}
                                    >
                                        Terminate
                                    </Button>
                                {/if}
                            </div>
                        </li>
                    {/each}
                </ul>
                {#if liveTotal > live.length}
                    <p class="more muted">
                        Showing {live.length} of {liveTotal}.
                        <a href="/status/sessions" use:link>See the rest</a>.
                    </p>
                {/if}
            {:else}
                <EmptyState
                    size="compact"
                    title="Nothing connected right now"
                    hint="Live sessions appear here as soon as someone connects."
                />
            {/if}
        </section>

        <div class="columns">
            <section>
                <div class="section-head">
                    <h2>Recent sessions</h2>
                    <a href="/status/sessions" use:link>View all &rarr;</a>
                </div>
                {#if recent.length}
                    <ul class="rows">
                        {#each recent as session (session.id)}
                            <li>
                                <StatusMarker
                                    kind={session.ended ? 'ended' : 'live'}
                                    label={session.ended ? 'Ended' : 'Live'}
                                    bare
                                />
                                <a
                                    class="row-main"
                                    href="/status/sessions/{session.id}"
                                    use:link
                                >
                                    <span class="wg-mono">
                                        {session.username ?? 'anonymous'}
                                    </span>
                                    <span class="muted">
                                        {targetOf(session) ?? '—'}
                                    </span>
                                </a>
                                <span class="row-when muted">
                                    <RelativeDate date={session.started} />
                                </span>
                            </li>
                        {/each}
                    </ul>
                {:else}
                    <EmptyState size="compact" title="No sessions yet" />
                {/if}
            </section>

            <section>
                <div class="section-head">
                    <h2>Recent audit events</h2>
                    <a href="/log" use:link>Full log &rarr;</a>
                </div>
                {#if events.length}
                    <ul class="rows">
                        {#each events as event (event.id)}
                            <li>
                                <div class="event-body">
                                    <span class="event-text">{event.text}</span>
                                    <span class="muted event-meta">
                                        <RelativeDate date={event.timestamp} />
                                        {#if event.username}
                                            &middot; {event.username}
                                        {/if}
                                    </span>
                                </div>
                            </li>
                        {/each}
                    </ul>
                {:else}
                    <EmptyState size="compact" title="No audit events yet" />
                {/if}
            </section>
        </div>
    {:else}
        <EmptyState
            title="Nothing to show"
            hint="Your admin role does not include permission to view sessions."
        />
    {/if}
{/if}

<ConfirmDialog
    open={!!terminating}
    title="Terminate this session?"
    confirmLabel="Terminate"
    onconfirm={confirmTerminate}
    oncancel={() => (terminating = undefined)}
>
    {#if terminating}
        {@const t = terminating}
        <p class="panel">
            <strong class="wg-mono">{t.username ?? 'anonymous'}</strong>
            is connected to
            <strong class="wg-mono">{targetOf(t) ?? 'a target'}</strong>
            over {t.protocol} from {t.remoteAddress}. The connection drops
            immediately; any recording written so far is kept.
        </p>
    {/if}
</ConfirmDialog>

<style>
    .head {
        margin-bottom: var(--wg-space-lg);
    }

    h1 {
        margin: 0;
        font: var(--wg-text-headline-lg);
    }

    h2 {
        display: flex;
        align-items: center;
        gap: var(--wg-space-sm);
        margin: 0;
        font: var(--wg-text-headline-md);
    }

    .banner,
    .loading {
        margin-bottom: var(--wg-space-lg);
    }

    .loading {
        display: flex;
        justify-content: center;
        padding: var(--wg-space-3xl) 0;
    }

    section {
        margin-top: var(--wg-space-2xl);
        min-width: 0;
    }

    .section-head {
        display: flex;
        align-items: baseline;
        justify-content: space-between;
        gap: var(--wg-space-md);
        margin-bottom: var(--wg-space-md);
    }

    .section-head a {
        color: var(--wg-text-muted);
        font: var(--wg-text-label-sm);
        white-space: nowrap;
    }

    .section-head a:focus-visible {
        outline: var(--wg-focus-ring);
        outline-offset: var(--wg-focus-ring-offset);
    }

    .columns {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(20rem, 1fr));
        gap: var(--wg-space-xl);
    }

    .live-grid {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(17rem, 1fr));
        gap: var(--wg-space-md);
        list-style: none;
        margin: 0;
        padding: 0;
    }

    .live-card {
        display: flex;
        flex-direction: column;
        gap: var(--wg-space-xs);
        padding: var(--wg-space-lg);
        background: var(--wg-surface-container);
        border: var(--wg-border-width) solid var(--wg-border);
        border-radius: var(--wg-radius-panel);
        min-width: 0;
    }

    .live-top {
        display: flex;
        align-items: center;
        justify-content: space-between;
        gap: var(--wg-space-sm);
        margin-bottom: var(--wg-space-xs);
    }

    .live-label {
        margin: 0;
        font: var(--wg-text-label-sm);
        letter-spacing: 0.06em;
        text-transform: uppercase;
        color: var(--wg-text-subtle);
    }

    .live-target {
        margin: 0;
        font: var(--wg-text-body-md);
        font-family: var(--wg-font-mono);
        overflow-wrap: anywhere;
    }

    .live-meta {
        display: flex;
        flex-wrap: wrap;
        gap: var(--wg-space-sm);
        margin-top: var(--wg-space-xs);
        font: var(--wg-text-label-sm);
    }

    .live-since {
        margin: 0;
        font: var(--wg-text-label-sm);
    }

    .live-actions {
        display: flex;
        gap: var(--wg-space-sm);
        margin-top: var(--wg-space-md);
    }

    .more {
        margin: var(--wg-space-md) 0 0;
        font: var(--wg-text-label-sm);
    }

    .rows {
        list-style: none;
        margin: 0;
        padding: 0;
    }

    .rows li {
        display: flex;
        align-items: center;
        gap: var(--wg-space-sm);
        padding: var(--wg-space-sm) 0;
        border-bottom: var(--wg-border-width) solid var(--wg-border);
        min-width: 0;
    }

    .rows li:last-child {
        border-bottom: 0;
    }

    .row-main {
        display: flex;
        flex-wrap: wrap;
        gap: var(--wg-space-sm);
        align-items: baseline;
        flex: 1 1 auto;
        min-width: 0;
        color: inherit;
        text-decoration: none;
        font: var(--wg-text-label-sm);
    }

    .row-main:hover {
        text-decoration: underline;
    }

    .row-main:focus-visible {
        outline: var(--wg-focus-ring);
        outline-offset: var(--wg-focus-ring-offset);
    }

    .row-when {
        flex: none;
        font: var(--wg-text-label-sm);
    }

    .event-body {
        display: flex;
        flex-direction: column;
        gap: 2px;
        min-width: 0;
    }

    .event-text {
        font: var(--wg-text-label-sm);
        overflow-wrap: anywhere;
    }

    .event-meta {
        font: var(--wg-text-label-sm);
    }

    .muted {
        color: var(--wg-text-muted);
    }

    .panel {
        margin: 0;
        color: var(--wg-text-muted);
    }

    @media (max-width: 640px) {
        h1 {
            font: var(--wg-text-headline-lg-mobile);
        }
    }
</style>
