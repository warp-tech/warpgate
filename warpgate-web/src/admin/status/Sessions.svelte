<script lang="ts">
    import { faCircleDot as iconActive } from '@fortawesome/free-regular-svg-icons'
    import { faChevronRight, faList } from '@fortawesome/free-solid-svg-icons'
    import { Input } from '@sveltestrap/sveltestrap'
    import { api, type UserSessionSnapshot } from 'admin/lib/api'
    import AsyncButton from 'common/AsyncButton.svelte'
    import { autosave } from 'common/autosave'
    import GettingStarted from 'common/GettingStarted.svelte'
    import ItemList, {
        type LoadOptions,
        type PaginatedResponse,
    } from 'common/ItemList.svelte'
    import RelativeDate from 'common/RelativeDate.svelte'
    import { formatDistance } from 'date-fns'
    import { serverInfo } from 'gateway/lib/store'
    import {
        combineLatest,
        from,
        fromEvent,
        map,
        merge,
        type Observable,
        switchMap,
        timer,
    } from 'rxjs'
    import { onDestroy } from 'svelte'
    import { SvelteSet } from 'svelte/reactivity'
    import Fa from 'svelte-fa'
    import { link } from 'svelte-spa-router'
    import PermissionGate from '../lib/PermissionGate.svelte'
    import { adminPermissions } from '../lib/store'
    import {
        groupSessions,
        newestSession,
        oldestSession,
        type SessionGroup,
    } from './sessionGroups'

    let [showActiveOnly, showActiveOnly$] = autosave(
        'sessions-list:show-active-only',
        false,
    )
    let [showLoggedInOnly, showLoggedInOnly$] = autosave(
        'sessions-list:show-logged-in-only',
        true,
    )
    let [groupSimilar, groupSimilar$] = autosave(
        'sessions-list:group-similar',
        false,
    )
    let [groupWindowMinutes, groupWindowMinutes$] = autosave(
        'sessions-list:group-window-minutes',
        5,
    )

    /** Grouping happens within a page, so pages are larger while it's on */
    const PAGE_SIZE = 100
    const GROUPED_PAGE_SIZE = 500

    const expandedGroups = new SvelteSet<string>()

    let activeSessionCount: number | undefined = $state()

    let socket = new WebSocket(
        `wss://${location.host}/@warpgate/admin/api/sessions/changes`,
    )
    let sessionChanges$ = fromEvent(socket, 'message')
    onDestroy(() => socket.close())

    function loadSessions(
        opt: LoadOptions,
    ): Observable<PaginatedResponse<SessionGroup>> {
        if (!$adminPermissions.sessionsView) {
            // return empty observable
            return from(Promise.resolve({ items: [], offset: 0, total: 0 }))
        }
        return combineLatest([
            showActiveOnly$,
            showLoggedInOnly$,
            groupSimilar$,
            groupWindowMinutes$,
            merge(timer(0, 60000), sessionChanges$),
        ]).pipe(
            switchMap(([activeOnly, loggedInOnly, group, windowMinutes]) => {
                api.getSessions({
                    activeOnly: true,
                    limit: 1,
                }).then(response => {
                    activeSessionCount = response.total
                })
                return from(
                    api.getSessions({
                        activeOnly,
                        loggedInOnly,
                        ...opt,
                    }),
                ).pipe(
                    map(response => ({
                        ...response,
                        items: group
                            ? groupSessions(
                                  response.items,
                                  Math.max(0, windowMinutes || 0) * 60000,
                              )
                            : response.items.map(session => ({
                                  key: session.id,
                                  sessions: [session],
                              })),
                    })),
                )
            }),
        )
    }

    async function _reloadSessions(): Promise<void> {
        activeSessionCount = (await api.getSessions({ activeOnly: true })).total
    }

    async function closeAllSesssions() {
        await api.closeAllSessions()
    }

    function describeSession(session: UserSessionSnapshot): string {
        let user =
            session.username ??
            (session.ended ? '<not logged in>' : '<logging in>')
        let activeTargets = session.targetSessions.filter(
            target => !target.ended,
        )
        if (!activeTargets.length) {
            return user
        }
        return `${user} on ${activeTargets.map(x => x.target?.name).join(', ')}`
    }

    function describeGroup(group: SessionGroup): string {
        const session = newestSession(group)
        const targets = [
            ...new Set(session.targetSessions.map(x => x.target?.name)),
        ]
        return `${session.username} on ${targets.join(', ')}`
    }

    function toggleGroup(group: SessionGroup) {
        if (expandedGroups.has(group.key)) {
            expandedGroups.delete(group.key)
        } else {
            expandedGroups.add(group.key)
        }
    }

    _reloadSessions()
    const interval = setInterval(_reloadSessions, 1000000)
    onDestroy(() => clearInterval(interval))
</script>

{#if $serverInfo?.setupState}
    <GettingStarted setupState={$serverInfo?.setupState} />
{/if}

{#snippet sessionRow(session: UserSessionSnapshot, grouped: boolean)}
    <a
        class="list-group-item list-group-item-action"
        class:grouped={grouped}
        href="/status/sessions/{session.id}"
        use:link
    >
        <div class="main">
            <div class="icon" class:text-success={!session.ended}>
                {#if !session.ended}
                    <Fa icon={iconActive} fw />
                {/if}
            </div>
            <div class="protocol text-muted me-2">
                {session.protocol}
            </div>
            <strong>
                {describeSession(session)}
            </strong>

            <div class="meta">
                {#if session.ended}
                    {formatDistance(new Date(session.started), new Date(session.ended))}
                {/if}
            </div>

            <div class="meta ms-auto">
                <RelativeDate date={session.started} />
            </div>
        </div>
    </a>
{/snippet}

<PermissionGate
    perm="sessionsView"
    message="You have no permission to view sessions."
>
    {#if activeSessionCount !== undefined}
        <div class="page-summary-bar">
            {#if activeSessionCount}
                <h1>
                    <span>active sessions:</span>
                    <span class="counter">{activeSessionCount}</span>
                </h1>
                <div class="ms-auto">
                    {#if $adminPermissions.sessionsTerminate}
                        <AsyncButton color="warning" click={closeAllSesssions}>
                            Close all
                        </AsyncButton>
                    {/if}
                </div>
            {:else}
                <h1>no active sessions</h1>
            {/if}
        </div>
    {/if}

    {#key $groupSimilar}
        <ItemList
            load={loadSessions}
            pageSize={$groupSimilar ? GROUPED_PAGE_SIZE : PAGE_SIZE}
        >
            {#snippet header()}
                <div class="d-flex align-items-center mb-1 w-100">
                    <div class="ms-auto"></div>
                    <Input
                        class="ms-3"
                        type="switch"
                        label="Active only"
                        bind:checked={$showActiveOnly}
                    />
                    <Input
                        class="ms-3"
                        type="switch"
                        label="Logged in only"
                        bind:checked={$showLoggedInOnly}
                    />
                    <Input
                        class="ms-3"
                        type="switch"
                        label="Group by user & target"
                        bind:checked={$groupSimilar}
                    />
                    {#if $groupSimilar}
                        <div
                            class="input-group input-group-sm ms-2 group-window"
                        >
                            <span class="input-group-text">within</span>
                            <input
                                class="form-control"
                                type="number"
                                min="0"
                                aria-label="Grouping window in minutes"
                                bind:value={$groupWindowMinutes}
                            />
                            <span class="input-group-text">min</span>
                        </div>
                    {/if}
                </div>
            {/snippet}

            {#snippet item(group: SessionGroup)}
                {#if group.sessions.length === 1}
                    {@render sessionRow(newestSession(group), false)}
                {:else}
                    {@const newest = newestSession(group)}
                    {@const oldest = oldestSession(group)}
                    {@const expanded = expandedGroups.has(group.key)}
                    <div
                        class="list-group-item list-group-item-action session-group"
                    >
                        <button
                            type="button"
                            class="main"
                            aria-expanded={expanded}
                            onclick={() => toggleGroup(group)}
                        >
                            <div
                                class="icon"
                                class:text-success={group.sessions.some(
                                    x => !x.ended,
                                )}
                            >
                                <Fa
                                    icon={faChevronRight}
                                    fw
                                    rotate={expanded ? 90 : 0}
                                />
                            </div>
                            <div class="protocol text-muted me-2">
                                {newest.protocol}
                            </div>
                            <strong>{describeGroup(group)}</strong>
                            <span class="badge bg-secondary ms-2">
                                {group.sessions.length} sessions
                            </span>

                            <div class="meta">
                                over {formatDistance(
                                    new Date(oldest.started),
                                    new Date(newest.ended ?? new Date()),
                                )}
                            </div>

                            <div class="meta ms-auto">
                                <RelativeDate date={newest.started} />
                            </div>
                        </button>
                        <a
                            class="btn btn-sm btn-link ms-2"
                            href="/log/sessions/{group.sessions.map(x => x.id).join(',')}"
                            title="Log entries of these sessions"
                            use:link
                        >
                            <Fa icon={faList} fw />
                            Log
                        </a>
                    </div>
                    {#if expanded}
                        {#each group.sessions as session (session.id)}
                            {@render sessionRow(session, true)}
                        {/each}
                    {/if}
                {/if}
            {/snippet}
        </ItemList>
    {/key}
</PermissionGate>

<style lang="scss">
    .group-window {
        width: 10rem;
    }

    .list-group-item {
        &.grouped {
            padding-left: 2.5rem;
        }

        &.session-group {
            display: flex;
            align-items: center;

            .main {
                flex: 1 1 auto;
                min-width: 0;
                padding: 0;
                border: none;
                background: none;
                color: inherit;
                text-align: start;
            }
        }

        .icon {
            display: flex;
            align-items: center;
            margin-right: 5px;
            width: 20px;
        }

        .main {
            display: flex;
            align-items: center;
        }

        .protocol {
            min-width: 3.5rem;
        }

        .meta {
            opacity: .75;
            margin-left: 25px;
            font-size: .75rem;
        }
    }
</style>
