<script lang="ts">
    import { faCircleDot as iconActive } from '@fortawesome/free-regular-svg-icons'
    import { Input } from '@sveltestrap/sveltestrap'
    import { api, type UserSessionSnapshot } from 'admin/lib/api'
    import AsyncButton from 'common/AsyncButton.svelte'
    import { autosave } from 'common/autosave'
    import GettingStarted from 'common/GettingStarted.svelte'
    import ItemList, {
        type Column,
        type LoadOptions,
        type PaginatedResponse,
    } from 'common/ItemList.svelte'
    import ListOverflowMenu from 'common/ListOverflowMenu.svelte'
    import RelativeDate from 'common/RelativeDate.svelte'
    import { formatDistance } from 'date-fns'
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
    import Fa from 'svelte-fa'
    import { link } from 'svelte-spa-router'
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

    let socket = new WebSocket(
        `wss://${location.host}/@warpgate/admin/api/sessions/changes`,
    )
    let sessionChanges$ = fromEvent(socket, 'message')
    onDestroy(() => socket.close())

    function loadSessions(
        opt: LoadOptions,
    ): Observable<PaginatedResponse<UserSessionSnapshot>> {
        if (!$adminPermissions.sessionsView) {
            // return empty observable
            return from(Promise.resolve({ items: [], offset: 0, total: 0 }))
        }
        return combineLatest([
            showActiveOnly$,
            showLoggedInOnly$,
            merge(timer(0, 60000), sessionChanges$),
        ]).pipe(
            switchMap(([activeOnly, loggedInOnly]) => {
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

    function describeTargets(session: UserSessionSnapshot): string {
        let eligible = session.ended
            ? session.targetSessions
            : session.targetSessions.filter(target => !target.ended)
        return eligible.map(x => x.target?.name).join(', ')
    }

    _reloadSessions()
    const interval = setInterval(_reloadSessions, 1000000)
    onDestroy(() => clearInterval(interval))

    const columns: Column<UserSessionSnapshot>[] = [
        { id: 'icon', cell: iconCell },
        {
            id: 'protocol',
            label: 'Protocol',
            cell: protocolCell,
            class: 'text-muted small text-end',
        },
        { id: 'username', cell: usernameCell },
        { id: 'targets', label: 'Targets', cell: targetsCell },
        {
            id: 'sourceAddress',
            label: 'Source IP',
            cell: sourceAddressCell,
            hiddenByDefault: true,
            class: 'ms-3',
        },
        {
            id: 'duration',
            label: 'Duration',
            cell: durationCell,
            class: 'ms-3',
        },
        {
            id: 'startTime',
            label: 'Start time',
            cell: startTimeCell,
            grow: true,
            class: 'text-end',
        },
    ]
</script>

{#snippet iconCell(session: UserSessionSnapshot)}
    <div class="icon" class:text-success={!session.ended}>
        {#if !session.ended}
            <Fa icon={iconActive} fw />
        {/if}
    </div>
{/snippet}
{#snippet protocolCell(session: UserSessionSnapshot)}
    <div class="text-muted me-2">
        {session.protocol}
    </div>
{/snippet}
{#snippet sourceAddressCell(session: UserSessionSnapshot)}
    <div class="meta">
        {session.remoteAddress.replace(/:\d+$/, '').replace(/^\[(.*)\]$/, '$1')}
    </div>
{/snippet}
{#snippet usernameCell(session: UserSessionSnapshot)}
    <strong>
        {session.username ??
            (session.ended ? '<not logged in>' : '<logging in>')}
    </strong>
{/snippet}
{#snippet targetsCell(session: UserSessionSnapshot)}
    {describeTargets(session)}
{/snippet}
{#snippet durationCell(session: UserSessionSnapshot)}
    {#if session.ended}
        <div class="meta ms-auto">
            {formatDistance(new Date(session.started), new Date(session.ended))}
        </div>
    {/if}
{/snippet}
{#snippet startTimeCell(session: UserSessionSnapshot)}
    <div class="meta ms-auto">
        <RelativeDate date={session.started} />
    </div>
{/snippet}

{#if $serverInfo?.setupState}
    <GettingStarted setupState={$serverInfo?.setupState} />
{/if}

<PermissionGate
    perm="sessionsView"
    message="You have no permission to view sessions."
>
    {#if activeSessionCount !== undefined}
        <div class="page-summary-bar">
            {#if activeSessionCount}
                <h1>
                    <span>active sessions</span>
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

    <ItemList
        load={loadSessions}
        pageSize={100}
        {columns}
        storageKey="admin-sessions"
    >
        {#snippet header(_items, groupControls, columnControls)}
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
                <ListOverflowMenu {groupControls} {columnControls} />
            </div>
        {/snippet}

        {#snippet item(session, cells)}
            <a
                class="list-group-item list-group-item-action"
                href="/status/sessions/{session.id}"
                use:link
            >
                {@render cells(session)}
            </a>
        {/snippet}
    </ItemList>
</PermissionGate>

<style lang="scss">
    .list-group-item {
        .meta {
            opacity: .75;
            margin-left: 25px;
            font-size: .75rem;
        }
    }
</style>
