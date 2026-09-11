<script lang="ts">
    import { faCircleDot as iconActive } from '@fortawesome/free-regular-svg-icons'
    import { Input } from '@sveltestrap/sveltestrap'
    import { api, type UserSessionSnapshot } from 'admin/lib/api'
    import AsyncButton from 'common/AsyncButton.svelte'
    import { autosave } from 'common/autosave'
    import GettingStarted from 'common/GettingStarted.svelte'
    import ItemList, {
        type LoadOptions,
        type PaginatedResponse,
    } from 'common/ItemList.svelte'
    import { PROTOCOL_PROPERTIES } from 'common/protocols'
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
    let [protocolFilter, protocolFilter$] = autosave(
        'sessions-list:protocol-filter',
        '',
    )
    let [fromDate, fromDate$] = autosave('sessions-list:from-date', '')
    let [toDate, toDate$] = autosave('sessions-list:to-date', '')

    const PROTOCOLS = Object.keys(PROTOCOL_PROPERTIES)

    let activeSessionCount: number | undefined = $state()

    let socket = new WebSocket(
        `wss://${location.host}/@warpgate/admin/api/sessions/changes`,
    )
    let sessionChanges$ = fromEvent(socket, 'message')
    onDestroy(() => socket.close())

    // A date input value ("YYYY-MM-DD") as an API timestamp bound; a `to` date
    // includes the whole selected day. Returned as a Date — the API client
    // serializes it to an ISO string.
    function dateInputToDate(
        value: string,
        endOfDay: boolean,
    ): Date | undefined {
        if (!value) {
            return undefined
        }
        const time = endOfDay ? '23:59:59.999' : '00:00:00.000'
        const parsed = new Date(`${value}T${time}`)
        return Number.isNaN(parsed.getTime()) ? undefined : parsed
    }

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
            protocolFilter$,
            fromDate$,
            toDate$,
            merge(timer(0, 60000), sessionChanges$),
        ]).pipe(
            switchMap(
                ([activeOnly, loggedInOnly, protocol, fromValue, toValue]) => {
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
                            protocol: protocol || undefined,
                            from: dateInputToDate(fromValue, false),
                            to: dateInputToDate(toValue, true),
                            ...opt,
                        }),
                    )
                },
            ),
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

    _reloadSessions()
    const interval = setInterval(_reloadSessions, 1000000)
    onDestroy(() => clearInterval(interval))
</script>

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

    <ItemList load={loadSessions} pageSize={100} showSearch={true}>
        {#snippet header()}
            <div class="filter-bar">
                <div class="filter-grid">
                    <Input
                        type="select"
                        aria-label="Protocol filter"
                        bind:value={$protocolFilter}
                    >
                        <option value="">All protocols</option>
                        {#each PROTOCOLS as protocol (protocol)}
                            <option value={protocol}>{protocol}</option>
                        {/each}
                    </Input>
                    <Input type="date" label="From" bind:value={$fromDate} />
                    <Input type="date" label="To" bind:value={$toDate} />
                </div>
                <div class="filter-actions">
                    <Input
                        type="switch"
                        label="Active only"
                        bind:checked={$showActiveOnly}
                    />
                    <Input
                        type="switch"
                        label="Logged in only"
                        bind:checked={$showLoggedInOnly}
                    />
                    {#if $protocolFilter || $fromDate || $toDate || $showActiveOnly || $showLoggedInOnly}
                        <button
                            type="button"
                            class="btn btn-sm btn-outline-secondary ms-auto"
                            onclick={() => {
                                $protocolFilter = ''
                                $fromDate = ''
                                $toDate = ''
                                $showActiveOnly = false
                                $showLoggedInOnly = false
                            }}
                        >
                            Clear filters
                        </button>
                    {/if}
                </div>
            </div>
        {/snippet}

        {#snippet item(session)}
            <a
                class="list-group-item list-group-item-action"
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
    </ItemList>
</PermissionGate>

<style lang="scss">
    .filter-bar {
        width: 100%;
        margin-bottom: 0.75rem;
    }

    .filter-grid {
        display: grid;
        grid-template-columns: repeat(3, 1fr);
        gap: 0.75rem;
        margin-bottom: 0.5rem;
    }

    .filter-actions {
        display: flex;
        align-items: center;
        gap: 1.25rem;
    }

    .list-group-item {
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
