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

    function describeUser(session: UserSessionSnapshot): string {
        return (
            session.username ??
            (session.ended ? '<not logged in>' : '<logging in>')
        )
    }

    // The source port changes with every connection and only adds noise
    function clientIp(address: string): string {
        return address.replace(/:\d+$/, '').replace(/^\[(.*)\]$/, '$1')
    }

    // Live sessions list the targets still open; finished ones keep every
    // target they visited, so the history says where a session went
    function describeTargets(session: UserSessionSnapshot): string {
        const visited = session.ended
            ? session.targetSessions
            : session.targetSessions.filter(target => !target.ended)
        const names = visited.map(x => x.target?.name).filter(Boolean)
        return [...new Set(names)].join(', ')
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

    <ItemList load={loadSessions} pageSize={100}>
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
            </div>
        {/snippet}

        {#snippet item(
            session,
        )}
            {@const targets = describeTargets(session)}
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
                    <div class="who">
                        <strong>
                            {describeUser(session)}
                        </strong>
                        {#if targets}
                            on {targets}
                        {/if}
                    </div>

                    <div class="meta address" title={session.remoteAddress}>
                        {#if session.remoteAddress}
                            {clientIp(session.remoteAddress)}
                        {/if}
                    </div>

                    <div class="meta duration">
                        {#if session.ended}
                            {formatDistance(
                                new Date(session.started),
                                new Date(session.ended),
                            )}
                        {:else}
                            active
                        {/if}
                    </div>

                    <div class="meta started">
                        <RelativeDate date={session.started} />
                    </div>
                </div>
            </a>
        {/snippet}
    </ItemList>
</PermissionGate>

<style lang="scss">
    .list-group-item {
        .icon {
            display: flex;
            align-items: center;
            margin-right: 5px;
            width: 20px;
        }

        // Columns line up from row to row: status, protocol, who and where,
        // client address, duration, start time
        .main {
            display: grid;
            grid-template-columns: 25px 3.5rem minmax(0, 1fr) 8rem 9rem 10rem;
            align-items: center;
        }

        .who {
            min-width: 0;
            overflow-wrap: anywhere;
        }

        .meta {
            color: var(--bs-secondary-color);
            font-size: .8125rem;
            font-variant-numeric: tabular-nums;
        }

        // An IPv6 address is wider than its column; the tooltip has it whole
        .address {
            min-width: 0;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
        }

        .started {
            text-align: right;
        }

        @media (max-width: 767px) {
            .main {
                grid-template-columns: 25px 3.5rem minmax(0, 1fr) auto;
            }

            .address,
            .duration {
                display: none;
            }
        }
    }
</style>
