<script lang="ts">
    import { faTerminal } from '@fortawesome/free-solid-svg-icons'
    import { Input } from '@sveltestrap/sveltestrap'
    import { api, type SessionCommandSnapshot } from 'admin/lib/api'
    import { autosave } from 'common/autosave'
    import ItemList, {
        type LoadOptions,
        type PaginatedResponse,
    } from 'common/ItemList.svelte'
    import RelativeDate from 'common/RelativeDate.svelte'
    import { combineLatest, from, type Observable, switchMap } from 'rxjs'
    import Fa from 'svelte-fa'
    import { link } from 'svelte-spa-router'
    import PermissionGate from '../lib/PermissionGate.svelte'

    // Note: commands are only indexed for SSH sessions recorded after the
    // command index landed, and detection is heuristic (see the command
    // detector docs) — treat this as an audit aid, not a complete transcript.
    let [userFilter, userFilter$] = autosave('commands-list:user-filter', '')
    let [targetFilter, targetFilter$] = autosave(
        'commands-list:target-filter',
        '',
    )
    let [fromDate, fromDate$] = autosave('commands-list:from-date', '')
    let [toDate, toDate$] = autosave('commands-list:to-date', '')

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

    function loadCommands(
        opt: LoadOptions,
    ): Observable<PaginatedResponse<SessionCommandSnapshot>> {
        return combineLatest([
            userFilter$,
            targetFilter$,
            fromDate$,
            toDate$,
        ]).pipe(
            switchMap(([user, target, fromValue, toValue]) =>
                from(
                    api.searchSessionCommands({
                        q: opt.search,
                        user: user || undefined,
                        target: target || undefined,
                        from: dateInputToDate(fromValue, false),
                        to: dateInputToDate(toValue, true),
                        offset: opt.offset,
                        limit: opt.limit,
                    }),
                ),
            ),
        )
    }
</script>

<PermissionGate
    perm="sessionsView"
    message="You have no permission to view commands."
>
    <div class="page-summary-bar">
        <h1>commands</h1>
    </div>

    <ItemList load={loadCommands} pageSize={100} showSearch={true}>
        {#snippet header()}
            <div class="d-flex align-items-center mb-1 w-100 flex-wrap gap-1">
                <Input
                    class="flex-grow-1"
                    type="text"
                    placeholder="User"
                    aria-label="Filter by user"
                    bind:value={$userFilter}
                />
                <Input
                    class="flex-grow-1 ms-3"
                    type="text"
                    placeholder="Target"
                    aria-label="Filter by target"
                    bind:value={$targetFilter}
                />
                <Input
                    class="ms-3"
                    type="date"
                    label="From"
                    bind:value={$fromDate}
                />
                <Input
                    class="ms-3"
                    type="date"
                    label="To"
                    bind:value={$toDate}
                />
            </div>
        {/snippet}

        {#snippet item(command)}
            {#if command.userSessionId}
                <a
                    class="list-group-item list-group-item-action"
                    href="/status/sessions/{command.userSessionId}"
                    use:link
                >
                    <div class="main">
                        <div class="icon text-muted">
                            <Fa icon={faTerminal} fw />
                        </div>
                        <code class="command text-truncate">
                            {command.command}
                        </code>

                        <div class="meta">
                            {command.username ?? '<unknown>'}
                            {#if command.targetName}
                                on {command.targetName}
                            {/if}
                        </div>

                        <div class="meta ms-auto">
                            <RelativeDate date={command.time} />
                        </div>
                    </div>
                </a>
            {:else}
                <div class="list-group-item">
                    <div class="main">
                        <div class="icon text-muted">
                            <Fa icon={faTerminal} fw />
                        </div>
                        <code class="command text-truncate">
                            {command.command}
                        </code>
                        <div class="meta ms-auto">
                            <RelativeDate date={command.time} />
                        </div>
                    </div>
                </div>
            {/if}
        {/snippet}
    </ItemList>
</PermissionGate>

<style lang="scss">
    .list-group-item {
        .main {
            display: flex;
            align-items: center;
            gap: 0.5rem;
            min-width: 0;
        }

        .icon {
            display: flex;
            align-items: center;
            width: 20px;
        }

        .command {
            font-size: 0.85rem;
        }

        .meta {
            opacity: 0.75;
            font-size: 0.75rem;
            white-space: nowrap;
        }
    }
</style>
