<script lang="ts" module>
    export interface LoadOptions {
        search?: string
        offset: number
        limit?: number
    }

    export interface PaginatedResponse<T> {
        items: T[]
        offset: number
        total: number
    }

    export interface GroupState {
        collapsed: boolean
        // False while a search is active, where every group is force-expanded:
        // a toggle would rewrite the persisted state without visible effect.
        collapsible: boolean
        toggle: () => void
    }

    export interface GroupControls {
        // False when there is nothing to collapse: either the list renders no
        // group headers, or a search is active, where the loaded items are only
        // a subset and "collapse all" would silently skip the rest.
        available: boolean
        collapseAll: () => void
        expandAll: () => void
    }
</script>

<script lang="ts" generics="T, G = unknown, GK = unknown">
    import { Input } from '@sveltestrap/sveltestrap'
    import {
        combineLatest,
        debounceTime,
        distinctUntilChanged,
        map,
        type Observable,
        Subject,
        share,
        switchMap,
        tap,
    } from 'rxjs'
    import { onDestroy, onMount, type Snippet } from 'svelte'
    import { observe } from 'svelte-observable'
    import DelayedSpinner from './DelayedSpinner.svelte'
    import EmptyState from './EmptyState.svelte'
    import Pagination from './Pagination.svelte'

    interface Props {
        page?: number
        pageSize?: number | undefined
        load: (_: LoadOptions) => Observable<PaginatedResponse<T>>
        groupObject?: (_: T) => G
        groupKey?: (_: G) => GK
        showSearch?: boolean
        header?: Snippet<[T[] | null, GroupControls]>
        item?: Snippet<[T]>
        footer?: Snippet<[T[]]>
        empty?: Snippet<[]>
        groupHeader?: Snippet<[G, GroupState]>
        collapsedGroups?: GK[]
    }

    let {
        page = $bindable(0),
        pageSize = undefined,
        load,
        showSearch = false,
        groupObject,
        groupKey,
        header,
        item,
        footer,
        empty,
        groupHeader,
        collapsedGroups = $bindable([]),
    }: Props = $props()

    let filter = $state('')
    let loaded = $state(false)
    let hasItems = $state(false)

    const page$ = new Subject<number>()
    const filter$ = new Subject<string>()

    const responses = combineLatest([
        page$,
        filter$.pipe(
            tap(() => {
                loaded = false
            }),
            debounceTime(200),
        ),
    ]).pipe(
        distinctUntilChanged(),
        switchMap(([p, f]) => {
            page = p
            loaded = false
            return load({
                search: f,
                offset: p * (pageSize ?? 0),
                limit: pageSize,
            })
        }),
        share(),
        tap(() => {
            loaded = true
        }),
    )

    const total = observe<number>(responses.pipe(map(x => x.total)), 0)
    const items = observe<T[] | null>(
        responses.pipe(
            map(x => x.items),
            tap(list => {
                hasItems = !!list?.length
            }),
        ),
        null,
    )

    interface Row {
        item: T
        group?: G
        key?: GK
        groupStart: boolean
        collapsed: boolean
    }

    interface Rows {
        rows: Row[]
        keys: GK[]
    }

    // Groups are detected by adjacency, so the caller is expected to hand us
    // items already sorted by group.
    function buildRows(list: T[]): Rows {
        const getGroup = groupObject
        const getKey = groupKey

        if (!getGroup || !getKey) {
            return {
                rows: list.map(_item => ({
                    item: _item,
                    groupStart: false,
                    collapsed: false,
                })),
                keys: [],
            }
        }

        const entries = list.map(_item => {
            const group = getGroup(_item)
            return { item: _item, group, key: getKey(group) }
        })

        // An active search expands everything, so that matches can't hide
        // inside a collapsed group - without touching the persisted state.
        const hidden = filter ? new Set<GK>() : new Set(collapsedGroups)

        return {
            keys: [...new Set(entries.map(entry => entry.key))],
            rows: entries.map((entry, _index) => ({
                ...entry,
                groupStart:
                    _index === 0 || entry.key !== entries[_index - 1]?.key,
                collapsed: hidden.has(entry.key),
            })),
        }
    }

    // Keys of groups that no longer exist are dropped on every write, so the
    // persisted set can't accumulate them as groups come and go.
    function toggleGroup(key: GK, present: GK[]) {
        const next = collapsedGroups.includes(key)
            ? collapsedGroups.filter(k => k !== key)
            : [...collapsedGroups, key]
        collapsedGroups = next.filter(k => present.includes(k))
    }

    onMount(() => {
        if (groupHeader && (!groupObject || !groupKey)) {
            throw new Error(
                'groupObject and groupKey must be provided when using groupHeader',
            )
        }
    })

    onDestroy(() => {
        page$.complete()
        filter$.complete()
    })

    $effect(() => {
        page$.next(page)
    })
    $effect(() => {
        filter$.next(filter)
    })

    filter$.subscribe(() => {
        page = 0
    })
</script>

<!-- Search input lives outside {#await} so it is never destroyed by data reloads -->
{#if showSearch && (filter || hasItems)}
    <div class="mb-2">
        <Input bind:value={filter} placeholder="Search..." class="w-100" />
    </div>
{/if}

{#await $items}
    <DelayedSpinner />
{:then _items}
    {@const _built = buildRows(_items ?? [])}
    <div hidden={!loaded}>
        <!-- Filters rendered on a separate row below search -->
        {@render header?.(_items, {
            available: _built.keys.length > 0 && !filter,
            collapseAll: () => {
                collapsedGroups = _built.keys
            },
            expandAll: () => {
                collapsedGroups = []
            },
        })}
    </div>
    {#if _items}
        <div class="list-group list-group-flush mb-3">
            {#each _built.rows as _row (_row.item)}
                {#if _row.groupStart && groupHeader && _row.group !== undefined && _row.key !== undefined}
                    {@const _key = _row.key}
                    {@render groupHeader(_row.group, {
                        collapsed: _row.collapsed,
                        collapsible: !filter,
                        toggle: () => toggleGroup(_key, _built.keys),
                    })}
                {/if}
                {#if !_row.collapsed}
                    {@render item?.(_row.item)}
                {/if}
            {/each}
        </div>
        {@render footer?.(_items)}
    {:else}
        <DelayedSpinner />
    {/if}

    {#if loaded && !_items?.length}
        {#if filter}
            <EmptyState title="Nothing found" />
        {:else}
            {@render empty?.()}
        {/if}
    {/if}
{/await}

{#await $total then _total}
    {#if pageSize && _total > pageSize}
        <Pagination total={_total} bind:page {pageSize} />
    {/if}
{/await}

<style lang="scss">
    .list-group:empty {
        display: none;
    }
</style>
