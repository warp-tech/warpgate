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
        count: number
        toggle: () => void
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
        header?: Snippet<[T[] | null]>
        item?: Snippet<[T]>
        footer?: Snippet<[T[]]>
        empty?: Snippet<[]>
        groupHeader?: Snippet<[G, GroupState]>
        collapsibleGroups?: boolean
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
        collapsibleGroups = false,
        collapsedGroups = $bindable([]),
    }: Props = $props()

    let filter = $state('')
    let loaded = $state(false)

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
    const items = observe<T[] | null>(responses.pipe(map(x => x.items)), null)

    interface Row {
        item: T
        group?: G
        key?: GK
        groupStart: boolean
        count: number
        collapsed: boolean
    }

    // Groups are detected by adjacency, so the caller is expected to hand us
    // items already sorted by group.
    function buildRows(list: T[]): Row[] {
        const getGroup = groupObject
        const getKey = groupKey

        if (!getGroup || !getKey) {
            return list.map(_item => ({
                item: _item,
                groupStart: false,
                count: 0,
                collapsed: false,
            }))
        }

        const entries = list.map(_item => {
            const group = getGroup(_item)
            return { item: _item, group, key: getKey(group) }
        })

        const counts = new Map<GK, number>()
        for (const entry of entries) {
            counts.set(entry.key, (counts.get(entry.key) ?? 0) + 1)
        }

        // An active search expands everything so that matches can't hide
        // inside a collapsed group - without touching the persisted state.
        const hidden =
            collapsibleGroups && !filter
                ? new Set(collapsedGroups)
                : new Set<GK>()

        return entries.map((entry, _index) => ({
            ...entry,
            groupStart: _index === 0 || entry.key !== entries[_index - 1]?.key,
            count: counts.get(entry.key) ?? 0,
            collapsed: hidden.has(entry.key),
        }))
    }

    function toggleGroup(key: GK) {
        collapsedGroups = collapsedGroups.includes(key)
            ? collapsedGroups.filter(k => k !== key)
            : [...collapsedGroups, key]
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

{#await $items}
    <DelayedSpinner />
{:then _items}
    <div class="d-flex align-items-center mb-2" hidden={!loaded}>
        <!-- either filtering or not filtering and there are at least some items at all -->
        {#if showSearch && (filter || !!_items?.length)}
            <Input
                bind:value={filter}
                placeholder="Search..."
                class="flex-grow-1"
            />
        {/if}
        {@render header?.(_items)}
    </div>
    {#if _items}
        {@const _rows = buildRows(_items)}
        <div class="list-group list-group-flush mb-3">
            {#each _rows as _row (_row.item)}
                {#if _row.groupStart && groupHeader && _row.group !== undefined && _row.key !== undefined}
                    {@const _key = _row.key}
                    {@render groupHeader(_row.group, {
                        collapsed: _row.collapsed,
                        count: _row.count,
                        toggle: () => toggleGroup(_key),
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
