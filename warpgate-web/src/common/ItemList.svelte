<script lang="ts" module>
    import type { Snippet } from 'svelte'

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

    export interface Column<T> {
        id: string
        // A cell that renders no nodes counts as empty; a column empty in
        // every row collapses to zero width.
        cell: Snippet<[T]>
        // Makes the column user-toggleable from the list menu.
        label?: string
        hiddenByDefault?: boolean
        when?: boolean
        // Takes the remaining width instead of sizing to its content. With
        // no growing column enabled, the first one grows.
        grow?: boolean
        class?: string
    }

    export interface ColumnControls {
        toggleable: { id: string; label: string; shown: boolean }[]
        toggle: (id: string) => void
    }
</script>

<script lang="ts" generics="T, G = unknown, GK extends string = string">
    import { Input } from '@sveltestrap/sveltestrap'
    import {
        combineLatest,
        debounceTime,
        distinctUntilChanged,
        type Observable,
        Subject,
        switchMap,
        tap,
    } from 'rxjs'
    import { onDestroy, onMount, untrack } from 'svelte'
    import { type Writable, writable } from 'svelte/store'
    import { autosave } from './autosave'
    import DelayedSpinner from './DelayedSpinner.svelte'
    import EmptyState from './EmptyState.svelte'
    import Pagination from './Pagination.svelte'
    import VirtualList from './VirtualList.svelte'

    interface Props {
        page?: number
        pageSize?: number | undefined
        load: (_: LoadOptions) => Observable<PaginatedResponse<T>>
        groupObject?: (_: T) => G
        groupKey?: (_: G) => GK
        showSearch?: boolean
        header?: Snippet<[T[] | null, GroupControls, ColumnControls]>
        // `cells` renders the enabled `columns` for an item.
        item?: Snippet<[T, Snippet<[T]>]>
        columns?: Column<T>[]
        // Persists the list's view state (column toggles, collapsed groups)
        // under this key; without one it lasts until the list unmounts.
        storageKey?: string
        footer?: Snippet<[T[]]>
        empty?: Snippet<[]>
        groupHeader?: Snippet<[G, GroupState]>
        virtual?: boolean
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
        virtual = false,
        columns,
        storageKey,
    }: Props = $props()

    // Stores are created once; a changed key would not move them.
    const initialStorageKey = untrack(() => storageKey)
    function viewState<V>(name: string, initial: V): Writable<V> {
        return initialStorageKey
            ? autosave<V>(`item-list:${initialStorageKey}:${name}`, initial)[0]
            : writable(initial)
    }

    // Only explicit user choices are stored, so untouched columns follow
    // `hiddenByDefault` even when it changes later.
    const shownColumns = viewState<Record<string, boolean>>('columns', {})
    const collapsedGroups = viewState<GK[]>('collapsed-groups', [])

    function isShown(column: Column<T>): boolean {
        return column.label
            ? ($shownColumns[column.id] ?? !column.hiddenByDefault)
            : true
    }

    const availableColumns = $derived(columns?.filter(c => c.when !== false))
    const enabledColumns = $derived.by(() => {
        const shown = availableColumns?.filter(isShown)
        const fallbackGrow = !shown?.some(c => c.grow)
        return shown?.map((c, i) => ({
            ...c,
            grow: c.grow || (fallbackGrow && i === 0),
        }))
    })
    const gridTemplate = $derived(
        enabledColumns
            ?.map(c => (c.grow ? 'minmax(0, 1fr)' : 'auto'))
            .join(' '),
    )
    const columnControls: ColumnControls = $derived({
        toggleable: (availableColumns ?? []).flatMap(c =>
            c.label ? [{ id: c.id, label: c.label, shown: isShown(c) }] : [],
        ),
        toggle: id => {
            const column = columns?.find(c => c.id === id)
            if (column) {
                $shownColumns = { ...$shownColumns, [id]: !isShown(column) }
            }
        },
    })
    const listClass = $derived(enabledColumns ? 'item-list-columns' : '')

    let filter = $state('')
    let loaded = $state(false)
    let list = $state.raw<T[] | null>(null)
    let total = $state(0)

    const page$ = new Subject<number>()
    const filter$ = new Subject<string>()

    const subscription = combineLatest([
        page$,
        filter$.pipe(
            tap(() => {
                loaded = false
            }),
            debounceTime(200),
        ),
    ])
        .pipe(
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
        )
        .subscribe(response => {
            loaded = true
            list = response.items
            total = response.total
        })

    type Entry =
        | { kind: 'group'; group: G; key: GK; collapsed: boolean }
        | { kind: 'item'; item: T }

    const built = $derived(buildEntries(list ?? []))

    // Groups are detected by adjacency, so the caller is expected to hand us
    // items already sorted by group. Items of collapsed groups are left out.
    function buildEntries(items: T[]): { entries: Entry[]; keys: GK[] } {
        const getGroup = groupObject
        const getKey = groupKey

        if (!getGroup || !getKey) {
            return {
                entries: items.map(_item => ({ kind: 'item', item: _item })),
                keys: [],
            }
        }

        // An active search expands everything, so that matches can't hide
        // inside a collapsed group - without touching the persisted state.
        const hidden = filter ? new Set<GK>() : new Set($collapsedGroups)
        const entries: Entry[] = []
        const keys: GK[] = []

        for (const _item of items) {
            const group = getGroup(_item)
            const key = getKey(group)
            if (!keys.length || keys.at(-1) !== key) {
                keys.push(key)
                entries.push({
                    kind: 'group',
                    group,
                    key,
                    collapsed: hidden.has(key),
                })
            }
            if (!hidden.has(key)) {
                entries.push({ kind: 'item', item: _item })
            }
        }

        return { entries, keys }
    }

    // Keys of groups that no longer exist are dropped on every write, so the
    // persisted set can't accumulate them as groups come and go.
    function toggleGroup(key: GK, present: GK[]) {
        const next = $collapsedGroups.includes(key)
            ? $collapsedGroups.filter(k => k !== key)
            : [...$collapsedGroups, key]
        $collapsedGroups = next.filter(k => present.includes(k))
    }

    onMount(() => {
        if (groupHeader && (!groupObject || !groupKey)) {
            throw new Error(
                'groupObject and groupKey must be provided when using groupHeader',
            )
        }
    })

    onDestroy(() => {
        subscription.unsubscribe()
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

{#snippet cells(_item: T)}
    {#each enabledColumns ?? [] as column (column.id)}
        <div class="item-list-cell {column.class ?? ''}">
            {@render column.cell(_item)}
        </div>
    {/each}
{/snippet}

<!-- Virtual mode only has the visible rows in the grid, so this invisible
row holds every item's content-sized cells and the tracks size to the
widest one anywhere in the list. -->
{#snippet sizer()}
    {#if enabledColumns}
        <div class="item-list-sizer" aria-hidden="true" inert>
            {#each enabledColumns as column (column.id)}
                <div class="item-list-cell {column.class ?? ''}">
                    {#if !column.grow}
                        {#each list ?? [] as _item, i (i)}
                            <div class="item-list-probe">
                                {@render column.cell(_item)}
                            </div>
                        {/each}
                    {/if}
                </div>
            {/each}
        </div>
    {/if}
{/snippet}

{#snippet row(entry: Entry)}
    {#if entry.kind === 'item'}
        {@render item?.(entry.item, cells)}
    {:else if groupHeader}
        {@render groupHeader(entry.group, {
            collapsed: entry.collapsed,
            collapsible: !filter,
            toggle: () => toggleGroup(entry.key, built.keys),
        })}
    {/if}
{/snippet}

{#if !list}
    <DelayedSpinner />
{:else}
    <div class="d-flex align-items-center mb-2" hidden={!loaded}>
        <!-- either filtering or not filtering and there are at least some items at all -->
        {#if showSearch && (filter || !!list.length)}
            <Input
                bind:value={filter}
                placeholder="Search..."
                class="flex-grow-1"
            />
        {/if}
        {@render header?.(
            list,
            {
                available: built.keys.length > 0 && !filter,
                collapseAll: () => {
                    $collapsedGroups = built.keys
                },
                expandAll: () => {
                    $collapsedGroups = []
                },
            },
            columnControls,
        )}
    </div>
    {#if virtual}
        <VirtualList
            items={built.entries}
            {row}
            class={listClass}
            gridTemplateColumns={gridTemplate}
            before={sizer}
        />
    {:else}
        <div
            class="list-group list-group-flush mb-3 {listClass}"
            style:grid-template-columns={gridTemplate}
            hidden={!built.entries.length}
        >
            {#each built.entries as _entry (_entry.kind === 'item'
                ? _entry.item
                : _entry.key)}
                {@render row(_entry)}
            {/each}
        </div>
    {/if}
    {@render footer?.(list)}

    {#if loaded && !list.length}
        {#if filter}
            <EmptyState title="Nothing found" />
        {:else}
            {@render empty?.()}
        {/if}
    {/if}
{/if}

{#if pageSize && total > pageSize}
    <Pagination {total} bind:page {pageSize} />
{/if}

<style lang="scss">
    // Rows are subgrids of the list, so cells align across the whole list.
    :global(.list-group.item-list-columns) {
        display: grid;

        > :global(*) {
            grid-column: 1 / -1;
        }

        > :global(.list-group-item),
        > :global([data-index]:has(> .list-group-item)),
        > :global([data-index] > .list-group-item),
        > :global(.item-list-sizer) {
            grid-column: 1 / -1;
            display: grid;
            grid-template-columns: subgrid;
            align-items: center;
        }

        // Column spacing sits on non-empty cells only, so an all-empty
        // column is zero wide.
        :global(
                .list-group-item > .item-list-cell:not(:first-child):not(:empty)
            ) {
            padding-inline-start: 1rem;
        }

        > :global(.item-list-sizer) {
            visibility: hidden;
            block-size: 0;
            overflow: hidden;

            > :global(.item-list-cell:not(:first-child) > .item-list-probe:not(:empty)) {
                padding-inline-start: 1rem;
            }
        }
    }
</style>
