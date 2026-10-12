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
        type Observable,
        Subject,
        switchMap,
        tap,
    } from 'rxjs'
    import { onDestroy, onMount, type Snippet, tick } from 'svelte'
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
        header?: Snippet<[T[] | null, GroupControls]>
        item?: Snippet<[T]>
        footer?: Snippet<[T[]]>
        empty?: Snippet<[]>
        groupHeader?: Snippet<[G, GroupState]>
        collapsedGroups?: GK[]
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
        collapsedGroups = $bindable([]),
        virtual = false,
    }: Props = $props()

    let filter = $state('')
    let loaded = $state(false)
    let list = $state.raw<T[] | null>(null)
    let total = $state(0)
    // Page of the items in `list`
    let shownPage = 0
    // Marks where the list starts, for bringing a new page's first items into
    // view: the pagination sits below a page's worth of items
    let listStart: HTMLElement | undefined = $state()

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
            if (page !== shownPage) {
                shownPage = page
                // Once the new items are rendered. Instantly, as re-rendering
                // the list cuts Bootstrap's smooth scrolling short
                void tick().then(() => {
                    if (
                        listStart &&
                        listStart.getBoundingClientRect().top < 0
                    ) {
                        listStart.scrollIntoView({ behavior: 'instant' })
                    }
                })
            }
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
        const hidden = filter ? new Set<GK>() : new Set(collapsedGroups)
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

    // Whether every item is loaded, rather than one page of them
    const complete = $derived((list?.length ?? 0) >= total)

    // Keys of groups that no longer exist are dropped on every write, so the
    // persisted set can't accumulate them as groups come and go. That's only
    // known when every item is loaded - other pages have groups of their own.
    function toggleGroup(key: GK, present: GK[]) {
        const next = collapsedGroups.includes(key)
            ? collapsedGroups.filter(k => k !== key)
            : [...collapsedGroups, key]
        collapsedGroups = complete
            ? next.filter(k => present.includes(k))
            : next
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

{#snippet row(entry: Entry)}
    {#if entry.kind === 'item'}
        {@render item?.(entry.item)}
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
        {@render header?.(list, {
            available: built.keys.length > 0 && !filter,
            collapseAll: () => {
                collapsedGroups = complete
                    ? built.keys
                    : [...new Set([...collapsedGroups, ...built.keys])]
            },
            expandAll: () => {
                collapsedGroups = complete
                    ? []
                    : collapsedGroups.filter(k => !built.keys.includes(k))
            },
        })}
    </div>
    <!-- Until the next page arrives, the current one stays on screen, dimmed -->
    <div bind:this={listStart} class="items" class:loading={!loaded}>
        {#if virtual}
            <VirtualList items={built.entries} {row} />
        {:else}
            <div
                class="list-group list-group-flush mb-3"
                hidden={!built.entries.length}
            >
                {#each built.entries as _entry (_entry.kind === 'item' ? _entry.item : _entry.key)}
                    {@render row(_entry)}
                {/each}
            </div>
        {/if}
    </div>
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
    .items {
        transition: opacity 0.15s;

        &.loading {
            opacity: 0.5;
            // Only for loads slow enough to notice, so that quick ones don't
            // flicker
            transition-delay: 0.2s;
        }
    }
</style>
