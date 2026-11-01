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
    import { onDestroy, onMount, type Snippet } from 'svelte'
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
        // The page's main search: focused on load and by `/` or Ctrl/Cmd+K.
        primarySearch?: boolean
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
        primarySearch = false,
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
    let searchInput: HTMLInputElement | undefined = $state()
    let autofocused = false

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

    // Keys of groups that no longer exist are dropped on every write, so the
    // persisted set can't accumulate them as groups come and go.
    function toggleGroup(key: GK, present: GK[]) {
        const next = collapsedGroups.includes(key)
            ? collapsedGroups.filter(k => k !== key)
            : [...collapsedGroups, key]
        collapsedGroups = next.filter(k => present.includes(k))
    }

    function isTextEntry(target: EventTarget | null): boolean {
        return (
            target instanceof HTMLElement &&
            (target.isContentEditable ||
                ['INPUT', 'TEXTAREA', 'SELECT'].includes(target.tagName))
        )
    }

    function onWindowKeydown(e: KeyboardEvent) {
        if (!primarySearch || !searchInput) {
            return
        }
        const shortcut =
            (e.key === 'k' && (e.ctrlKey || e.metaKey)) ||
            (e.key === '/' && !isTextEntry(e.target))
        if (shortcut) {
            e.preventDefault()
            searchInput.focus()
            searchInput.select()
        }
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
    // Once only, so a later re-render never steals focus. Touch devices are
    // skipped, where focusing would pop up the on-screen keyboard.
    $effect(() => {
        if (
            primarySearch &&
            searchInput &&
            !autofocused &&
            matchMedia('(pointer: fine)').matches
        ) {
            autofocused = true
            searchInput.focus()
        }
    })

    filter$.subscribe(() => {
        page = 0
    })
</script>

{#snippet row(
    entry: Entry,
)}
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

<svelte:window onkeydown={onWindowKeydown} />

{#if !list}
    <DelayedSpinner />
{:else}
    <div class="d-flex align-items-center mb-2" hidden={!loaded}>
        <!-- either filtering or not filtering and there are at least some items at all -->
        {#if showSearch && (filter || !!list.length)}
            <div class="search position-relative flex-grow-1">
                <Input
                    bind:inner={searchInput}
                    bind:value={filter}
                    placeholder="Search..."
                />
                {#if primarySearch && !filter}
                    <kbd class="shortcut-hint" aria-hidden="true">/</kbd>
                {/if}
            </div>
        {/if}
        {@render header?.(list, {
            available: built.keys.length > 0 && !filter,
            collapseAll: () => {
                collapsedGroups = built.keys
            },
            expandAll: () => {
                collapsedGroups = []
            },
        })}
    </div>
    {#if virtual}
        <VirtualList items={built.entries} {row} />
    {:else}
        <div
            class="list-group list-group-flush mb-3"
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
    .shortcut-hint {
        position: absolute;
        top: 50%;
        right: 0.75rem;
        transform: translateY(-50%);
        pointer-events: none;
        padding: 0.1rem 0.4rem;
        font-size: 0.75rem;
        color: var(--bs-secondary-color);
        background: transparent;
        border: 1px solid var(--bs-border-color);
    }

    .search:focus-within .shortcut-hint {
        display: none;
    }
</style>
