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
</script>

<script lang="ts" generics="T">
    import { Subject, switchMap, map, Observable, distinctUntilChanged, share, combineLatest, tap, debounceTime } from 'rxjs'
    import Pagination from './Pagination.svelte'
    import { observe } from 'svelte-observable'
    import { Input } from '@sveltestrap/sveltestrap'
    import DelayedSpinner from './DelayedSpinner.svelte'
    import { onDestroy, type Snippet } from 'svelte'
    import EmptyState from './EmptyState.svelte'

    interface Props {
        page?: number
        pageSize?: number|undefined
        load: (_: LoadOptions) => Observable<PaginatedResponse<T>>
        showSearch?: boolean
        header?: Snippet<[]>
        item?: Snippet<[T]>
        footer?: Snippet<[T[]]>
        empty?: Snippet<[]>
    }

    let {
        page = $bindable(0),
        pageSize = undefined,
        load,
        showSearch = false,
        header,
        item,
        footer,
        empty,
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
    const items = observe<T[]|null>(responses.pipe(map(x => x.items)), null)

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
    <div class="d-flex mb-2" hidden={!loaded}>
        <!-- either filtering or not filtering and there are at least some items at all -->
        {#if showSearch && (filter || !!_items?.length)}
            <Input bind:value={filter} placeholder="Search..." class="flex-grow-1 border-0" />
        {/if}
        {@render header?.()}
    </div>
    {#if _items}
        <div class="list-group list-group-flush mb-3">
            {#each _items as _item (_item)}
                {@render item?.(_item)}
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
        <Pagination total={_total} bind:page={page} pageSize={pageSize} />
    {/if}
{/await}

<style lang="scss">
    .list-group:empty {
        display: none;
    }
</style>
