<script lang="ts" context="module">
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
    import { onDestroy } from 'svelte'
    import { Subject, switchMap, map, Observable, distinctUntilChanged, share, combineLatest, tap, debounceTime } from 'rxjs'
    import Pagination from './Pagination.svelte'
    import { observe } from 'svelte-observable'
    import { Input } from '@sveltestrap/sveltestrap'
    import DelayedSpinner from './DelayedSpinner.svelte'

    export let page = 0
    export let pageSize: number|undefined = undefined
    export let load: (_: LoadOptions) => Observable<PaginatedResponse<T>>
    export let showSearch = false

    let filter = ''
    let loaded = false

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

    $: page$.next(page)
    $: filter$.next(filter)

    filter$.subscribe(() => {
        page = 0
    })
</script>

<div class="d-flex mb-2" hidden={!loaded}>
    {#if showSearch}
        <Input bind:value={filter} placeholder="Search..." class="flex-grow-1 border-0" />
    {/if}
    <slot name="header" items={items} />
</div>
{#await $items}
    <DelayedSpinner />
{:then _items}
    {#if _items}
        <div class="list-group list-group-flush mb-3">
            {#each _items as item}
                <slot name="item" item={item} />
            {/each}
        </div>
        <slot name="footer" items={_items} />
    {:else}
        <DelayedSpinner />
    {/if}

    {#if filter && loaded && !_items?.length}
        <em>
            Nothing found
        </em>
    {/if}
{/await}

{#await $total then _total}
    {#if pageSize && _total > pageSize}
        <Pagination total={_total} bind:page={page} pageSize={pageSize} />
    {/if}
{/await}
