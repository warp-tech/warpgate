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
    import { onDestroy } from 'svelte'

    interface Props {
        page?: number
        pageSize?: number|undefined
        // eslint-disable-next-line no-undef
        load: (_: LoadOptions) => Observable<PaginatedResponse<T>>
        showSearch?: boolean
        header?: import('svelte').Snippet<[any]>
        item?: import('svelte').Snippet<[any]>
        footer?: import('svelte').Snippet<[any]>
    }

    let {
        page = $bindable(0),
        pageSize = undefined,
        load,
        showSearch = false,
        header,
        item,
        footer,
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
    // eslint-disable-next-line no-undef
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

<div class="d-flex mb-2" hidden={!loaded}>
    {#if showSearch}
        <Input bind:value={filter} placeholder="Search..." class="flex-grow-1 border-0" />
    {/if}
    {@render header?.({ items })}
</div>
{#await $items}
    <DelayedSpinner />
{:then _items}
    {#if _items}
        <div class="list-group list-group-flush mb-3">
            {#each _items as _item}
                {@render item?.({ item: _item })}
            {/each}
        </div>
        {@render footer?.({ items: _items })}
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
