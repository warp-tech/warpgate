<script lang="ts" context="module">
    export interface LoadOptions {
        offset: number
        limit: number
    }

    export interface PaginatedResponse<T> {
        items: T[]
        offset: number
        total: number
    }
</script>

<script lang="ts">
    import { onDestroy } from 'svelte'
    import { Subject, switchMap, map, Observable, distinctUntilChanged, share } from 'rxjs'
    import Pagination from './Pagination.svelte'
    import { observe } from 'svelte-observable'
    import DelayedSpinner from './DelayedSpinner.svelte'

    // eslint-disable-next-line @typescript-eslint/no-type-alias
    type T = $$Generic

    export let page = 0
    export let pageSize = 100
    export let load: (_: LoadOptions) => Observable<PaginatedResponse<T>>

    const page$ = new Subject<number>()

    const responses = page$.pipe(
        distinctUntilChanged(),
        switchMap(p => {
            page = p
            return load({
                offset: p * pageSize,
                limit: pageSize,
            })
        }),
        share(),
    )

    const total = observe<number>(responses.pipe(map(x => x.total)), 0)
    const items = observe<T[]|null>(responses.pipe(map(x => x.items)), null)

    onDestroy(() => {
        page$.complete()
    })

    $: page$.next(page)
</script>

{#await $items}
    <DelayedSpinner />
{:then items}
    {#if items}
        <slot name="header" items={items} />
        <div class="list-group list-group-flush mb-3">
            {#each items as item}
                <slot name="item" item={item} />
            {/each}
        </div>
        <slot name="footer" items={items} />
    {:else}
        <DelayedSpinner />
    {/if}
{/await}

{#await $total then total}
    {#if total > pageSize}
        <Pagination total={total} bind:page={page} pageSize={pageSize} />
    {/if}
{/await}
