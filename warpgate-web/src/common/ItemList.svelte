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
    import { Subject, switchMap, Observable } from 'rxjs'
    import Pagination from './Pagination.svelte'
    // import { observe } from 'svelte-observable';

    // eslint-disable-next-line @typescript-eslint/no-type-alias
    type T = $$Generic

    export let page = 0
    export let pageSize = 5
    export let load: (LoadOptions) => Observable<PaginatedResponse<T>>

    let items: T[]|undefined
    let total = 0

    let page$ = new Subject<number>()

    page$.pipe(switchMap(p => {
        page = p
        return load({
            offset: p * pageSize,
            limit: pageSize,
        })
    })).subscribe(response => {
        total = response.total
        items = response.items
    })

    onDestroy(() => {
        page$.complete()
    })

    $: page$.next(page)
</script>

{#if items}
    <div class="list-group list-group-flush mb-3">
        {#each items as item}
            <slot item={item} />
        {/each}
    </div>
{/if}

{#if total > pageSize}
    <Pagination total={total} bind:page={page} pageSize={pageSize} />
{/if}
