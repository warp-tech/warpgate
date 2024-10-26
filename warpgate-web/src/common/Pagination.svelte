<script lang="ts">
    import { faAngleLeft, faAngleRight } from '@fortawesome/free-solid-svg-icons'
    import Fa from 'svelte-fa'
    import { Pagination, PaginationItem, PaginationLink } from '@sveltestrap/sveltestrap'

    interface Props {
        page?: number;
        pageSize?: number;
        total?: number;
    }

    let { page = $bindable(0), pageSize = 1, total = 1 }: Props = $props()

    let pages: (number|null)[] = $state([])

    $effect(() => {
        let i = 0
        pages = []
        let totalPages = Math.floor((total - 1) / pageSize + 1)
        while (i < totalPages) {
            if (i < 2 || i > totalPages - 3 || Math.abs(i - page) < 3) {
                pages.push(i)
            } else if (pages[pages.length - 1]) {
                pages.push(null)
            }
            i++
        }
    })
</script>

<Pagination>
    <PaginationItem disabled={page === 0}>
        <PaginationLink on:click={() => page--} href="#">
            <Fa icon={faAngleLeft} />
        </PaginationLink>
    </PaginationItem>
    {#each pages as i}
        {#if i !== null}
            <PaginationItem active={page === i}>
                <PaginationLink on:click={() => page = i} href="#">{i + 1}</PaginationLink>
            </PaginationItem>
        {:else}
            <PaginationItem disabled>
                <PaginationLink href="#">...</PaginationLink>
            </PaginationItem>
        {/if}
    {/each}
    <PaginationItem disabled={(page + 1) * pageSize >= total}>
        <PaginationLink on:click={() => page++} href="#">
            <Fa icon={faAngleRight} />
        </PaginationLink>
    </PaginationItem>
</Pagination>
