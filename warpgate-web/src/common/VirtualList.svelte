<script lang="ts" generics="T">
    import { createWindowVirtualizer } from '@tanstack/svelte-virtual'
    import { type Snippet, untrack } from 'svelte'

    interface Props {
        items: T[]
        row: Snippet<[T]>
    }

    const { items, row }: Props = $props()

    const virtualizer = createWindowVirtualizer<HTMLDivElement>({
        count: 0,
        estimateSize: () => 48,
        overscan: 10,
    })
    const rows = $derived($virtualizer.getVirtualItems())
    const margin = $derived($virtualizer.options.scrollMargin)

    // This elements locates the real top edge of the list
    let listStart: HTMLDivElement | undefined = $state()

    function measureRow(node: HTMLDivElement) {
        $virtualizer.measureElement(node)
        return {
            destroy: () => $virtualizer.measureElement(null),
        }
    }

    $effect(() => {
        const count = items.length
        const scrollMargin = listStart
            ? listStart.getBoundingClientRect().top + window.scrollY
            : 0
        untrack(() => $virtualizer.setOptions({ count, scrollMargin }))
    })
</script>

<div
    style:height="{(rows[0]?.start ?? margin) - margin}px"
    bind:this={listStart}
></div>
<div class="list-group list-group-flush mb-3" hidden={!items.length}>
    {#each rows as _row (_row.key)}
        {@const _item = items[_row.index]}
        <!-- The row count trails the items by one render, so the tail can
        point past the end. -->
        {#if _item !== undefined}
            <div data-index={_row.index} use:measureRow>
                {@render row(_item)}
            </div>
        {/if}
    {/each}
</div>
<div
    style:height="{$virtualizer.getTotalSize() - ((rows.at(-1)?.end ?? margin) - margin)}px"
></div>

<style lang="scss">
    // wrapper elements breaks bootstrap .list-group-item nesting rule
    [data-index] > :global(.list-group-item) {
        border-width: 0 0 var(--bs-list-group-border-width);
    }

    [data-index]:last-child > :global(.list-group-item) {
        border-bottom-width: 0;
    }
</style>
