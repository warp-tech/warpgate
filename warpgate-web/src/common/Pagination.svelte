<script lang="ts">
    /**
     * Page selector for ItemList.
     *
     * Behaviour preserved exactly: the same elision algorithm — always the
     * first two pages, the last three, and anything within two of the current
     * one, with a single ellipsis standing in for each run that is dropped.
     *
     * Changed: the pages were sveltestrap `PaginationLink`s, i.e. `<a href="#">`
     * with preventDefault. They go nowhere, so they are buttons now. That also
     * fixes two things the anchors got wrong — the ellipsis was a focusable
     * link that navigated to the current page, and nothing told assistive tech
     * which page was current. `aria-current="page"` does that, and the
     * ellipsis is inert text.
     *
     * The whole thing is a <nav> with a name, because a bare row of numbers
     * is meaningless out of context.
     */
    interface Props {
        page?: number
        pageSize?: number
        total?: number
    }

    let { page = $bindable(0), pageSize = 1, total = 1 }: Props = $props()

    const totalPages = $derived(Math.floor((total - 1) / pageSize + 1))

    const pages: (number | null)[] = $derived.by(() => {
        let i = 0
        const result: (number | null)[] = []
        while (i < totalPages) {
            if (i < 2 || i > totalPages - 3 || Math.abs(i - page) < 3) {
                result.push(i)
            } else if (result[result.length - 1] !== null) {
                result.push(null)
            }
            i++
        }
        return result
    })

    const canPrev = $derived(page > 0)
    const canNext = $derived((page + 1) * pageSize < total)
</script>

{#if totalPages > 1}
    <nav class="pager" aria-label="Pagination">
        <button
            type="button"
            class="page-btn"
            disabled={!canPrev}
            aria-label="Previous page"
            onclick={() => (page = page - 1)}
        >
            <svg viewBox="0 0 16 16" width="14" height="14" aria-hidden="true">
                <path
                    d="M10 3.5L5.5 8l4.5 4.5"
                    fill="none"
                    stroke="currentColor"
                    stroke-width="1.75"
                    stroke-linecap="round"
                    stroke-linejoin="round"
                />
            </svg>
        </button>

        {#each pages as i, idx (i === null ? `gap-${idx}` : i)}
            {#if i !== null}
                <button
                    type="button"
                    class="page-btn"
                    class:page-current={page === i}
                    aria-current={page === i ? 'page' : undefined}
                    aria-label="Page {i + 1}"
                    onclick={() => (page = i)}
                >
                    {i + 1}
                </button>
            {:else}
                <span class="gap" aria-hidden="true">…</span>
            {/if}
        {/each}

        <button
            type="button"
            class="page-btn"
            disabled={!canNext}
            aria-label="Next page"
            onclick={() => (page = page + 1)}
        >
            <svg viewBox="0 0 16 16" width="14" height="14" aria-hidden="true">
                <path
                    d="M6 3.5L10.5 8 6 12.5"
                    fill="none"
                    stroke="currentColor"
                    stroke-width="1.75"
                    stroke-linecap="round"
                    stroke-linejoin="round"
                />
            </svg>
        </button>
    </nav>
{/if}

<style>
    .pager {
        display: flex;
        align-items: center;
        gap: var(--wg-space-xs);
        flex-wrap: wrap;
    }

    .page-btn {
        display: inline-flex;
        align-items: center;
        justify-content: center;
        min-width: var(--wg-control-height-compact);
        height: var(--wg-control-height-compact);
        padding: 0 var(--wg-space-sm);
        background: none;
        border: var(--wg-border-width) solid transparent;
        border-radius: var(--wg-radius-control);
        color: var(--wg-text-muted);
        font: var(--wg-text-label-md);
        font-variant-numeric: tabular-nums;
        cursor: pointer;
    }

    .page-btn:hover:not(:disabled) {
        background: var(--wg-surface-container-high);
        color: var(--wg-text);
    }

    .page-btn:focus-visible {
        outline: var(--wg-focus-ring);
        outline-offset: var(--wg-focus-ring-offset);
    }

    .page-btn:disabled {
        opacity: 0.4;
        cursor: not-allowed;
    }

    .page-current {
        background: var(--wg-surface-container-highest);
        border-color: var(--wg-border-strong);
        color: var(--wg-text);
    }

    .gap {
        padding: 0 var(--wg-space-xs);
        color: var(--wg-text-subtle);
    }
</style>
