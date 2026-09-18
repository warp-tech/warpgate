<script lang="ts">
    /**
     * Loading placeholder for table rows.
     *
     * Replaces DelayedSpinner's 1000ms-then-spinner approach for lists. The
     * delay in that component exists to avoid flashing a spinner on a fast
     * response; skeletons solve the same problem differently, by occupying the
     * space the rows will take so nothing jumps when they land.
     *
     * The whole block is a single live region labelled "Loading" rather than
     * N announced rows — a screen reader does not need to hear about the
     * placeholder geometry.
     */
    interface Props {
        rows?: number
        /** Relative column widths, e.g. [2, 3, 1]. */
        columns?: number[]
        dense?: boolean
        class?: string
    }

    let {
        rows = 5,
        columns = [2, 3, 2, 1],
        dense = false,
        class: className = '',
    }: Props = $props()

    // Varying the fill width per row stops the block reading as a solid
    // rectangle, which is what makes it legible as "content is coming".
    function width(row: number, col: number): string {
        const base = [92, 74, 86, 62, 80]
        return `${base[(row + col) % base.length]}%`
    }
</script>

<div
    class="wg-skeleton {className}"
    class:wg-skeleton-dense={dense}
    role="status"
    aria-label="Loading"
>
    {#each { length: rows } as _, row (row)}
        <div class="wg-skeleton-row">
            {#each columns as flex, col (col)}
                <div class="wg-skeleton-cell" style="flex: {flex}">
                    <span
                        class="wg-skeleton-bar"
                        style="width: {width(row, col)}"
                    ></span>
                </div>
            {/each}
        </div>
    {/each}
</div>

<style>
    .wg-skeleton-row {
        display: flex;
        align-items: center;
        gap: var(--wg-space-lg);
        height: var(--wg-row-height);
        padding: 0 var(--wg-space-md);
        border-bottom: var(--wg-border-width) solid var(--wg-border);
    }

    .wg-skeleton-dense .wg-skeleton-row {
        height: var(--wg-row-height-dense);
    }

    .wg-skeleton-cell {
        min-width: 0;
    }

    .wg-skeleton-bar {
        display: block;
        height: 0.5rem;
        border-radius: var(--wg-radius-sm);
        background: var(--wg-surface-container-high);
        animation: wg-shimmer 1.4s ease-in-out infinite;
    }

    .wg-skeleton-row:nth-child(even) .wg-skeleton-bar {
        animation-delay: 0.2s;
    }

    @keyframes wg-shimmer {
        0%,
        100% {
            opacity: 1;
        }
        50% {
            opacity: 0.45;
        }
    }

    @media (prefers-reduced-motion: reduce) {
        .wg-skeleton-bar {
            animation: none;
        }
    }
</style>
