<script lang="ts" module>
    export interface AuditTarget {
        /** What is being checked, e.g. "Button / primary". */
        name: string
        /** CSS selector, resolved inside the styleguide document. */
        selector: string
        /** 'text' = 1.4.3 (4.5:1); 'ui' = 1.4.11 non-text (3:1). */
        rule?: 'text' | 'ui'
        /**
         * For 'ui' checks: compare this element's border against the background of
         * its nearest painted ancestor rather than its own text colour.
         */
        border?: boolean
    }
</script>

<script lang="ts">
    /**
     * Extends the Phase 1 live token audit to rendered primitives.
     *
     * Reads back what the browser actually painted — resolved foreground,
     * background and border colours — and grades them. A token can be correct
     * while a component still fails, because components compose tokens; this
     * catches that gap without anyone having to reason about it.
     */
    import { onMount } from 'svelte'
    import { contrast } from './contrast'

    interface Props {
        targets: AuditTarget[]
        caption: string
    }

    let { targets, caption }: Props = $props()

    interface Row {
        name: string
        fg: string
        bg: string
        ratio: number | null
        threshold: number
        pass: boolean
        missing?: boolean
    }

    let rows: Row[] = $state([])

    // Walks up for the first ancestor with a non-transparent background —
    // a button's own background may be `none`, and grading against
    // "rgba(0,0,0,0)" would be meaningless.
    function paintedBackground(el: Element): string {
        let node: Element | null = el
        while (node) {
            const bg = getComputedStyle(node).backgroundColor
            if (
                bg &&
                bg !== 'transparent' &&
                !bg.startsWith('rgba(0, 0, 0, 0')
            ) {
                return bg
            }
            node = node.parentElement
        }
        return getComputedStyle(document.body).backgroundColor
    }

    function measure() {
        rows = targets.map(target => {
            const el = document.querySelector(target.selector)
            if (!el) {
                return {
                    name: target.name,
                    fg: '—',
                    bg: '—',
                    ratio: null,
                    threshold: 0,
                    pass: false,
                    missing: true,
                }
            }
            const style = getComputedStyle(el)
            const threshold = target.rule === 'ui' ? 3 : 4.5
            const fg = target.border ? style.borderTopColor : style.color
            const bg = target.border
                ? paintedBackground(el.parentElement ?? el)
                : paintedBackground(el)
            const ratio = contrast(fg, bg)
            return {
                name: target.name,
                fg,
                bg,
                ratio,
                threshold,
                pass: (ratio ?? 0) >= threshold,
            }
        })
    }

    onMount(() => {
        // After paint, and after fonts settle, so computed styles are final.
        const run = () => requestAnimationFrame(measure)
        run()

        /**
         * Some audited components mount asynchronously — Table renders its rows
         * out of ItemList's `{#await}`, so at first paint there is no <td> to
         * measure and the row reports "not rendered". Re-measuring on subtree
         * changes (debounced) picks them up once they land, instead of the
         * audit quietly under-reporting the things most likely to be wrong.
         */
        let settle: ReturnType<typeof setTimeout>
        const reMeasure = () => {
            clearTimeout(settle)
            settle = setTimeout(run, 120)
        }
        const content = new MutationObserver(reMeasure)
        content.observe(document.body, { childList: true, subtree: true })

        const observer = new MutationObserver(run)
        observer.observe(document.documentElement, {
            attributes: true,
            attributeFilter: ['data-wg-theme'],
        })
        const mq = window.matchMedia('(prefers-color-scheme: dark)')
        mq.addEventListener('change', run)
        return () => {
            clearTimeout(settle)
            content.disconnect()
            observer.disconnect()
            mq.removeEventListener('change', run)
        }
    })

    const failures = $derived(rows.filter(r => !r.pass && !r.missing).length)
</script>

<div class="audit">
    <div class="audit-head">
        <strong>{caption}</strong>
        <span class:audit-bad={failures > 0} class:audit-good={failures === 0}>
            {failures === 0 ? 'all pass' : `${failures} failing`}
        </span>
    </div>
    <table>
        <thead>
            <tr>
                <th scope="col">Target</th>
                <th scope="col">Foreground</th>
                <th scope="col">Background</th>
                <th scope="col">Ratio</th>
                <th scope="col">Needs</th>
            </tr>
        </thead>
        <tbody>
            {#each rows as row (row.name)}
                <tr class:audit-row-bad={!row.pass && !row.missing}>
                    <td>{row.name}</td>
                    <td class="mono">{row.fg}</td>
                    <td class="mono">{row.bg}</td>
                    <td class="mono num">
                        {row.missing ? 'not rendered' : (row.ratio?.toFixed(2) ?? '—')}
                    </td>
                    <td class="mono num">{row.threshold}:1</td>
                </tr>
            {/each}
        </tbody>
    </table>
</div>

<style>
    .audit {
        border: var(--wg-border-width) solid var(--wg-border);
        border-radius: var(--wg-radius-panel);
        overflow: hidden;
        margin-top: var(--wg-space-md);
    }

    .audit-head {
        display: flex;
        justify-content: space-between;
        align-items: center;
        gap: var(--wg-space-md);
        padding: var(--wg-space-sm) var(--wg-space-md);
        background: var(--wg-surface-container);
        border-bottom: var(--wg-border-width) solid var(--wg-border);
        font: var(--wg-text-label-md);
    }

    .audit-good {
        color: var(--wg-tertiary);
    }

    .audit-bad {
        color: var(--wg-error);
    }

    table {
        width: 100%;
        border-collapse: collapse;
        font: var(--wg-text-label-sm);
    }

    th {
        text-align: left;
        padding: var(--wg-space-xs) var(--wg-space-md);
        color: var(--wg-text-muted);
        border-bottom: var(--wg-border-width) solid var(--wg-border);
    }

    td {
        padding: var(--wg-space-xs) var(--wg-space-md);
        border-bottom: var(--wg-border-width) solid var(--wg-border);
    }

    tbody tr:last-child td {
        border-bottom: 0;
    }

    .audit-row-bad td {
        color: var(--wg-error);
    }

    .mono {
        font-family: var(--wg-font-mono);
    }

    .num {
        font-variant-numeric: tabular-nums;
        text-align: right;
    }
</style>
