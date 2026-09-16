<script lang="ts" module>
    export interface Column {
        key: string
        label: string
        sortable?: boolean
        /** Right-align numeric columns; actions anchor right per DESIGN.md. */
        align?: 'start' | 'end'
        width?: string
        /** Hidden below this viewport width. */
        hideBelow?: number
    }

    export interface SortState {
        key: string
        direction: 'asc' | 'desc'
    }

    export type Density = 'comfortable' | 'dense'
</script>

<script lang="ts" generics="T, G = unknown, GK = unknown">
    import ItemList, {
        type GroupControls,
        type GroupState,
        type LoadOptions,
        type PaginatedResponse,
    } from 'common/ItemList.svelte'
    import type { Observable } from 'rxjs'
    /**
     * Table WRAPS common/ItemList.svelte. It deliberately owns none of the
     * data behaviour.
     *
     * ItemList keeps: the RxJS search debounce, pagination, adjacency-based
     * grouping, persisted group collapse, the search-force-expand rule, empty
     * and loading states. Table reaches none of that — it passes `load`,
     * `page`, `pageSize`, `groupObject`/`groupKey` and `collapsedGroups`
     * straight through, and supplies markup via ItemList's `container` and
     * `searchInput` snippets.
     *
     * Table adds exactly five things: sticky header, sortable headers,
     * a density toggle, keyboard row navigation, and row selection.
     *
     * Sorting is surfaced, not applied. ItemList owns row order because
     * grouping is adjacency-based, so sorting rows here would silently break
     * groups. `sort` is bindable; the caller feeds it into its own `load`.
     */
    import type { Snippet } from 'svelte'
    import Checkbox from './Checkbox.svelte'
    import Input from './Input.svelte'
    import SegmentedControl from './SegmentedControl.svelte'

    interface Props {
        columns: Column[]
        load: (_: LoadOptions) => Observable<PaginatedResponse<T>>
        /** Stable identity for selection and keyed iteration. */
        rowKey: (item: T) => string
        caption: string
        page?: number
        pageSize?: number
        showSearch?: boolean
        searchPlaceholder?: string
        sort?: SortState | undefined
        density?: Density
        showDensityToggle?: boolean
        selectable?: boolean
        selected?: string[]
        groupObject?: (_: T) => G
        groupKey?: (_: G) => GK
        collapsedGroups?: GK[]
        class?: string
        onrowactivate?: (item: T) => void
        /** Renders the <td> cells for one row. Table supplies the <tr>. */
        row: Snippet<[T]>
        groupHeader?: Snippet<[G, GroupState]>
        toolbar?: Snippet<[T[] | null, GroupControls]>
        empty?: Snippet
    }

    let {
        columns,
        load,
        rowKey,
        caption,
        page = $bindable(0),
        pageSize,
        showSearch = false,
        searchPlaceholder = 'Search…',
        sort = $bindable(undefined),
        density = $bindable('comfortable'),
        showDensityToggle = true,
        selectable = false,
        selected = $bindable([]),
        groupObject,
        groupKey,
        collapsedGroups = $bindable([]),
        class: className = '',
        onrowactivate,
        row,
        groupHeader,
        toolbar,
        empty,
    }: Props = $props()

    let tbody: HTMLTableSectionElement | undefined = $state()
    /**
     * Roving tabindex, keyed rather than indexed: the table is one tab stop
     * and arrows move within it. Tracked by row key because ItemList may
     * reorder or regroup rows underneath us, and a stale integer index would
     * silently move the tab stop to a different record.
     */
    let activeKey: string | null = $state(null)

    function toggleSort(column: Column) {
        if (!column.sortable) {
            return
        }
        if (sort?.key !== column.key) {
            sort = { key: column.key, direction: 'asc' }
        } else if (sort.direction === 'asc') {
            sort = { key: column.key, direction: 'desc' }
        } else {
            // Third click clears — an operator who sorted by mistake should
            // not have to guess which column was the original order.
            sort = undefined
        }
    }

    function ariaSort(
        column: Column,
    ): 'ascending' | 'descending' | 'none' | undefined {
        if (!column.sortable) {
            return undefined
        }
        if (sort?.key !== column.key) {
            return 'none'
        }
        return sort.direction === 'asc' ? 'ascending' : 'descending'
    }

    function rowElements(): HTMLTableRowElement[] {
        return Array.from(
            tbody?.querySelectorAll<HTMLTableRowElement>('tr[data-row]') ?? [],
        )
    }

    /**
     * Keeps exactly one row tabbable. Runs after every row render so that the
     * tab stop lands on the first row initially, and is re-seated if the row
     * it was on disappears — a page change, a filter, a collapsed group.
     * Without this the table would either have no tab stop or one pointing at
     * a detached element.
     */
    $effect(() => {
        const all = rowElements()
        if (!all.length) {
            activeKey = null
            return
        }
        const stillPresent =
            activeKey !== null &&
            all.some(el => el.dataset.rowKey === activeKey)
        if (!stillPresent) {
            activeKey = all[0]?.dataset.rowKey ?? null
        }
    })

    // Position is read from the DOM at event time rather than captured during
    // render: grouping means rendered order is not item order, and a captured
    // index goes stale the moment a group collapses.
    function focusRelative(
        from: HTMLTableRowElement,
        delta: number | 'first' | 'last',
    ) {
        const all = rowElements()
        if (!all.length) {
            return
        }
        const current = all.indexOf(from)
        const target =
            delta === 'first'
                ? 0
                : delta === 'last'
                  ? all.length - 1
                  : Math.max(0, Math.min(current + delta, all.length - 1))
        const el = all[target]
        if (el) {
            activeKey = el.dataset.rowKey ?? null
            el.focus()
        }
    }

    function onRowKeydown(event: KeyboardEvent, item: T) {
        const self = event.currentTarget as HTMLTableRowElement
        switch (event.key) {
            case 'ArrowDown':
                event.preventDefault()
                focusRelative(self, 1)
                break
            case 'ArrowUp':
                event.preventDefault()
                focusRelative(self, -1)
                break
            case 'Home':
                event.preventDefault()
                focusRelative(self, 'first')
                break
            case 'End':
                event.preventDefault()
                focusRelative(self, 'last')
                break
            case 'Enter':
                if (onrowactivate) {
                    event.preventDefault()
                    onrowactivate(item)
                }
                break
            case ' ':
                if (selectable) {
                    event.preventDefault()
                    toggleRow(item)
                }
                break
        }
    }

    function isSelected(item: T): boolean {
        return selected.includes(rowKey(item))
    }

    function toggleRow(item: T) {
        const key = rowKey(item)
        selected = selected.includes(key)
            ? selected.filter(k => k !== key)
            : [...selected, key]
    }

    function toggleAll(items: T[] | null) {
        const keys = (items ?? []).map(rowKey)
        const allOn = keys.length > 0 && keys.every(k => selected.includes(k))
        selected = allOn
            ? selected.filter(k => !keys.includes(k))
            : [...new Set([...selected, ...keys])]
    }

    function headerCheckboxState(items: T[] | null) {
        const keys = (items ?? []).map(rowKey)
        const on = keys.filter(k => selected.includes(k)).length
        return {
            checked: keys.length > 0 && on === keys.length,
            indeterminate: on > 0 && on < keys.length,
        }
    }

    const DENSITY_SEGMENTS = [
        { value: 'comfortable' as const, label: 'Comfortable' },
        { value: 'dense' as const, label: 'Dense' },
    ]
</script>

<div class="wg-table-wrap {className}">
    <ItemList
        {load}
        bind:page
        {pageSize}
        {showSearch}
        {groupObject}
        {groupKey}
        bind:collapsedGroups
        {groupHeader}
        {empty}
    >
        {#snippet searchInput(value, setValue)}
            <Input
                label="Search"
                labelHidden
                type="search"
                placeholder={searchPlaceholder}
                {value}
                class="wg-table-search"
                oninput={e => setValue((e.target as HTMLInputElement).value)}
            />
        {/snippet}

        {#snippet header(items, groups)}
            <div class="wg-table-toolbar">
                {#if selectable && selected.length}
                    <span class="wg-table-count" aria-live="polite">
                        {selected.length}
                        selected
                    </span>
                {/if}
                {@render toolbar?.(items, groups)}
                {#if showDensityToggle}
                    <SegmentedControl
                        label="Row density"
                        size="compact"
                        segments={DENSITY_SEGMENTS}
                        bind:value={density}
                        class="wg-table-density"
                    />
                {/if}
            </div>
        {/snippet}

        {#snippet container(renderRows, items)}
            <div class="wg-table-scroll">
                <!-- Rationale in the component header: ARIA in HTML permits role=grid on <table>, and this is an interactive grid. -->
                <table
                    class="wg-table"
                    class:wg-table-dense={density === 'dense'}
                    role="grid"
                >
                    <caption class="wg-sr-only">
                        {caption}
                    </caption>
                    <thead>
                        <tr>
                            {#if selectable}
                                {@const state = headerCheckboxState(items)}
                                <th scope="col" class="wg-table-select-col">
                                    <Checkbox
                                        label="Select all rows"
                                        labelHidden
                                        checked={state.checked}
                                        indeterminate={state.indeterminate}
                                        onchange={() => toggleAll(items)}
                                    />
                                </th>
                            {/if}
                            {#each columns as column (column.key)}
                                <th
                                    scope="col"
                                    style:width={column.width}
                                    style:text-align={column.align === 'end'
                                        ? 'right'
                                        : undefined}
                                    aria-sort={ariaSort(column)}
                                    data-hide-below={column.hideBelow}
                                >
                                    {#if column.sortable}
                                        <button
                                            type="button"
                                            class="wg-table-sort"
                                            onclick={() => toggleSort(column)}
                                        >
                                            {column.label}
                                            <span
                                                class="wg-table-sort-icon"
                                                aria-hidden="true"
                                            >
                                                {#if sort?.key === column.key}
                                                    {sort.direction === 'asc' ? '▲' : '▼'}
                                                {:else}
                                                    <span
                                                        class="wg-table-sort-idle"
                                                        >▲</span
                                                    >
                                                {/if}
                                            </span>
                                        </button>
                                    {:else}
                                        {column.label}
                                    {/if}
                                </th>
                            {/each}
                        </tr>
                    </thead>
                    <tbody bind:this={tbody}>
                        {@render renderRows()}
                    </tbody>
                </table>
            </div>
        {/snippet}

        {#snippet item(entry)}
            {@const key = rowKey(entry)}
            <tr
                data-row
                data-row-key={key}
                tabindex={key === activeKey ? 0 : -1}
                aria-selected={selectable ? isSelected(entry) : undefined}
                class:wg-row-selected={selectable && isSelected(entry)}
                class:wg-row-activatable={!!onrowactivate}
                onkeydown={e => onRowKeydown(e, entry)}
                onfocus={() => (activeKey = key)}
                ondblclick={() => onrowactivate?.(entry)}
            >
                {#if selectable}
                    <td class="wg-table-select-col">
                        <Checkbox
                            label="Select row"
                            labelHidden
                            checked={isSelected(entry)}
                            onchange={() => toggleRow(entry)}
                        />
                    </td>
                {/if}
                {@render row(entry)}
            </tr>
        {/snippet}
    </ItemList>
</div>

<style>
    .wg-table-wrap {
        display: flex;
        flex-direction: column;
        min-width: 0;
    }

    .wg-table-toolbar {
        display: flex;
        align-items: center;
        gap: var(--wg-space-sm);
        margin-left: auto;
    }

    .wg-table-count {
        font: var(--wg-text-label-md);
        color: var(--wg-text-muted);
        font-variant-numeric: tabular-nums;
    }

    /* Only the table scrolls sideways; the page never does. */
    .wg-table-scroll {
        overflow-x: auto;
        border: var(--wg-border-width) solid var(--wg-border);
        border-radius: var(--wg-radius-panel);
    }

    .wg-table {
        width: 100%;
        border-collapse: separate;
        border-spacing: 0;
        /* DESIGN.md: data rows are square, separation is borders + striping */
        border-radius: var(--wg-radius-table);
        font: var(--wg-text-body-md);
        color: var(--wg-text);
    }

    :global(.wg-table thead th) {
        position: sticky;
        top: 0;
        z-index: 1;
        text-align: left;
        white-space: nowrap;
        padding: 0 var(--wg-space-md);
        height: var(--wg-row-height);
        background: var(--wg-surface-container);
        border-bottom: var(--wg-border-width) solid var(--wg-border);
        font: var(--wg-text-label-md);
        color: var(--wg-text-muted);
    }

    :global(.wg-table td) {
        padding: 0 var(--wg-space-md);
        height: var(--wg-row-height);
        border-bottom: var(--wg-border-width) solid var(--wg-border);
        font-variant-numeric: tabular-nums;
    }

    :global(.wg-table-dense th),
    :global(.wg-table-dense td) {
        height: var(--wg-row-height-dense);
    }

    :global(.wg-table tbody tr:last-child td) {
        border-bottom: 0;
    }

    :global(.wg-table tbody tr:nth-child(even)) {
        background: var(--wg-row-stripe);
    }

    :global(.wg-table tbody tr:hover) {
        background: var(--wg-row-hover);
    }

    :global(.wg-table tbody tr.wg-row-selected) {
        background: var(--wg-row-selected);
    }

    :global(.wg-table tbody tr.wg-row-activatable) {
        cursor: pointer;
    }

    :global(.wg-table tbody tr:focus-visible) {
        outline: var(--wg-focus-ring);
        /* Inset so the ring is not clipped by the scroll container */
        outline-offset: calc(-1 * var(--wg-focus-ring-width));
    }

    .wg-table-select-col {
        width: 2.5rem;
        padding-left: var(--wg-space-md);
    }

    .wg-table-sort {
        display: inline-flex;
        align-items: center;
        gap: var(--wg-space-xs);
        height: 100%;
        padding: 0;
        border: 0;
        background: none;
        color: inherit;
        font: inherit;
        cursor: pointer;
    }

    .wg-table-sort:hover {
        color: var(--wg-text);
    }

    .wg-table-sort:focus-visible {
        outline: var(--wg-focus-ring);
        outline-offset: var(--wg-focus-ring-offset);
    }

    .wg-table-sort-icon {
        font-size: 0.5rem;
        line-height: 1;
    }

    /* Idle arrow stays visible but quiet, so a sortable column is
     * discoverable without hovering every header to find out. */
    .wg-table-sort-idle {
        opacity: 0.35;
    }

    .wg-sr-only {
        position: absolute;
        width: 1px;
        height: 1px;
        padding: 0;
        margin: -1px;
        overflow: hidden;
        clip-path: inset(50%);
        white-space: nowrap;
        border: 0;
    }
</style>
