<script lang="ts" module>
    export interface PaletteEntity {
        id: string
        /** Primary searchable label. */
        label: string
        /** Secondary line — an address, a username, a timestamp. */
        detail?: string
        group: string
        href: string
        mono?: boolean
    }
</script>

<script lang="ts">
    import Badge from 'ui/Badge.svelte'
    import ConfirmDialog from 'ui/ConfirmDialog.svelte'
    /**
     * Command palette (Cmd/Ctrl+K).
     *
     * ARIA combobox pattern: the input owns focus for the whole interaction and
     * announces the active option through `aria-activedescendant`, so arrow
     * keys move a visual highlight without ever moving DOM focus off the field.
     * That is what lets the operator keep typing to narrow while navigating.
     *
     * Permission gating lives in shell/actions.ts and is applied before
     * anything reaches this component — actions the operator cannot perform are
     * absent, not disabled.
     *
     * Dangerous actions do not fire on Enter. They route through a typed-name
     * confirmation, because one Enter from a fuzzy match is the fastest
     * mis-click path in the product.
     */
    import { focusTrap, scrollLock } from 'ui/focusTrap'
    import type { PaletteAction } from './actions'
    import { fuzzyRank, highlightRuns, type Scored } from './fuzzy'

    interface Props {
        open?: boolean
        actions: PaletteAction[]
        /** Loaded lazily on first open; see shell/entities.ts. */
        entities?: PaletteEntity[]
        loading?: boolean
        onnavigate?: (href: string) => void
        onopen?: () => void
    }

    let {
        open = $bindable(false),
        actions,
        entities = [],
        loading = false,
        onnavigate,
        onopen,
    }: Props = $props()

    type Row =
        | { kind: 'action'; action: PaletteAction; indices: number[] }
        | { kind: 'entity'; entity: PaletteEntity; indices: number[] }

    let query = $state('')
    let activeIndex = $state(0)
    let input: HTMLInputElement | undefined = $state()
    let listEl: HTMLElement | undefined = $state()

    let pendingDangerous: PaletteAction | null = $state(null)
    let confirmOpen = $state(false)

    const id = 'wg-palette'

    const rankedActions = $derived(
        fuzzyRank(
            query,
            actions,
            a => [a.label, a.keywords ?? '', a.group],
            30,
        ) as Scored<PaletteAction>[],
    )

    const rankedEntities = $derived(
        fuzzyRank(
            query,
            entities,
            e => [e.label, e.detail ?? '', e.group],
            40,
        ) as Scored<PaletteEntity>[],
    )

    const rows: Row[] = $derived([
        ...rankedActions.map(
            r =>
                ({ kind: 'action', action: r.item, indices: r.indices }) as Row,
        ),
        ...rankedEntities.map(
            r =>
                ({ kind: 'entity', entity: r.item, indices: r.indices }) as Row,
        ),
    ])

    // Grouped for display while keeping one flat index for keyboard movement —
    // the operator moves through what they see, not through a nested model.
    const grouped = $derived.by(() => {
        const out: { group: string; rows: { row: Row; index: number }[] }[] = []
        rows.forEach((row, index) => {
            const group =
                row.kind === 'action' ? row.action.group : row.entity.group
            let bucket = out.find(b => b.group === group)
            if (!bucket) {
                bucket = { group, rows: [] }
                out.push(bucket)
            }
            bucket.rows.push({ row, index })
        })
        return out
    })

    $effect(() => {
        // Re-clamp whenever the result set changes under the cursor.
        void rows.length
        activeIndex = 0
    })

    $effect(() => {
        if (!open) {
            return
        }
        query = ''
        activeIndex = 0
        onopen?.()
        const lock = scrollLock()
        return () => lock.release()
    })

    // Keeps the highlighted row in view when arrowing past the fold.
    $effect(() => {
        if (!open || !listEl) {
            return
        }
        const el = listEl.querySelector<HTMLElement>(
            `#${id}-opt-${activeIndex}`,
        )
        el?.scrollIntoView({ block: 'nearest' })
    })

    function close() {
        open = false
    }

    /**
     * Named rather than inlined into <svelte:window>. In an inline handler the
     * `open` prop is indistinguishable from `window.open` to static analysis,
     * and a shorthand that reads as a global reassignment is worth avoiding in
     * a keyboard shortcut that fires on every keystroke in the app.
     */
    function onGlobalKeydown(event: KeyboardEvent) {
        if (
            (event.metaKey || event.ctrlKey) &&
            event.key.toLowerCase() === 'k'
        ) {
            event.preventDefault()
            open = !open
        }
    }

    function rowLabel(row: Row): string {
        return row.kind === 'action' ? row.action.label : row.entity.label
    }

    function choose(row: Row) {
        if (row.kind === 'action' && row.action.dangerous) {
            pendingDangerous = row.action
            confirmOpen = true
            return
        }
        commit(row)
    }

    function commit(row: Row) {
        const href = row.kind === 'action' ? row.action.href : row.entity.href
        const run = row.kind === 'action' ? row.action.run : undefined
        close()
        if (run) {
            run()
        } else if (href) {
            if (onnavigate) {
                onnavigate(href)
            } else {
                location.hash = href.replace(/^#/, '')
            }
        }
    }

    function confirmDangerous() {
        const action = pendingDangerous
        pendingDangerous = null
        if (!action) {
            return
        }
        close()
        if (action.run) {
            action.run()
        } else if (action.href) {
            if (onnavigate) {
                onnavigate(action.href)
            } else {
                location.hash = action.href.replace(/^#/, '')
            }
        }
    }

    function onkeydown(event: KeyboardEvent) {
        switch (event.key) {
            case 'Escape':
                event.preventDefault()
                close()
                break
            case 'ArrowDown':
                event.preventDefault()
                activeIndex = rows.length ? (activeIndex + 1) % rows.length : 0
                break
            case 'ArrowUp':
                event.preventDefault()
                activeIndex = rows.length
                    ? (activeIndex - 1 + rows.length) % rows.length
                    : 0
                break
            case 'Home':
                event.preventDefault()
                activeIndex = 0
                break
            case 'End':
                event.preventDefault()
                activeIndex = Math.max(0, rows.length - 1)
                break
            case 'Enter': {
                event.preventDefault()
                const row = rows[activeIndex]
                if (row) {
                    choose(row)
                }
                break
            }
        }
    }
</script>

<svelte:window on:keydown={onGlobalKeydown} />

{#if open}
    <div
        class="wg-palette-scrim"
        data-wg-overlay
        onclick={close}
        aria-hidden="true"
    ></div>

    <div
        class="wg-palette"
        role="dialog"
        aria-modal="true"
        aria-label="Command palette"
        tabindex="-1"
        use:focusTrap
    >
        <div class="wg-palette-search">
            <svg viewBox="0 0 16 16" width="15" height="15" aria-hidden="true">
                <circle
                    cx="7"
                    cy="7"
                    r="4.5"
                    fill="none"
                    stroke="currentColor"
                    stroke-width="1.5"
                />
                <path
                    d="M10.5 10.5L14 14"
                    stroke="currentColor"
                    stroke-width="1.5"
                    stroke-linecap="round"
                />
            </svg>
            <input
                bind:this={input}
                bind:value={query}
                data-autofocus
                type="text"
                role="combobox"
                aria-expanded="true"
                aria-controls="{id}-list"
                aria-activedescendant={rows.length
                    ? `${id}-opt-${activeIndex}`
                    : undefined}
                aria-label="Search targets, users, sessions and commands"
                placeholder="Search targets, users, sessions and commands…"
                autocomplete="off"
                spellcheck="false"
                {onkeydown}
            >
            <kbd>esc</kbd>
        </div>

        <div bind:this={listEl} class="wg-palette-results">
            {#if loading && !rows.length}
                <p class="wg-palette-empty">Loading…</p>
            {:else if !rows.length}
                <p class="wg-palette-empty">
                    Nothing matches <strong>{query}</strong>
                </p>
            {:else}
                <ul id="{id}-list" role="listbox" aria-label="Results">
                    {#each grouped as bucket (bucket.group)}
                        <li class="wg-palette-group" role="presentation">
                            {bucket.group}
                        </li>
                        {#each bucket.rows as { row, index } (index)}
                            <!--
                              The keyboard handler for these options is on the
                              input, not here. In the ARIA combobox pattern the
                              input keeps focus for the whole interaction and
                              announces the active option through
                              aria-activedescendant — that is what lets the
                              operator keep typing to narrow while arrowing
                              through results. Options must NOT be individually
                              focusable, so they cannot be buttons, and a
                              keydown here would never fire.
                            -->
                            <!-- svelte-ignore a11y_click_events_have_key_events -->
                            <li
                                id="{id}-opt-{index}"
                                role="option"
                                tabindex="-1"
                                aria-selected={index === activeIndex}
                                class="wg-palette-row"
                                class:wg-palette-active={index === activeIndex}
                                onclick={() => choose(row)}
                                onmousemove={() => (activeIndex = index)}
                            >
                                <span
                                    class="wg-palette-label"
                                    class:wg-palette-mono={row.kind === 'entity' &&
                                        row.entity.mono}
                                >
                                    {#each highlightRuns(rowLabel(row), row.indices) as run, i (i)}
                                        {#if run.match}
                                            <mark>{run.text}</mark>
                                        {:else}
                                            {run.text}
                                        {/if}
                                    {/each}
                                </span>
                                {#if row.kind === 'entity' && row.entity.detail}
                                    <span class="wg-palette-detail">
                                        {row.entity.detail}
                                    </span>
                                {/if}
                                {#if row.kind === 'action' && row.action.dangerous}
                                    <Badge tone="danger">Confirms</Badge>
                                {/if}
                            </li>
                        {/each}
                    {/each}
                </ul>
            {/if}
        </div>

        <div class="wg-palette-foot">
            <span><kbd>↑</kbd><kbd>↓</kbd> move</span>
            <span><kbd>↵</kbd> open</span>
            <span><kbd>esc</kbd> close</span>
        </div>
    </div>
{/if}

{#if pendingDangerous}
    <ConfirmDialog
        bind:open={confirmOpen}
        title={pendingDangerous.label}
        confirmLabel={pendingDangerous.label}
        confirmText={pendingDangerous.label}
        confirmTextLabel="action name"
        onconfirm={confirmDangerous}
        oncancel={() => (pendingDangerous = null)}
    >
        <p>
            This action changes who can administer Warpgate. It was reached from
            the command palette, so it asks you to type its name before
            continuing.
        </p>
    </ConfirmDialog>
{/if}

<style>
    .wg-palette-scrim {
        position: fixed;
        inset: 0;
        background: rgb(0 0 0 / 0.6);
        z-index: 1200;
    }

    .wg-palette {
        position: fixed;
        top: 12vh;
        left: 50%;
        transform: translateX(-50%);
        z-index: 1201;
        display: flex;
        flex-direction: column;
        width: min(100vw - 2 * var(--wg-space-lg), 40rem);
        max-height: 70vh;
        background: var(--wg-surface-container);
        border: var(--wg-border-width) solid var(--wg-border-strong);
        border-radius: var(--wg-radius-panel);
        box-shadow: var(--wg-shadow-overlay);
        color: var(--wg-text);
        overflow: hidden;
    }

    .wg-palette-search {
        display: flex;
        align-items: center;
        gap: var(--wg-space-sm);
        flex: none;
        padding: 0 var(--wg-space-md);
        height: 3rem;
        border-bottom: var(--wg-border-width) solid var(--wg-border);
        color: var(--wg-text-subtle);
    }

    .wg-palette-search input {
        flex: 1 1 auto;
        min-width: 0;
        height: 100%;
        border: 0;
        background: none;
        color: var(--wg-text);
        font: var(--wg-text-body-lg);
    }

    .wg-palette-search input:focus {
        outline: none;
    }

    .wg-palette-search input::placeholder {
        color: var(--wg-text-subtle);
    }

    .wg-palette-results {
        flex: 1 1 auto;
        overflow-y: auto;
        padding: var(--wg-space-xs) 0;
    }

    ul {
        list-style: none;
        margin: 0;
        padding: 0;
    }

    .wg-palette-group {
        padding: var(--wg-space-sm) var(--wg-space-md) var(--wg-space-xs);
        font: var(--wg-text-label-sm);
        color: var(--wg-text-subtle);
    }

    .wg-palette-row {
        display: flex;
        align-items: center;
        gap: var(--wg-space-sm);
        padding: 0 var(--wg-space-md);
        height: var(--wg-row-height);
        cursor: pointer;
        font: var(--wg-text-body-md);
    }

    .wg-palette-active {
        background: var(--wg-row-hover);
        /* A 2px primary edge, so the active row is identifiable without
         * relying on the background tone alone. */
        box-shadow: inset 2px 0 0 var(--wg-primary);
    }

    .wg-palette-label {
        flex: none;
        max-width: 60%;
        overflow: hidden;
        text-overflow: ellipsis;
        white-space: nowrap;
    }

    .wg-palette-mono {
        font-family: var(--wg-font-mono);
    }

    mark {
        background: none;
        color: var(--wg-primary);
        font-weight: 600;
    }

    .wg-palette-detail {
        flex: 1 1 auto;
        min-width: 0;
        overflow: hidden;
        text-overflow: ellipsis;
        white-space: nowrap;
        font: var(--wg-text-code-sm);
        color: var(--wg-text-muted);
    }

    .wg-palette-empty {
        margin: 0;
        padding: var(--wg-space-xl) var(--wg-space-md);
        text-align: center;
        color: var(--wg-text-muted);
        font: var(--wg-text-body-md);
    }

    .wg-palette-foot {
        display: flex;
        gap: var(--wg-space-lg);
        flex: none;
        padding: var(--wg-space-sm) var(--wg-space-md);
        border-top: var(--wg-border-width) solid var(--wg-border);
        font: var(--wg-text-label-sm);
        color: var(--wg-text-subtle);
    }

    kbd {
        display: inline-block;
        min-width: 1.25rem;
        padding: 0 var(--wg-space-xs);
        border: var(--wg-border-width) solid var(--wg-border);
        border-radius: var(--wg-radius-sm);
        background: var(--wg-surface-container-high);
        font: var(--wg-text-code-sm);
        text-align: center;
        margin-right: 2px;
    }
</style>
