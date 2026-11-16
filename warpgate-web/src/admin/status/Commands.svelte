<script lang="ts">
    import { faTerminal } from '@fortawesome/free-solid-svg-icons'
    import { api, type CommandEntry } from 'admin/lib/api'
    import { adminPermissions } from 'admin/lib/store'
    import ItemList, {
        type Column,
        type ColumnControls,
        type LoadOptions,
        type PaginatedResponse,
    } from 'common/ItemList.svelte'
    import { from, type Observable } from 'rxjs'
    import Fa from 'svelte-fa'
    import { link } from 'svelte-spa-router'
    import PermissionGate from '../lib/PermissionGate.svelte'

    function getCommands(
        options: LoadOptions,
    ): Observable<PaginatedResponse<CommandEntry>> {
        return from(
            api.getCommands({
                getCommandsRequest: {
                    search: options.search,
                    offset: options.offset,
                    limit: options.limit,
                },
            }),
        )
    }

    const columns: Column<CommandEntry>[] = [
        { id: 'time', label: 'Time', cell: timeCell, class: 'commands-time' },
        { id: 'name', label: 'Name', cell: nameCell, class: 'commands-name' },
        {
            id: 'target',
            label: 'Target',
            cell: targetCell,
            class: 'commands-target',
        },
        {
            id: 'command',
            label: 'Command',
            cell: commandCell,
            grow: true,
            class: 'text-truncate',
        },
        // No label: the action is always shown, never listed among the
        // toggleable columns.
        { id: 'open', cell: openCell, class: 'commands-open' },
    ]

    // The body's grid template comes from the enabled columns, so the header
    // has to follow the same rule or a column toggle desynchronises the two:
    // hidden toggleable columns drop out, and if no remaining column grows the
    // first one does (ItemList's fallback).
    function headerColumns(controls: ColumnControls) {
        const shown = columns.filter(column => {
            const toggle = controls.toggleable.find(c => c.id === column.id)
            return toggle ? toggle.shown : true
        })
        const fallbackGrow = !shown.some(column => column.grow)
        return shown.map((column, i) => ({
            ...column,
            grow: column.grow || (fallbackGrow && i === 0),
        }))
    }

    function headerTemplate(controls: ColumnControls) {
        return headerColumns(controls)
            .map(column => (column.grow ? 'minmax(0, 1fr)' : 'auto'))
            .join(' ')
    }
</script>

{#snippet timeCell(entry: CommandEntry)}
    <div class="meta" title={entry.timestamp.toISOString()}>
        {entry.timestamp.toLocaleString()}
    </div>
{/snippet}
{#snippet nameCell(entry: CommandEntry)}
    {#if entry.username}
        <strong>{entry.username}</strong>
    {:else}
        <span class="text-muted">&lt;unknown&gt;</span>
    {/if}
{/snippet}
{#snippet targetCell(entry: CommandEntry)}
    {#if entry.targetName}
        {entry.targetName}
    {:else}
        <span class="text-muted">—</span>
    {/if}
{/snippet}
{#snippet commandCell(entry: CommandEntry)}
    <code>{entry.command}</code>
{/snippet}
{#snippet openCell(entry: CommandEntry)}
    <!-- The session page itself requires sessionsView; without it the button
         would only lead to a permission error page. -->
    {#if entry.userSessionId && $adminPermissions.sessionsView}
        <a
            class="btn btn-sm btn-outline-secondary"
            href="#/status/sessions/{entry.userSessionId}"
            aria-label="Open session"
            title="Open session"
            use:link
        >
            <Fa icon={faTerminal} />
        </a>
    {/if}
{/snippet}

<PermissionGate
    perm="shellCommandsView"
    message="You have no permission to view shell commands."
>
    <div class="page-summary-bar">
        <h1>commands</h1>
    </div>

    <ItemList
        load={getCommands}
        pageSize={100}
        {columns}
        storageKey="admin-commands"
        showSearch={true}
    >
        {#snippet header(items, _groupControls, columnControls)}
            {#if items?.length}
                <div
                    class="commands-header"
                    style:grid-template-columns={headerTemplate(columnControls)}
                >
                    {#each headerColumns(columnControls) as column (column.id)}
                        <div class={column.class ?? ''}>
                            {column.label ?? ''}
                        </div>
                    {/each}
                </div>
            {/if}
        {/snippet}

        {#snippet item(entry, cells)}
            <div class="list-group-item">
                {@render cells(entry)}
            </div>
        {/snippet}
    </ItemList>
</PermissionGate>

<style lang="scss">
    .list-group-item {
        .meta {
            opacity: .75;
            font-size: .75rem;
            white-space: nowrap;
        }
    }

    // Explicit widths keep the three auto tracks of ItemList's grid (and the
    // matching ones below) from growing with the widest cell's content.
    :global(.commands-time) {
        width: 13rem;
        white-space: nowrap;
    }

    :global(.commands-name) {
        width: 9rem;
        overflow: hidden;
        text-overflow: ellipsis;
        white-space: nowrap;
    }

    :global(.commands-target) {
        width: 10rem;
        overflow: hidden;
        text-overflow: ellipsis;
        white-space: nowrap;
    }

    // Trailing action column: as narrow as its button, flush with the list's
    // right edge. The min width pins the track to the button's box
    // (2 * .5rem padding + 1.125em terminal icon at .875rem + 2px border)
    // plus this cell's 1rem gap, so the header's empty cell and the body's
    // button occupy the same track.
    :global(.commands-open) {
        min-inline-size: calc(1rem + 2.125rem);
        text-align: right;
        white-space: nowrap;
    }

    :global(.commands-open .btn) {
        min-inline-size: 2.125rem;
    }

    // The list drops the header snippet into the flex row that also holds the
    // search input; wrapping gives the header a line of its own above the list.
    :global(.d-flex:has(> .commands-header)) {
        flex-wrap: wrap;
    }

    .commands-header {
        flex: 1 1 auto;
        width: 100%;
        display: grid;
        align-items: center;
        padding-inline: var(--bs-list-group-item-padding-x);
        padding-block-end: .25rem;
        color: var(--bs-secondary-color);
        font-size: .75rem;

        // Matches the spacing ItemList puts on a row's non-first cells.
        > :not(:first-child) {
            padding-inline-start: 1rem;
        }
    }
</style>
