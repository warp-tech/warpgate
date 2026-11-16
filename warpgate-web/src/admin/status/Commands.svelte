<script lang="ts">
    import { faTerminal } from '@fortawesome/free-solid-svg-icons'
    import { api, type CommandEntry } from 'admin/lib/api'
    import ItemList, {
        type Column,
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
    {#if entry.userSessionId}
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
        {#snippet header(items)}
            {#if items?.length}
                <div class="commands-header">
                    <div class="commands-time">Time</div>
                    <div class="commands-name">Name</div>
                    <div class="commands-target">Target</div>
                    <div>Command</div>
                    <div class="commands-open"></div>
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
    // right edge.
    :global(.commands-open) {
        text-align: right;
        white-space: nowrap;
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
        grid-template-columns: auto auto auto minmax(0, 1fr) auto;
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
