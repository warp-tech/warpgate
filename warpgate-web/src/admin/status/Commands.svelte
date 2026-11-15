<script lang="ts">
    import { api, type CommandEntry } from 'admin/lib/api'
    import ItemList, {
        type Column,
        type LoadOptions,
        type PaginatedResponse,
    } from 'common/ItemList.svelte'
    import { from, type Observable } from 'rxjs'
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
        { id: 'time', label: 'Time', cell: timeCell },
        { id: 'name', label: 'Name', cell: nameCell },
        {
            id: 'command',
            label: 'Command',
            cell: commandCell,
            grow: true,
            class: 'text-truncate',
        },
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
{#snippet commandCell(entry: CommandEntry)}
    <code>{entry.command}</code>
{/snippet}

<PermissionGate
    perm="sessionsView"
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
</style>
