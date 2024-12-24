<script lang="ts">
    import { Observable, from, map } from 'rxjs'
    import { type Target, api } from 'admin/lib/api'
    import ItemList, { type LoadOptions, type PaginatedResponse } from 'common/ItemList.svelte'
    import { link } from 'svelte-spa-router'
    import { TargetKind } from 'gateway/lib/api'
    import EmptyState from 'common/EmptyState.svelte';

    function getTargets (options: LoadOptions): Observable<PaginatedResponse<Target>> {
        return from(api.getTargets({
            search: options.search,
        })).pipe(map(targets => ({
            items: targets,
            offset: 0,
            total: targets.length,
        })))
    }
</script>

<div class="page-summary-bar">
    <h1>targets</h1>
    <a
        class="btn btn-primary ms-auto"
        href="/targets/create"
        use:link>
        Add a target
    </a>
</div>

<ItemList load={getTargets} showSearch={true}>
    {#snippet empty()}
        <EmptyState
            title="No targets yet"
            hint="Targets are destinations on the internal network that your users will connect to"
        />
    {/snippet}
    {#snippet item(target)}
        <a
            class="list-group-item list-group-item-action"
            class:disabled={target.options.kind === TargetKind.WebAdmin}
            href="/targets/{target.id}"
            use:link>
            <strong class="me-auto">
                {target.name}
            </strong>
            <small class="text-muted ms-auto">
                {#if target.options.kind === TargetKind.Http}
                    HTTP
                {/if}
                {#if target.options.kind === TargetKind.MySql}
                    MySQL
                {/if}
                {#if target.options.kind === TargetKind.Postgres}
                    PostgreSQL
                {/if}
                {#if target.options.kind === TargetKind.Ssh}
                    SSH
                {/if}
                {#if target.options.kind === TargetKind.WebAdmin}
                    This web admin interface
                {/if}
            </small>
        </a>
            {/snippet}
</ItemList>

<style lang="scss">
    .list-group-item {
        display: flex;
        align-items: center;
    }
</style>
