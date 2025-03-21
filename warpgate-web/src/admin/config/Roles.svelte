<script lang="ts">
    import { Observable, from, map } from 'rxjs'
    import { type Role, api } from 'admin/lib/api'
    import ItemList, { type LoadOptions, type PaginatedResponse } from 'common/ItemList.svelte'
    import { link } from 'svelte-spa-router'

    function getRoles (options: LoadOptions): Observable<PaginatedResponse<Role>> {
        return from(api.getRoles({
            search: options.search,
        })).pipe(map(targets => ({
            items: targets,
            offset: 0,
            total: targets.length,
        })))
    }
</script>

<div class="page-summary-bar">
    <h1>roles</h1>
    <a
        class="btn btn-primary ms-auto"
        href="/roles/create"
        use:link>
        Add a role
    </a>
</div>

<ItemList load={getRoles} showSearch={true}>
    {#snippet item(role)}
        <a
            class="list-group-item list-group-item-action"
            href="/roles/{role.id}"
            use:link>
            <div>
                <strong class="me-auto">
                    {role.name}
                </strong>
                {#if role.description}
                    <small class="d-block text-muted">{role.description}</small>
                {/if}
            </div>
        </a>
    {/snippet}
</ItemList>

<style lang="scss">
    .list-group-item {
        display: flex;
        align-items: center;
    }
</style>
