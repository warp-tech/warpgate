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


<div class="page-summary-bar mt-4">
    <h1>Roles</h1>
    <a
        class="btn btn-outline-secondary ms-auto"
        href="/roles/create"
        use:link>
        Add a role
    </a>
</div>

<ItemList load={getRoles} showSearch={true}>
    {#snippet item({ item: role })}
        <a
            class="list-group-item list-group-item-action"
            href="/roles/{role.id}"
            use:link>
            <strong class="me-auto">
                {role.name}
            </strong>
        </a>
    {/snippet}
</ItemList>

<style lang="scss">
    .list-group-item {
        display: flex;
        align-items: center;
    }
</style>
