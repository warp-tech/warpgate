<script lang="ts">
    import { Observable, from, map } from 'rxjs'
    import { type User, api } from 'admin/lib/api'
    import ItemList, { type LoadOptions, type PaginatedResponse } from 'common/ItemList.svelte'
    import { link } from 'svelte-spa-router'

    function getUsers (options: LoadOptions): Observable<PaginatedResponse<User>> {
        return from(api.getUsers({
            search: options.search,
        })).pipe(map(targets => ({
            items: targets,
            offset: 0,
            total: targets.length,
        })))
    }
</script>

<div class="container-max-md">
    <div class="page-summary-bar">
        <h1>users</h1>
        <a
            class="btn btn-primary ms-auto"
            href="/config/users/create"
            use:link>
            Add a user
        </a>
    </div>

    <ItemList load={getUsers} showSearch={true}>
        {#snippet item(user)}
            <a
                class="list-group-item list-group-item-action"
                href="/config/users/{user.id}"
                use:link>
                <div>
                    <strong class="me-auto">
                        {user.username}
                    </strong>
                    {#if user.description}
                        <small class="d-block text-muted">{user.description}</small>
                    {/if}
                </div>
            </a>
        {/snippet}
    </ItemList>
</div>

<style lang="scss">
    .list-group-item {
        display: flex;
        align-items: center;
    }
</style>
