<script lang="ts">
    import { Observable, from, map } from 'rxjs'
    import { Role, Target, User, api } from 'admin/lib/api'
    import ItemList, { LoadOptions, PaginatedResponse } from 'common/ItemList.svelte'
    import { link } from 'svelte-spa-router'

    function getTargets (options: LoadOptions): Observable<PaginatedResponse<Target>> {
        return from(api.getTargets({
            search: options.search,
        })).pipe(map(targets => ({
            items: targets,
            offset: 0,
            total: targets.length,
        })))
    }

    function getUsers (options: LoadOptions): Observable<PaginatedResponse<User>> {
        return from(api.getUsers({
            search: options.search,
        })).pipe(map(targets => ({
            items: targets,
            offset: 0,
            total: targets.length,
        })))
    }

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

<div class="row">
    <div class="col-12 col-lg-6 mb-4 pe-4">
        <div class="page-summary-bar">
            <h1>Targets</h1>
            <a
                class="btn btn-outline-secondary ms-auto"
                href="/targets/create"
                use:link>
                Add a target
            </a>
        </div>

        <ItemList load={getTargets} showSearch={true}>
            <!-- svelte-ignore a11y-missing-attribute -->
            <a
                slot="item" let:item={target}
                class="list-group-item list-group-item-action"
                href="/targets/{target.id}"
                use:link>
                <strong class="me-auto">
                    {target.name}
                </strong>
                <small class="text-muted ms-auto">
                    {#if target.options.kind === 'Http'}
                        HTTP
                    {/if}
                    {#if target.options.kind === 'MySql'}
                        MySQL
                    {/if}
                    {#if target.options.kind === 'Ssh'}
                        SSH
                    {/if}
                    {#if target.options.kind === 'WebAdmin'}
                        This web admin interface
                    {/if}
                </small>
            </a>
        </ItemList>
    </div>

    <div class="col-12 col-lg-6 pe-4">
        <div class="page-summary-bar">
            <h1>Users</h1>
            <a
                class="btn btn-outline-secondary ms-auto"
                href="/users/create"
                use:link>
                Add a user
            </a>
        </div>

        <ItemList load={getUsers} showSearch={true}>
            <!-- svelte-ignore a11y-missing-attribute -->
            <a
                slot="item" let:item={user}
                class="list-group-item list-group-item-action"
                href="/users/{user.id}"
                use:link>
                <strong class="me-auto">
                    {user.username}
                </strong>
            </a>
        </ItemList>

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
            <!-- svelte-ignore a11y-missing-attribute -->
            <a
                slot="item" let:item={role}
                class="list-group-item list-group-item-action"
                href="/roles/{role.id}"
                use:link>
                <strong class="me-auto">
                    {role.name}
                </strong>
            </a>
        </ItemList>
    </div>
</div>

<style lang="scss">
    .list-group-item {
        display: flex;
        align-items: center;
    }
</style>
