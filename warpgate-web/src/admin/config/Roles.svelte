<script lang="ts">
    import { Observable, from, map } from 'rxjs'
    import { type Role, api } from 'admin/lib/api'
    import ItemList, { type LoadOptions, type PaginatedResponse } from 'common/ItemList.svelte'
    import { link } from 'svelte-spa-router'
    import { compare as naturalCompareFactory } from 'natural-orderby'

    function getRoles(options: LoadOptions): Observable<PaginatedResponse<Role>> {
        return from(
            api.getRoles({
                search: options.search,
            })
        ).pipe(
            map(roles => {
                const sorted = roles.sort((a, b) =>
                    naturalCompareFactory()(
                        a.name.toLowerCase(),
                        b.name.toLowerCase()
                    )
                )

                return {
                    items: sorted,
                    offset: 0,
                    total: sorted.length,
                }
            })
        )
    }
</script>

<div class="container-max-md">
    <div class="page-summary-bar">
        <h1>roles</h1>
        <a
            class="btn btn-primary ms-auto"
            href="/config/roles/create"
            use:link>
            Add a role
        </a>
    </div>

    <ItemList load={getRoles} showSearch={true}>
        {#snippet item(role)}
            <a
                class="list-group-item list-group-item-action"
                href="/config/roles/{role.id}"
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
</div>

<style lang="scss">
    .list-group-item {
        display: flex;
        align-items: center;
    }
</style>
