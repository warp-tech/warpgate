<script lang="ts">
    import { Observable, from, map } from 'rxjs'
    import { type TargetGroup, api } from 'admin/lib/api'
    import ItemList, { type PaginatedResponse } from 'common/ItemList.svelte'
    import { link } from 'svelte-spa-router'
    import EmptyState from 'common/EmptyState.svelte'
    import GroupColorCircle from 'common/GroupColorCircle.svelte'
    import { compare as naturalCompareFactory } from 'natural-orderby'

    function getTargetGroups(): Observable<PaginatedResponse<TargetGroup>> {
        return from(api.listTargetGroups()).pipe(
            map(groups => {
                const sorted = groups.sort((a, b) =>
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
        <h1>target groups</h1>
        <a
            class="btn btn-primary ms-auto"
            href="/config/target-groups/create"
            use:link>
            Add a group
        </a>
    </div>

    <ItemList load={getTargetGroups} showSearch={true}>
        {#snippet empty()}
            <EmptyState
                title="No target groups yet"
                hint="Target groups help organize your targets for easier management"
            />
        {/snippet}
        {#snippet item(group)}
            <a
                class="list-group-item list-group-item-action"
                href="/config/target-groups/{group.id}"
                use:link>
                <div class="me-auto">
                    <div class="d-flex align-items-center gap-2">
                        {#if group.color}
                            <GroupColorCircle color={group.color} />
                        {/if}
                        <strong>{group.name}</strong>
                    </div>
                    {#if group.description}
                        <small class="d-block text-muted">{group.description}</small>
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
