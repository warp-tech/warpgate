<script lang="ts">
    import { api, type TargetGroup } from 'admin/lib/api'
    import { adminPermissions } from 'admin/lib/store'
    import EmptyState from 'common/EmptyState.svelte'
    import GroupColorIcon from 'common/GroupColorIcon.svelte'
    import ItemList, {
        type Column,
        type LoadOptions,
        type PaginatedResponse,
    } from 'common/ItemList.svelte'
    import ListOverflowMenu from 'common/ListOverflowMenu.svelte'
    import { compare as naturalCompareFactory } from 'natural-orderby'
    import { from, map, type Observable } from 'rxjs'
    import { link } from 'svelte-spa-router'

    function getTargetGroups(
        options: LoadOptions,
    ): Observable<PaginatedResponse<TargetGroup>> {
        // The API has no search parameter, so the search box filters here.
        const search = options.search?.toLowerCase()
        return from(api.listTargetGroups()).pipe(
            map(groups => {
                const matching = search
                    ? groups.filter(g => g.name.toLowerCase().includes(search))
                    : groups
                const sorted = matching.sort((a, b) =>
                    naturalCompareFactory()(
                        a.name.toLowerCase(),
                        b.name.toLowerCase(),
                    ),
                )

                return {
                    items: sorted,
                    offset: 0,
                    total: sorted.length,
                }
            }),
        )
    }

    const columns: Column<TargetGroup>[] = [
        { id: 'icon', cell: iconCell },
        { id: 'name', cell: nameCell },
        {
            id: 'description',
            label: 'Description',
            cell: descriptionCell,
            grow: true,
            class: 'text-truncate text-muted small',
        },
    ]
</script>

{#snippet iconCell(group: TargetGroup)}
    {#if group.color}
        <GroupColorIcon color={group.color} />
    {/if}
{/snippet}
{#snippet nameCell(group: TargetGroup)}
    <strong>{group.name}</strong>
{/snippet}
{#snippet descriptionCell(group: TargetGroup)}
    <small class="d-block text-muted">
        {group.description}
    </small>
{/snippet}

<div class="container-max-md">
    <div class="page-summary-bar">
        <h1>target groups</h1>
        <a
            class="btn btn-primary ms-auto"
            href="/manage/target-groups/create"
            class:disabled={!$adminPermissions.targetsCreate}
            use:link
        >
            Add a group
        </a>
    </div>

    <ItemList
        load={getTargetGroups}
        showSearch={true}
        {columns}
        storageKey="admin-target-groups"
    >
        {#snippet empty()}
            <EmptyState
                title="No target groups yet"
                hint="Target groups help organize your targets for easier management"
            />
        {/snippet}
        {#snippet header(_items, groupControls, columnControls)}
            <ListOverflowMenu {groupControls} {columnControls} />
        {/snippet}
        {#snippet item(group, cells)}
            <a
                class="list-group-item list-group-item-action"
                href="/manage/target-groups/{group.id}"
                use:link
            >
                {@render cells(group)}
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
