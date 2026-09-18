<script lang="ts">
    /**
     * Target groups — restyled in place.
     *
     * Behaviour preserved: natural sort by lowercased name, the colour icon
     * when a group has one, and Add gated on targetsCreate.
     */
    import { api, type TargetGroup } from 'admin/lib/api'
    import { adminPermissions } from 'admin/lib/store'
    import GroupColorIcon from 'common/GroupColorIcon.svelte'
    import ItemList, { type PaginatedResponse } from 'common/ItemList.svelte'
    import { compare as naturalCompareFactory } from 'natural-orderby'
    import { from, map, type Observable } from 'rxjs'
    import { link, push } from 'svelte-spa-router'
    import Button from 'ui/Button.svelte'
    import EmptyState from 'ui/EmptyState.svelte'
    import 'ui/layout.css'

    function getTargetGroups(): Observable<PaginatedResponse<TargetGroup>> {
        return from(api.listTargetGroups()).pipe(
            map(groups => {
                const natural = naturalCompareFactory()
                const sorted = groups.sort((a, b) =>
                    natural(a.name.toLowerCase(), b.name.toLowerCase()),
                )
                return { items: sorted, offset: 0, total: sorted.length }
            }),
        )
    }
</script>

<div class="wg-page-head">
    <h1>Target groups</h1>
    <Button
        variant="primary"
        size="compact"
        disabled={!$adminPermissions.targetsCreate}
        onclick={() => push('/config/target-groups/create')}
    >
        Add a group
    </Button>
</div>

<ItemList load={getTargetGroups} showSearch={true}>
    {#snippet container(rows)}
        <ul class="wg-rows">
            {@render rows()}
        </ul>
    {/snippet}
    {#snippet item(group)}
        <li>
            <a
                class="wg-row-link"
                href="/config/target-groups/{group.id}"
                use:link
            >
                <span class="group-text">
                    <span class="group-name">
                        {#if group.color}
                            <GroupColorIcon color={group.color} />
                        {/if}
                        <strong>{group.name}</strong>
                    </span>
                    {#if group.description}
                        <small>{group.description}</small>
                    {/if}
                </span>
            </a>
        </li>
    {/snippet}
    {#snippet empty()}
        <EmptyState
            title="No target groups yet"
            hint="Target groups organise your targets for easier management."
        />
    {/snippet}
</ItemList>

<style>
    .group-text {
        display: flex;
        flex-direction: column;
        gap: 2px;
        min-width: 0;
    }

    .group-name {
        display: flex;
        align-items: center;
        gap: var(--wg-space-sm);
    }

    .group-text small {
        color: var(--wg-text-muted);
        font: var(--wg-text-label-sm);
    }
</style>
