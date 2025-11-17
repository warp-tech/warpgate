<script lang="ts">
    import { Observable, from, map, catchError, of } from 'rxjs'
    import { type TargetGroup, api } from 'admin/lib/api'
    import ItemList, { type LoadOptions, type PaginatedResponse } from 'common/ItemList.svelte'
    import { link } from 'svelte-spa-router'
    import EmptyState from 'common/EmptyState.svelte'

    function getTargetGroups (options: LoadOptions): Observable<PaginatedResponse<TargetGroup>> {
        return from(api.listTargetGroups()).pipe(
            map(groups => ({
                items: groups,
                offset: 0,
                total: groups.length,
            })),
            catchError(error => {
                console.error('Failed to load target groups:', error)
                return of({
                    items: [],
                    offset: 0,
                    total: 0,
                })
            })
        )
    }

    function getColorStyle(color: string | null | undefined): string {
        if (!color) return ''
        // Handle capitalized color names from API (e.g., "Primary" -> "primary")
        const colorLower = color.toLowerCase()
        const validColors = ['primary', 'secondary', 'success', 'danger', 'warning', 'info', 'light', 'dark']
        if (validColors.includes(colorLower)) {
            return `background-color: var(--bs-${colorLower});`
        }
        return ''
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
                    <div class="d-flex align-items-center">
                        {#if group.color}
                            <span class="color-circle me-2" style={getColorStyle(group.color)}></span>
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

    .color-circle {
        display: inline-block;
        width: 12px;
        height: 12px;
        border-radius: 50%;
        flex-shrink: 0;
    }
</style>
