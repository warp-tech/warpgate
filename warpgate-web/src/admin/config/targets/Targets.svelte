<script lang="ts">
    import { Observable, from, map, combineLatest } from 'rxjs'
    import { type Target, type TargetGroup, api } from 'admin/lib/api'
    import ItemList, { type LoadOptions, type PaginatedResponse } from 'common/ItemList.svelte'
    import { link } from 'svelte-spa-router'
    import { TargetKind } from 'gateway/lib/api'
    import EmptyState from 'common/EmptyState.svelte'
    import { onMount } from 'svelte'
    import { Button, Dropdown, DropdownToggle, DropdownMenu, DropdownItem } from '@sveltestrap/sveltestrap'

    let groups: TargetGroup[] = $state([])
    let selectedGroupId: string | undefined = $state()
    let groupDropdownOpen = $state(false)

    onMount(async () => {
        try {
            groups = await api.listTargetGroups()
        } catch (e) {
            console.error('Failed to load target groups:', e)
        }
    })

    function getTargets (options: LoadOptions): Observable<PaginatedResponse<Target>> {
        return from(api.getTargets({
            search: options.search,
            groupId: selectedGroupId,
        })).pipe(map(targets => ({
            items: targets,
            offset: 0,
            total: targets.length,
        })))
    }

    function getGroupName(groupId: string | undefined): string {
        if (!groupId) return 'All groups'
        const group = groups.find(g => g.id === groupId)
        return group ? group.name : 'Unknown group'
    }

    function selectGroup(groupId: string | undefined) {
        selectedGroupId = groupId
        groupDropdownOpen = false
    }
</script>

<div class="container-max-md">
    <div class="page-summary-bar">
        <h1>targets</h1>
        <div class="d-flex gap-2 ms-auto">
            <Dropdown isOpen={groupDropdownOpen} toggle={() => groupDropdownOpen = !groupDropdownOpen}>
                <DropdownToggle caret>
                    {getGroupName(selectedGroupId)}
                </DropdownToggle>
                <DropdownMenu>
                    <DropdownItem onclick={() => selectGroup(undefined)}>
                        All groups
                    </DropdownItem>
                    {#each groups as group}
                        <DropdownItem onclick={() => selectGroup(group.id)}>
                            {#if group.color}
                                <span class="badge me-2" class:bg-primary={group.color === 'primary'} class:bg-secondary={group.color === 'secondary'} class:bg-success={group.color === 'success'} class:bg-danger={group.color === 'danger'} class:bg-warning={group.color === 'warning'} class:bg-info={group.color === 'info'} class:bg-light={group.color === 'light'} class:bg-dark={group.color === 'dark'}></span>
                            {/if}
                            {group.name}
                        </DropdownItem>
                    {/each}
                </DropdownMenu>
            </Dropdown>
            <a
                class="btn btn-primary"
                href="/config/targets/create"
                use:link>
                Add a target
            </a>
        </div>
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
                href="/config/targets/{target.id}"
                use:link>
                <div class="me-auto">
                    <div class="d-flex align-items-center">
                        {#if target.groupId}
                            {@const group = groups.find(g => g.id === target.groupId)}
                            {#if group}
                                {#if group.color}
                                    <span class="badge me-2" class:bg-primary={group.color === 'primary'} class:bg-secondary={group.color === 'secondary'} class:bg-success={group.color === 'success'} class:bg-danger={group.color === 'danger'} class:bg-warning={group.color === 'warning'} class:bg-info={group.color === 'info'} class:bg-light={group.color === 'light'} class:bg-dark={group.color === 'dark'}></span>
                                {/if}
                                <small class="text-muted me-2">{group.name}</small>
                            {/if}
                        {/if}
                        <strong>
                            {target.name}
                        </strong>
                    </div>
                    {#if target.description}
                        <small class="d-block text-muted">{target.description}</small>
                    {/if}
                </div>
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
</div>

<style lang="scss">
    .list-group-item {
        display: flex;
        align-items: center;
    }
</style>
