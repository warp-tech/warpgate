<script lang="ts">
    import { faEllipsisV } from '@fortawesome/free-solid-svg-icons'
    import {
        Alert,
        Dropdown,
        DropdownItem,
        DropdownMenu,
        DropdownToggle,
    } from '@sveltestrap/sveltestrap'
    import { api, type Target, type TargetGroup } from 'admin/lib/api'
    import { autosave } from 'common/autosave'
    import CollapsibleGroupHeader from 'common/CollapsibleGroupHeader.svelte'
    import EmptyState from 'common/EmptyState.svelte'
    import { stringifyError } from 'common/errors'
    import GroupColorCircle from 'common/GroupColorCircle.svelte'
    import ItemList, {
        type LoadOptions,
        type PaginatedResponse,
    } from 'common/ItemList.svelte'
    import { BootstrapThemeColor, TargetKind } from 'gateway/lib/api'
    import { compare as naturalCompareFactory } from 'natural-orderby'
    import { from, map, type Observable } from 'rxjs'
    import { onMount } from 'svelte'
    import Fa from 'svelte-fa'
    import { link } from 'svelte-spa-router'
    import { firstBy } from 'thenby'
    import { adminPermissions } from '../../lib/store'

    let error: string | undefined = $state()
    let groups: TargetGroup[] = $state([])
    let selectedGroup: TargetGroup | undefined = $state()

    const [collapsedGroups] = autosave<string[]>(
        'admin-target-list:collapsed-groups',
        [],
    )

    // The group headers make the group ordering load-bearing, so the target
    // list has to wait for the groups instead of racing them.
    const groupsPromise = api.listTargetGroups().then(result => {
        const natural = naturalCompareFactory()
        return result.sort((a, b) =>
            natural(a.name.toLowerCase(), b.name.toLowerCase()),
        )
    })

    onMount(async () => {
        try {
            groups = await groupsPromise
        } catch (err) {
            error = await stringifyError(err)
        }
    })

    function getTargets(
        options: LoadOptions,
    ): Observable<PaginatedResponse<Target>> {
        return from(
            Promise.all([
                // Errors are surfaced by the onMount handler above - here we
                // just fall back to an unresolved grouping.
                groupsPromise.catch(() => [] as TargetGroup[]),
                api.getTargets({
                    search: options.search,
                    groupId: selectedGroup?.id,
                }),
            ]),
        ).pipe(
            map(([targetGroups, targets]) => {
                const natural = naturalCompareFactory()
                const groupName = (target: Target) =>
                    (
                        targetGroups.find(g => g.id === target.groupId)?.name ??
                        ''
                    ).toLowerCase()

                return targets.sort(
                    firstBy((x: Target) => !x.groupId)
                        // Natural sort between groups
                        .thenBy((a: Target, b: Target) =>
                            natural(groupName(a), groupName(b)),
                        )
                        // Natural sort within a group
                        .thenBy((a, b) =>
                            natural(a.name.toLowerCase(), b.name.toLowerCase()),
                        ),
                )
            }),
            map(targets => ({
                items: targets,
                offset: 0,
                total: targets.length,
            })),
        )
    }

    interface GroupInfo {
        id: string
        name: string
        color: BootstrapThemeColor
    }

    function groupInfoFromTarget(target: Target): GroupInfo {
        const group = target.groupId
            ? groups.find(g => g.id === target.groupId)
            : undefined
        if (!group) {
            return {
                id: '$ungrouped',
                name: 'Ungrouped',
                color: BootstrapThemeColor.Secondary,
            }
        }
        return {
            id: group.id,
            name: group.name,
            color: group.color ?? BootstrapThemeColor.Secondary,
        }
    }

    function collapseAllGroups(targets: Target[] | null) {
        $collapsedGroups = [
            ...new Set((targets ?? []).map(x => groupInfoFromTarget(x).id)),
        ]
    }
</script>

<div class="container-max-md">
    <div class="page-summary-bar">
        <h1>targets</h1>
        <div class="d-flex gap-2 ms-auto">
            {#if groups.length > 0}
                <Dropdown>
                    <DropdownToggle caret>
                        {selectedGroup?.name ?? 'All groups'}
                    </DropdownToggle>
                    <DropdownMenu>
                        <DropdownItem
                            onclick={() => {
                                selectedGroup = undefined
                            }}
                        >
                            All groups
                        </DropdownItem>
                        {#each groups as group (group.id)}
                            <DropdownItem
                                onclick={() => {
                                    selectedGroup = group
                                }}
                                class="d-flex align-items-center gap-2"
                            >
                                {#if group.color}
                                    <GroupColorCircle color={group.color} />
                                {/if}
                                {group.name}
                            </DropdownItem>
                        {/each}
                    </DropdownMenu>
                </Dropdown>
            {/if}
            <a
                class="btn btn-primary"
                href="/config/targets/create"
                class:disabled={!$adminPermissions.targetsCreate}
                use:link
            >
                Add a target
            </a>
        </div>
    </div>

    {#if error}
        <Alert color="danger">{error}</Alert>
    {/if}

    {#key selectedGroup}
        <ItemList
            load={getTargets}
            showSearch={true}
            groupObject={groupInfoFromTarget}
            groupKey={group => group.id}
            collapsibleGroups
            bind:collapsedGroups={$collapsedGroups}
        >
            {#snippet header(items)}
                {#if items?.length}
                    <Dropdown>
                        <DropdownToggle color="link">
                            <Fa icon={faEllipsisV} fw />
                        </DropdownToggle>
                        <DropdownMenu end>
                            <div class="dropdown-header">Groups</div>
                            <DropdownItem
                                onclick={() => collapseAllGroups(items)}
                            >
                                Collapse all
                            </DropdownItem>
                            <DropdownItem
                                onclick={() => { $collapsedGroups = [] }}
                            >
                                Expand all
                            </DropdownItem>
                        </DropdownMenu>
                    </Dropdown>
                {/if}
            {/snippet}
            {#snippet empty()}
                <EmptyState
                    title="No targets yet"
                    hint="Targets are destinations on the internal network that your users will connect to"
                />
            {/snippet}
            {#snippet groupHeader(group, state)}
                <CollapsibleGroupHeader
                    name={group.name}
                    color={group.color}
                    count={state.count}
                    collapsed={state.collapsed}
                    toggle={state.toggle}
                />
            {/snippet}
            {#snippet item(target)}
                <a
                    class="list-group-item list-group-item-action"
                    href="/config/targets/{target.id}"
                    use:link
                >
                    <div class="me-auto">
                        <div class="d-flex align-items-center gap-2">
                            <strong>
                                {target.name}
                            </strong>
                        </div>
                        {#if target.description}
                            <small class="d-block text-muted"
                                >{target.description}</small
                            >
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
                        {#if target.options.kind === TargetKind.Kubernetes}
                            Kubernetes
                        {/if}
                        {#if target.options.kind === TargetKind.Vnc}
                            VNC
                        {/if}
                        {#if target.options.kind === TargetKind.Rdp}
                            RDP
                        {/if}
                    </small>
                </a>
            {/snippet}
        </ItemList>
    {/key}
</div>

<style lang="scss">
    .list-group-item {
        display: flex;
        align-items: center;
    }
</style>
