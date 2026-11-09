<script lang="ts">
    import { faLock } from '@fortawesome/free-solid-svg-icons'
    import {
        Alert,
        Dropdown,
        DropdownItem,
        DropdownMenu,
        DropdownToggle,
        Tooltip,
    } from '@sveltestrap/sveltestrap'
    import { api, type Target, type TargetGroup } from 'admin/lib/api'
    import { targetAddress } from 'admin/lib/targetAddress'
    import CollapsibleGroupHeader from 'common/CollapsibleGroupHeader.svelte'
    import EmptyState from 'common/EmptyState.svelte'
    import { stringifyError } from 'common/errors'
    import GroupColorIcon from 'common/GroupColorIcon.svelte'
    import { orderForGroupedList, resolveGroup } from 'common/groups'
    import { uuid } from 'common/helpers'
    import ItemList, {
        type Column,
        type LoadOptions,
        type PaginatedResponse,
    } from 'common/ItemList.svelte'
    import ListOverflowMenu from 'common/ListOverflowMenu.svelte'
    import { TARGET_KIND_LABELS } from 'common/targetKinds'
    import { compare as naturalCompareFactory } from 'natural-orderby'
    import { from, map, type Observable } from 'rxjs'
    import Fa from 'svelte-fa'
    import { link } from 'svelte-spa-router'
    import { adminPermissions } from '../../lib/store'

    let error: string | undefined = $state()
    let groups: TargetGroup[] = $state([])
    let selectedGroup: TargetGroup | undefined = $state()

    const groupsPromise = api
        .listTargetGroups()
        .then(result => {
            const natural = naturalCompareFactory()
            groups = result.sort((a, b) =>
                natural(a.name.toLowerCase(), b.name.toLowerCase()),
            )
        })
        .catch(async err => {
            error = await stringifyError(err)
            groups = []
        })

    const columns: Column<Target>[] = [
        { id: 'name', cell: nameCell },
        {
            id: 'requiresAdminApproval',
            label: 'Requires admin approval',
            cell: requiresApprovalCell,
        },
        {
            id: 'address',
            label: 'Address',
            hiddenByDefault: true,
            cell: addressCell,
            class: 'text-muted small font-monospace',
        },
        {
            id: 'description',
            label: 'Description',
            cell: descriptionCell,
            grow: true,
            class: 'text-truncate text-muted small',
        },
        {
            id: 'kind',
            label: 'Type',
            cell: kindCell,
            class: 'text-muted small text-end',
        },
    ]

    function getTargets(
        options: LoadOptions,
    ): Observable<PaginatedResponse<Target>> {
        return from(
            Promise.all([
                groupsPromise,
                api.getTargets({
                    search: options.search,
                    groupId: selectedGroup?.id,
                }),
            ]),
        ).pipe(
            map(([_, targets]) =>
                orderForGroupedList(targets, options.search, {
                    groupId: t => t.groupId,
                    groupName: t =>
                        groups.find(g => g.id === t.groupId)?.name ?? '',
                    name: t => t.name,
                }),
            ),
            map(targets => ({
                items: targets,
                offset: 0,
                total: targets.length,
            })),
        )
    }

    function groupInfoFromTarget(target: Target) {
        return resolveGroup(groups.find(g => g.id === target.groupId))
    }
</script>

{#snippet nameCell(target: Target)}
    <strong>{target.name}</strong>
{/snippet}

{#snippet addressCell(target: Target)}
    {targetAddress(target.options)}
{/snippet}

{#snippet descriptionCell(target: Target)}
    {target.description}
{/snippet}

{#snippet kindCell(target: Target)}
    {TARGET_KIND_LABELS[target.options.kind]}
{/snippet}

{#snippet requiresApprovalCell(target: Target)}
    {const id = uuid()}
    {#if target.requireApproval}
        <Fa icon={faLock} {id}></Fa>
    {/if}
    <Tooltip target={id} delay="500"> Requires admin approval </Tooltip>
{/snippet}

<div>
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
                                    <GroupColorIcon color={group.color} />
                                {/if}
                                {group.name}
                            </DropdownItem>
                        {/each}
                    </DropdownMenu>
                </Dropdown>
            {/if}
            <a
                class="btn btn-primary"
                href="/manage/targets/create"
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
            {columns}
            storageKey="admin-targets"
            showSearch={true}
            groupObject={groupInfoFromTarget}
            groupKey={group => group.id}
            virtual
        >
            {#snippet header(_items, groupControls, columnControls)}
                <ListOverflowMenu {groupControls} {columnControls} />
            {/snippet}
            {#snippet empty()}
                <EmptyState
                    title="No targets yet"
                    hint="Targets are destinations on the internal network that your users will connect to"
                />
            {/snippet}
            {#snippet groupHeader(group, state)}
                <CollapsibleGroupHeader {group} {state} />
            {/snippet}
            {#snippet item(target, cells)}
                <a
                    class="list-group-item list-group-item-action"
                    href="/manage/targets/{target.id}"
                    use:link
                >
                    {@render cells(target)}
                </a>
            {/snippet}
        </ItemList>
    {/key}
</div>
