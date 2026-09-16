<script lang="ts">
    /**
     * Targets — screen 3.
     *
     * Behaviour preserved from admin/config/targets/Targets.svelte:
     *   - group filter, with the list re-keyed on change so ItemList reloads
     *   - three-level natural sort: ungrouped first, then by group name, then
     *     by target name within the group
     *   - collapsed groups persisted through common/autosave
     *   - collapse-all / expand-all, now in the table toolbar rather than an
     *     overflow menu
     *   - "Add a target" gated on targetsCreate
     *
     * Columns follow warpgate_targets minus the four with no backing data:
     * Health, TLS, Last used and Sessions. See IMPLEMENTATION-NOTES D7.
     */
    import { api, type Target, type TargetGroup } from 'admin/lib/api'
    import { autosave } from 'common/autosave'
    import { stringifyError } from 'common/errors'
    import { type ResolvedGroup, resolveGroup } from 'common/groups'
    import type {
        GroupState,
        LoadOptions,
        PaginatedResponse,
    } from 'common/ItemList.svelte'
    import { TargetKind } from 'gateway/lib/api'
    import { compare as naturalCompareFactory } from 'natural-orderby'
    import { from, map, type Observable } from 'rxjs'
    import { push } from 'svelte-spa-router'
    import { firstBy } from 'thenby'
    import Badge from 'ui/Badge.svelte'
    import Button from 'ui/Button.svelte'
    import Callout from 'ui/Callout.svelte'
    import EmptyState from 'ui/EmptyState.svelte'
    import Select from 'ui/Select.svelte'
    import Table, { type Column } from 'ui/Table.svelte'
    import { adminPermissions } from '../lib/store'

    const PROTOCOL_LABELS: Record<string, string> = {
        [TargetKind.Http]: 'HTTP',
        [TargetKind.MySql]: 'MySQL',
        [TargetKind.Postgres]: 'PostgreSQL',
        [TargetKind.Ssh]: 'SSH',
        [TargetKind.Kubernetes]: 'Kubernetes',
        [TargetKind.Vnc]: 'VNC',
        [TargetKind.Rdp]: 'RDP',
    }

    let error: string | undefined = $state()
    let groups: TargetGroup[] = $state([])
    let selectedGroupId: string | undefined = $state()

    const [collapsedGroups] = autosave<string[]>(
        'admin-target-list:collapsed-groups',
        [],
    )

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

    function getTargets(
        options: LoadOptions,
    ): Observable<PaginatedResponse<Target>> {
        return from(
            Promise.all([
                groupsPromise,
                api.getTargets({
                    search: options.search,
                    groupId: selectedGroupId,
                }),
            ]),
        ).pipe(
            map(([_, targets]) => {
                const natural = naturalCompareFactory()
                const groupName = (target: Target) =>
                    (
                        groups.find(g => g.id === target.groupId)?.name ?? ''
                    ).toLowerCase()

                return targets.sort(
                    firstBy((x: Target) => !x.groupId)
                        .thenBy((a: Target, b: Target) =>
                            natural(groupName(a), groupName(b)),
                        )
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

    function groupOf(target: Target): ResolvedGroup {
        return resolveGroup(groups.find(g => g.id === target.groupId))
    }

    function addressOf(target: Target): string {
        const o = target.options
        switch (o.kind) {
            case TargetKind.Ssh:
            case TargetKind.MySql:
            case TargetKind.Postgres:
            case TargetKind.Vnc:
            case TargetKind.Rdp:
                return `${o.host}:${o.port}`
            case TargetKind.Http:
                return o.url
            case TargetKind.Kubernetes:
                return o.clusterUrl
            default:
                return '—'
        }
    }

    const columns: Column[] = [
        { key: 'name', label: 'Name', sortable: true },
        { key: 'address', label: 'Address' },
        { key: 'protocol', label: 'Protocol', width: '8rem' },
        { key: 'roles', label: 'Allowed roles', width: '10rem', align: 'end' },
    ]

    const groupOptions = $derived([
        { value: '', label: 'All groups' },
        ...groups.map(g => ({ value: g.id, label: g.name })),
    ])
</script>

<div class="head">
    <h1>Targets</h1>
    <div class="head-actions">
        {#if groups.length > 0}
            <Select
                label="Group"
                labelHidden
                size="compact"
                options={groupOptions}
                value={selectedGroupId ?? ''}
                onchange={e => {
                    const v = (e.target as HTMLSelectElement).value
                    selectedGroupId = v || undefined
                }}
            />
        {/if}
        <Button
            variant="primary"
            size="compact"
            disabled={!$adminPermissions.targetsCreate}
            onclick={() => push('/config/targets/create')}
        >
            Add a target
        </Button>
    </div>
</div>

{#if error}
    <Callout tone="danger" title="Something went wrong">{error}</Callout>
{/if}

<!-- Re-keyed so a group change reloads the list rather than filtering in place -->
{#key selectedGroupId}
    <Table
        caption="Targets"
        {columns}
        load={getTargets}
        rowKey={t => t.id}
        showSearch
        searchPlaceholder="Search targets…"
        groupObject={groupOf}
        groupKey={g => g.id}
        bind:collapsedGroups={$collapsedGroups}
        onrowactivate={t => push(`/config/targets/${t.id}`)}
    >
        {#snippet groupHeader(group: ResolvedGroup, state: GroupState)}
            <tr class="group-row">
                <th colspan={columns.length} scope="colgroup">
                    {#if state.collapsible}
                        <button
                            type="button"
                            class="group-toggle"
                            aria-expanded={!state.collapsed}
                            onclick={state.toggle}
                        >
                            <span
                                class="group-caret"
                                class:collapsed={state.collapsed}
                                aria-hidden="true"
                                >▾</span
                            >
                            {group.name}
                        </button>
                    {:else}
                        <span class="group-static">{group.name}</span>
                    {/if}
                </th>
            </tr>
        {/snippet}

        {#snippet row(target)}
            <td class="wg-mono">{target.name}</td>
            <td class="wg-mono muted">{addressOf(target)}</td>
            <td>
                {PROTOCOL_LABELS[target.options.kind] ?? target.options.kind}
            </td>
            <td class="num">
                {#if target.allowRoles.length}
                    <Badge>{target.allowRoles.length}</Badge>
                {:else}
                    <span class="muted">none</span>
                {/if}
            </td>
        {/snippet}

        {#snippet empty()}
            <EmptyState
                size="compact"
                title="No targets yet"
                hint="Targets are destinations on the internal network that your users connect to."
            >
                {#snippet action()}
                    <Button
                        variant="primary"
                        size="compact"
                        disabled={!$adminPermissions.targetsCreate}
                        onclick={() => push('/config/targets/create')}
                    >
                        Add a target
                    </Button>
                {/snippet}
            </EmptyState>
        {/snippet}
    </Table>
{/key}

<style>
    .head {
        display: flex;
        align-items: center;
        justify-content: space-between;
        gap: var(--wg-space-lg);
        flex-wrap: wrap;
        margin-bottom: var(--wg-space-lg);
    }

    .head-actions {
        display: flex;
        align-items: center;
        gap: var(--wg-space-sm);
    }

    h1 {
        margin: 0;
        font: var(--wg-text-headline-lg);
    }

    .muted {
        color: var(--wg-text-muted);
    }

    .num {
        text-align: right;
    }

    /* Group-header rows sit in tbody; Table's sticky rule is scoped to thead,
     * so this needs no override. */
    .group-row th {
        background: var(--wg-surface-container-high);
        text-align: left;
    }

    .group-toggle {
        display: inline-flex;
        align-items: center;
        gap: var(--wg-space-xs);
        padding: 0;
        border: 0;
        background: none;
        color: var(--wg-text);
        font: var(--wg-text-label-md);
        cursor: pointer;
    }

    .group-toggle:focus-visible {
        outline: var(--wg-focus-ring);
        outline-offset: var(--wg-focus-ring-offset);
    }

    .group-caret {
        display: inline-block;
        transition: transform var(--wg-duration-fast) var(--wg-easing);
    }

    .group-caret.collapsed {
        transform: rotate(-90deg);
    }

    .group-static {
        font: var(--wg-text-label-md);
        color: var(--wg-text);
    }

    @media (prefers-reduced-motion: reduce) {
        .group-caret {
            transition: none;
        }
    }

    @media (max-width: 640px) {
        h1 {
            font: var(--wg-text-headline-lg-mobile);
        }
    }
</style>
