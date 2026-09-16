<script lang="ts">
    /**
     * Roles — screen 7. Rows = targets, columns = roles, one two-state toggle
     * per cell.
     *
     * DIVERGENCE FROM THE MOCKUP, by decision. warpgate_roles_access_matrix
     * draws four capability columns — Connect, Record, Copy/Paste, File
     * Transfer. No such model exists: `Role` is {id, name, description,
     * is_default} and role↔target is a plain many-to-many join with no
     * per-capability granularity. The matrix layout survives; the capability
     * columns are gone. Unenforced toggles in an access-control UI are worse
     * than no toggles.
     *
     * No new primitive. The grid is screen-local markup over Checkbox, Badge
     * and Button — a "matrix" primitive used on exactly one screen is how a
     * design system forks.
     *
     * Loading strategy: one request for the role list, then one per role for
     * its targets (`/role/{id}/targets`). Roles are few and targets many, so
     * this is O(roles) requests rather than O(targets) — the inverse shape
     * would have been the obvious-but-wrong choice.
     */
    import { api, type Role, type Target } from 'admin/lib/api'
    import { stringifyError } from 'common/errors'
    import { compare as naturalCompareFactory } from 'natural-orderby'
    import { push } from 'svelte-spa-router'
    import Badge from 'ui/Badge.svelte'
    import Button from 'ui/Button.svelte'
    import Callout from 'ui/Callout.svelte'
    import Checkbox from 'ui/Checkbox.svelte'
    import EmptyState from 'ui/EmptyState.svelte'
    import Input from 'ui/Input.svelte'
    import SkeletonRow from 'ui/SkeletonRow.svelte'
    import { toast } from 'ui/toasts.svelte'
    import { adminPermissions } from '../lib/store'

    let roles: Role[] = $state([])
    let targets: Target[] = $state([])
    /** roleId -> set of targetIds that role can reach. */
    let grants: Record<string, Set<string>> = $state({})
    let loading = $state(true)
    let error: string | undefined = $state()
    let filter = $state('')

    const natural = naturalCompareFactory()

    async function load() {
        loading = true
        try {
            const [allRoles, allTargets] = await Promise.all([
                api.getRoles(),
                api.getTargets({}),
            ])

            roles = allRoles.sort((a, b) =>
                natural(a.name.toLowerCase(), b.name.toLowerCase()),
            )
            targets = allTargets.sort((a, b) =>
                natural(a.name.toLowerCase(), b.name.toLowerCase()),
            )

            const perRole = await Promise.all(
                roles.map(role =>
                    api
                        .getRoleTargets({ id: role.id })
                        .then(
                            list =>
                                [
                                    role.id,
                                    new Set(list.map(t => t.id)),
                                ] as const,
                        ),
                ),
            )
            grants = Object.fromEntries(perRole)
        } catch (err) {
            error = await stringifyError(err)
        } finally {
            loading = false
        }
    }

    function isAllowed(targetId: string, roleId: string): boolean {
        return grants[roleId]?.has(targetId) ?? false
    }

    /**
     * Optimistic, then reverted on failure. A matrix invites rapid clicking,
     * and waiting for each round trip would make it feel broken; but a cell
     * that silently stays on after a failed grant would be a lie about who
     * can reach what, so failure restores the previous state and says so.
     */
    async function toggle(target: Target, role: Role) {
        const on = isAllowed(target.id, role.id)
        const next = { ...grants }
        const set = new Set(next[role.id] ?? [])
        if (on) {
            set.delete(target.id)
        } else {
            set.add(target.id)
        }
        next[role.id] = set
        grants = next

        try {
            if (on) {
                await api.deleteTargetRole({ id: target.id, roleId: role.id })
            } else {
                await api.addTargetRole({ id: target.id, roleId: role.id })
            }
        } catch (err) {
            const reverted = { ...grants }
            const undo = new Set(reverted[role.id] ?? [])
            if (on) {
                undo.add(target.id)
            } else {
                undo.delete(target.id)
            }
            reverted[role.id] = undo
            grants = reverted
            toast.error(
                `Could not ${on ? 'revoke' : 'grant'} ${role.name} on ${target.name}`,
                { detail: await stringifyError(err) },
            )
        }
    }

    function grantCount(roleId: string): number {
        return grants[roleId]?.size ?? 0
    }

    const visibleTargets = $derived(
        filter.trim()
            ? targets.filter(t =>
                  t.name.toLowerCase().includes(filter.trim().toLowerCase()),
              )
            : targets,
    )

    load()
</script>

<div class="head">
    <h1>Roles</h1>
    <div class="head-actions">
        <Button
            variant="primary"
            size="compact"
            disabled={!$adminPermissions.accessRolesCreate}
            onclick={() => push('/config/access-roles/create')}
        >
            Add a role
        </Button>
    </div>
</div>

<p class="intro">
    Which targets each role can reach. A role grants access to a target or it
    does not — Warpgate has no per-capability permissions, so there is nothing
    finer to set here.
</p>

{#if error}
    <Callout tone="danger" title="Something went wrong">{error}</Callout>
{:else if loading}
    <SkeletonRow rows={6} columns={[3, 1, 1, 1, 1]} />
{:else if !roles.length}
    <EmptyState
        title="No roles yet"
        hint="Roles connect users to the targets they are allowed to reach."
    >
        {#snippet action()}
            <Button
                variant="primary"
                size="compact"
                disabled={!$adminPermissions.accessRolesCreate}
                onclick={() => push('/config/access-roles/create')}
            >
                Add a role
            </Button>
        {/snippet}
    </EmptyState>
{:else if !targets.length}
    <EmptyState
        title="No targets yet"
        hint="Add a target before assigning roles to it."
    >
        {#snippet action()}
            <Button
                size="compact"
                onclick={() => push('/config/targets/create')}
            >
                Add a target
            </Button>
        {/snippet}
    </EmptyState>
{:else}
    <div class="toolbar">
        <Input
            label="Filter targets"
            labelHidden
            type="search"
            placeholder="Filter targets…"
            bind:value={filter}
            class="filter"
        />
        {#if !$adminPermissions.accessRolesAssign}
            <Badge tone="warning">Read-only — you cannot assign roles</Badge>
        {/if}
    </div>

    <div class="matrix-scroll">
        <table class="matrix">
            <caption class="sr-only">
                Targets by role. Each cell grants or revokes one role's access
                to one target.
            </caption>
            <thead>
                <tr>
                    <th scope="col" class="corner">Target</th>
                    {#each roles as role (role.id)}
                        <th scope="col" class="role-col">
                            <a
                                class="role-link"
                                href="#/config/access-roles/{role.id}"
                            >
                                {role.name}
                            </a>
                            <span class="role-count">
                                {grantCount(role.id)}
                                {#if role.isDefault}
                                    · default
                                {/if}
                            </span>
                        </th>
                    {/each}
                </tr>
            </thead>
            <tbody>
                {#each visibleTargets as target (target.id)}
                    <tr>
                        <th scope="row" class="target-col">
                            <a
                                class="target-link"
                                href="#/config/targets/{target.id}"
                            >
                                {target.name}
                            </a>
                        </th>
                        {#each roles as role (role.id)}
                            <td class="cell">
                                <Checkbox
                                    label="Allow {role.name} on {target.name}"
                                    labelHidden
                                    checked={isAllowed(target.id, role.id)}
                                    disabled={!$adminPermissions.accessRolesAssign}
                                    onchange={() => toggle(target, role)}
                                />
                            </td>
                        {/each}
                    </tr>
                {:else}
                    <tr>
                        <td colspan={roles.length + 1} class="no-match">
                            No targets match “{filter}”
                        </td>
                    </tr>
                {/each}
            </tbody>
        </table>
    </div>
{/if}

<style>
    .head {
        display: flex;
        align-items: center;
        justify-content: space-between;
        gap: var(--wg-space-lg);
        flex-wrap: wrap;
        margin-bottom: var(--wg-space-sm);
    }

    h1 {
        margin: 0;
        font: var(--wg-text-headline-lg);
    }

    .intro {
        margin: 0 0 var(--wg-space-lg);
        max-width: 72ch;
        font: var(--wg-text-body-md);
        color: var(--wg-text-muted);
    }

    .toolbar {
        display: flex;
        align-items: center;
        gap: var(--wg-space-md);
        margin-bottom: var(--wg-space-md);
    }

    .toolbar :global(.filter) {
        max-width: 20rem;
    }

    /* Only the matrix scrolls sideways; the page never does. */
    .matrix-scroll {
        overflow: auto;
        max-height: 70vh;
        border: var(--wg-border-width) solid var(--wg-border);
        border-radius: var(--wg-radius-panel);
    }

    .matrix {
        border-collapse: separate;
        border-spacing: 0;
        font: var(--wg-text-body-md);
    }

    .matrix th,
    .matrix td {
        border-bottom: var(--wg-border-width) solid var(--wg-border);
        padding: 0 var(--wg-space-md);
        height: var(--wg-row-height);
    }

    /* Column headers stay put vertically */
    .matrix thead th {
        position: sticky;
        top: 0;
        z-index: 2;
        background: var(--wg-surface-container);
        text-align: center;
        white-space: nowrap;
        font: var(--wg-text-label-md);
        color: var(--wg-text-muted);
        vertical-align: bottom;
        padding-bottom: var(--wg-space-xs);
    }

    /* Row headers stay put horizontally; the corner does both, so it needs a
     * higher stacking order than either. */
    .corner {
        position: sticky;
        left: 0;
        z-index: 3;
        text-align: left;
        min-width: 14rem;
    }

    .target-col {
        position: sticky;
        left: 0;
        z-index: 1;
        background: var(--wg-surface-container);
        text-align: left;
        white-space: nowrap;
        font: var(--wg-text-body-md);
        /* A hairline on the right marks where the frozen column ends */
        box-shadow: inset -1px 0 0 var(--wg-border);
    }

    .matrix tbody tr:nth-child(even) td {
        background: var(--wg-row-stripe);
    }

    .matrix tbody tr:hover td {
        background: var(--wg-row-hover);
    }

    .cell {
        text-align: center;
        min-width: 6rem;
    }

    /* Centres the checkbox, which is an inline-flex label */
    .cell :global(.wg-check) {
        justify-content: center;
    }

    .role-col {
        min-width: 6rem;
    }

    .role-link,
    .target-link {
        color: var(--wg-text);
        text-decoration: none;
    }

    .role-link:hover,
    .target-link:hover {
        text-decoration: underline;
    }

    .role-link:focus-visible,
    .target-link:focus-visible {
        outline: var(--wg-focus-ring);
        outline-offset: var(--wg-focus-ring-offset);
        border-radius: var(--wg-radius-sm);
    }

    .target-link {
        font-family: var(--wg-font-mono);
    }

    .role-count {
        display: block;
        font: var(--wg-text-label-sm);
        color: var(--wg-text-subtle);
        font-variant-numeric: tabular-nums;
    }

    .no-match {
        text-align: center;
        color: var(--wg-text-muted);
        padding: var(--wg-space-xl);
    }

    .sr-only {
        position: absolute;
        width: 1px;
        height: 1px;
        padding: 0;
        margin: -1px;
        overflow: hidden;
        clip-path: inset(50%);
        white-space: nowrap;
        border: 0;
    }

    @media (max-width: 640px) {
        h1 {
            font: var(--wg-text-headline-lg-mobile);
        }
    }
</style>
