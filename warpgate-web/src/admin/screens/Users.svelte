<script lang="ts">
    /**
     * Users — screen 5.
     *
     * Undesigned; derived from Targets (screen 3) rather than invented, per the
     * derive-never-invent rule. Same head/actions layout, same Table, same
     * search. No new primitives.
     *
     * Behaviour preserved from admin/config/users/Users.svelte:
     *   - natural sort by username
     *   - LDAP servers loaded on mount; "Add from LDAP" appears only when at
     *     least one is configured, and routes to that server's user browser
     *   - both create paths gated on usersCreate
     *   - the LDAP badge marks directory-linked accounts
     */
    import { api, type LdapServerResponse, type User } from 'admin/lib/api'
    import type { LoadOptions, PaginatedResponse } from 'common/ItemList.svelte'
    import { compare as naturalCompareFactory } from 'natural-orderby'
    import { from, map, type Observable } from 'rxjs'
    import { onMount } from 'svelte'
    import { push } from 'svelte-spa-router'
    import Badge from 'ui/Badge.svelte'
    import Button from 'ui/Button.svelte'
    import EmptyState from 'ui/EmptyState.svelte'
    import Select from 'ui/Select.svelte'
    import Table, { type Column } from 'ui/Table.svelte'
    import { adminPermissions } from '../lib/store'

    let ldapServers = $state<LdapServerResponse[]>([])

    function getUsers(
        options: LoadOptions,
    ): Observable<PaginatedResponse<User>> {
        return from(api.getUsers({ search: options.search })).pipe(
            map(users => {
                const natural = naturalCompareFactory()
                const sorted = users.sort((a, b) =>
                    natural(a.username.toLowerCase(), b.username.toLowerCase()),
                )
                return { items: sorted, offset: 0, total: sorted.length }
            }),
        )
    }

    onMount(() => {
        api.getLdapServers().then(servers => {
            ldapServers = servers
        })
    })

    const columns: Column[] = [
        { key: 'username', label: 'Username', sortable: true },
        { key: 'description', label: 'Description' },
        { key: 'source', label: 'Source', width: '8rem', align: 'end' },
    ]

    const ldapOptions = $derived([
        { value: '', label: 'Add from LDAP…' },
        ...ldapServers.map(s => ({ value: s.id, label: s.name })),
    ])
</script>

<div class="head">
    <h1>Users</h1>
    <div class="head-actions">
        {#if ldapServers.length > 0}
            <Select
                label="Add from LDAP"
                labelHidden
                size="compact"
                options={ldapOptions}
                value=""
                disabled={!$adminPermissions.usersCreate}
                onchange={e => {
                    const id = (e.target as HTMLSelectElement).value
                    if (id) {
                        push(`/config/ldap-servers/${id}/users`)
                    }
                }}
            />
        {/if}
        <Button
            variant="primary"
            size="compact"
            disabled={!$adminPermissions.usersCreate}
            onclick={() => push('/config/users/create')}
        >
            Add a user
        </Button>
    </div>
</div>

<Table
    caption="Users"
    {columns}
    load={getUsers}
    rowKey={u => u.id}
    showSearch
    searchPlaceholder="Search users…"
    onrowactivate={u => push(`/config/users/${u.id}`)}
>
    {#snippet row(user)}
        <td class="wg-mono">{user.username}</td>
        <td class="muted">{user.description || '—'}</td>
        <td class="num">
            {#if user.ldapServerId}
                <Badge tone="primary">LDAP</Badge>
            {:else}
                <span class="muted">Local</span>
            {/if}
        </td>
    {/snippet}

    {#snippet empty()}
        <EmptyState
            size="compact"
            title="No users yet"
            hint="Users sign in to reach the targets their roles allow."
        >
            {#snippet action()}
                <Button
                    variant="primary"
                    size="compact"
                    disabled={!$adminPermissions.usersCreate}
                    onclick={() => push('/config/users/create')}
                >
                    Add a user
                </Button>
            {/snippet}
        </EmptyState>
    {/snippet}
</Table>

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

    @media (max-width: 640px) {
        h1 {
            font: var(--wg-text-headline-lg-mobile);
        }
    }
</style>
