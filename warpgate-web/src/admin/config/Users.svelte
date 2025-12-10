<script lang="ts">
    import { Observable, from, map } from 'rxjs'
    import { type LdapServerResponse, type User, api } from 'admin/lib/api'
    import ItemList, { type LoadOptions, type PaginatedResponse } from 'common/ItemList.svelte'
    import { link, push } from 'svelte-spa-router'
    import { onMount } from 'svelte'
    import { Dropdown, DropdownItem, DropdownMenu, DropdownToggle } from '@sveltestrap/sveltestrap'

    let ldapServers = $state<LdapServerResponse[]>([])

    function getUsers (options: LoadOptions): Observable<PaginatedResponse<User>> {
        return from(api.getUsers({
            search: options.search,
        })).pipe(map(targets => ({
            items: targets,
            offset: 0,
            total: targets.length,
        })))
    }

    onMount(() => {
        api.getLdapServers().then(servers => {
            ldapServers = servers
        })
    })
</script>

<div class="container-max-md">
    <div class="page-summary-bar">
        <h1>users</h1>
        <a
            class="btn btn-primary ms-auto"
            href="/config/users/create"
            use:link>
            Add a user
        </a>
            {#if ldapServers.length > 0}
            <Dropdown>
                <DropdownToggle caret>
                    Add from LDAP
                </DropdownToggle>
                <DropdownMenu>
                    {#each ldapServers as server (server.id)}
                        <DropdownItem onclick={() => {
                            push(`/config/ldap-servers/${server.id}/users`)
                        }}>
                            {server.name}
                        </DropdownItem>
                    {/each}
                </DropdownMenu>
            </Dropdown>
            {/if}
    </div>

    <ItemList load={getUsers} showSearch={true}>
        {#snippet item(user)}
            <a
                class="list-group-item list-group-item-action"
                href="/config/users/{user.id}"
                use:link>
                <div>
                    <strong class="me-auto">
                        {user.username}
                    </strong>
                    {#if user.description}
                    <small class="d-block text-muted">{user.description}</small>
                    {/if}
                </div>
                {#if user.ldapServerId}
                    <span class="badge bg-info ms-auto">
                        LDAP
                    </span>
                {/if}
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
