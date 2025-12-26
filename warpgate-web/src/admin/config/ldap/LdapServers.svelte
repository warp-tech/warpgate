<script lang="ts">
    import { Observable, from, map } from 'rxjs'
    import { api } from 'admin/lib/api'
    import ItemList, { type LoadOptions, type PaginatedResponse } from 'common/ItemList.svelte'
    import { link } from 'svelte-spa-router'
    import EmptyState from 'common/EmptyState.svelte'
    import InfoBox from 'common/InfoBox.svelte'

    interface LdapServer {
        id: string
        name: string
        host: string
        port: number
        enabled: boolean
        description: string
    }

    function getLdapServers (options: LoadOptions): Observable<PaginatedResponse<LdapServer>> {
        return from(api.getLdapServers({
            search: options.search,
        })).pipe(map(servers => ({
            items: servers,
            offset: 0,
            total: servers.length,
        })))
    }
</script>

<div class="container-max-md">
    <div class="page-summary-bar">
        <h1>LDAP Servers</h1>
        <a
            class="btn btn-primary ms-auto"
            href="/config/ldap-servers/create"
            use:link>
            Add LDAP Server
        </a>
    </div>

    <InfoBox>
        Currently, LDAP can only be used to import users and their SSH keys. Warpgate will automatically sync the public keys of Warpgate users that are linked to LDAP users.
    </InfoBox>

    <ItemList load={getLdapServers} showSearch={true}>
        {#snippet empty()}
            <EmptyState
                title="No LDAP servers configured"
                hint="Connecting to LDAP lets you synchronize users' SSH keys from it"
            />
        {/snippet}
        {#snippet item(server)}
            <a
                class="list-group-item list-group-item-action"
                href="/config/ldap-servers/{server.id}"
                use:link>
                <strong class="me-auto">
                    {server.name}
                </strong>
                {#if server.description}
                    <small class="d-block text-muted">{server.description}</small>
                {/if}
            </a>
        {/snippet}
    </ItemList>
</div>

<style lang="scss">
    .list-group-item {
        display: block;
    }
</style>
