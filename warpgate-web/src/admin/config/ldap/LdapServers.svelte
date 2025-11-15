<script lang="ts">
    import { Observable, from, map } from 'rxjs'
    import { api } from 'admin/lib/api'
    import ItemList, { type LoadOptions, type PaginatedResponse } from 'common/ItemList.svelte'
    import { link } from 'svelte-spa-router'

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

    <ItemList load={getLdapServers} showSearch={true}>
        {#snippet item(server)}
            <a
                class="list-group-item list-group-item-action"
                href="/config/ldap-servers/{server.id}"
                use:link>
                <div class="d-flex align-items-center">
                    <div class="flex-grow-1">
                        <strong class="me-auto">
                            {server.name}
                        </strong>
                        <small class="d-block text-muted">
                            {server.host}:{server.port}
                        </small>
                        {#if server.description}
                            <small class="d-block text-muted">{server.description}</small>
                        {/if}
                    </div>
                    <div class="ms-3">
                        {#if server.enabled}
                            <span class="badge bg-success">Enabled</span>
                        {:else}
                            <span class="badge bg-secondary">Disabled</span>
                        {/if}
                    </div>
                </div>
            </a>
        {/snippet}
    </ItemList>
</div>

<style lang="scss">
    .list-group-item {
        display: block;
    }
</style>
