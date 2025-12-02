<script lang="ts">
    import { link } from 'svelte-spa-router'
    import { api, stringifyError } from 'admin/lib/api'
    import Loadable from 'common/Loadable.svelte'
    import AsyncButton from 'common/AsyncButton.svelte'

    interface Props {
        params: { id: string }
    }

    let { params }: Props = $props()

    let server = $state<any>(null)
    let users = $state<any[]>([])
    let error = $state<string | null>(null)
    let searchTerm = $state('')

    async function load() {
        server = await api.getLdapServer({ id: params.id })
    }

    async function loadUsers() {
        error = null
        try {
            users = await api.getLdapUsers({ id: params.id })
        } catch (e: any) {
            error = await stringifyError(e)
        }
    }

    let filteredUsers = $derived(
        searchTerm
            ? users.filter(
                (u) =>
                    u.username.toLowerCase().includes(searchTerm.toLowerCase()) ||
                    u.email?.toLowerCase().includes(searchTerm.toLowerCase()) ||
                    u.displayName?.toLowerCase().includes(searchTerm.toLowerCase()),
              )
            : users,
    )
</script>

<Loadable promise={load()}>
    <div class="container-max-md">
        <div class="page-summary-bar">
            <h1>LDAP Users</h1>
            <a class="btn btn-secondary ms-auto" href="/config/ldap-servers/{params.id}" use:link>
                Back to Server
            </a>
        </div>

        {#if server}
            <div class="card mb-3">
                <div class="card-body">
                    <h5 class="card-title">{server.name}</h5>
                    <p class="card-text text-muted">
                        {server.host}:{server.port}
                    </p>
                </div>
            </div>
        {/if}

        {#if users.length === 0}
            <div class="text-center my-5">
                <AsyncButton class="btn btn-primary" click={loadUsers}>
                    Load Users from LDAP
                </AsyncButton>
            </div>
        {:else}
            <div class="mb-3">
                <input
                    type="text"
                    class="form-control"
                    placeholder="Search users..."
                    bind:value={searchTerm}
                />
            </div>

            <div class="d-flex justify-content-between align-items-center mb-2">
                <span class="text-muted">
                    {filteredUsers.length} user(s) {searchTerm ? `(filtered from ${users.length})` : ''}
                </span>
                <AsyncButton class="btn btn-sm btn-secondary" click={loadUsers}>
                    Refresh
                </AsyncButton>
            </div>

            <div class="list-group">
                {#each filteredUsers as user (user.dn)}
                    <div class="list-group-item">
                        <div class="d-flex w-100 justify-content-between">
                            <h6 class="mb-1">{user.username}</h6>
                            {#if user.displayName}
                                <small class="text-muted">{user.displayName}</small>
                            {/if}
                        </div>
                        {#if user.email}
                            <p class="mb-1">
                                <small>{user.email}</small>
                            </p>
                        {/if}
                        <small class="text-muted">DN: {user.dn}</small>
                    </div>
                {/each}
            </div>
        {/if}

        {#if error}
            <div class="alert alert-danger mt-3" role="alert">
                {error}
            </div>
        {/if}
    </div>
</Loadable>
