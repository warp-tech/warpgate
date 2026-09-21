<script lang="ts">
    import { faRefresh } from '@fortawesome/free-solid-svg-icons'
    import {
        api,
        type LdapServerResponse,
        type LdapUserResponse,
    } from 'admin/lib/api'
    import { stringifyError } from 'common/errors'
    import Loadable from 'common/Loadable.svelte'
    import Fa from 'svelte-fa'
    import Button from 'ui/Button.svelte'
    import Callout from 'ui/Callout.svelte'

    interface Props {
        params: { id: string }
    }

    let { params }: Props = $props()

    let server = $state<LdapServerResponse | null>(null)
    let users = $state<LdapUserResponse[]>([])
    let error = $state<string | null>(null)
    let success = $state<string | null>(null)
    let searchTerm = $state('')

    let selectedUserDns = $state<string[]>([])

    async function load() {
        server = await api.getLdapServer({ id: params.id })
        await loadUsers()
    }

    async function loadUsers() {
        error = null
        try {
            users = await api.getLdapUsers({ id: params.id })
        } catch (e) {
            error = await stringifyError(e)
        }
    }

    let filteredUsers = $derived(
        searchTerm
            ? users.filter(
                  u =>
                      u.username
                          .toLowerCase()
                          .includes(searchTerm.toLowerCase()) ||
                      u.email
                          ?.toLowerCase()
                          .includes(searchTerm.toLowerCase()) ||
                      u.displayName
                          ?.toLowerCase()
                          .includes(searchTerm.toLowerCase()),
              )
            : users,
    )

    async function batchImport() {
        error = null
        success = null
        try {
            await api.importLdapUsers({
                id: params.id,
                importLdapUsersRequest: {
                    dns: selectedUserDns,
                },
            })
            await loadUsers()
            success = `Successfully imported ${selectedUserDns.length} users.`
            selectedUserDns = []
        } catch (e) {
            error = await stringifyError(e)
        }
    }
</script>

{#if error}
    <Callout tone="danger" title="Something went wrong">{error}</Callout>
{/if}
{#if success}
    <Callout tone="success">{success}</Callout>
{/if}

<Loadable promise={load()}>
    {#if server}
        <div class="container-max-md">
            <div class="page-summary-bar">
                <h1>{server.name}</h1>
            </div>

            {#if users.length === 0}
                <div class="text-center my-5">
                    <Button class="btn btn-primary" click={loadUsers}>
                        Load Users from LDAP
                    </Button>
                </div>
            {:else}
                <div class="mb-3">
                    <input
                        type="text"
                        class="form-control"
                        aria-label="Search users"
                        placeholder="Search users..."
                        bind:value={searchTerm}
                    >
                </div>

                <div
                    class="d-flex justify-content-between align-items-center mb-2"
                >
                    <span class="text-muted">
                        {filteredUsers.length}
                        users
                        {searchTerm ? `(filtered from ${users.length})` : ''}
                    </span>
                    <div class="d-flex gap-2">
                        <Button
                            class="btn btn-sm btn-primary"
                            click={batchImport}
                            disabled={selectedUserDns.length === 0}
                        >
                            Import {selectedUserDns.length} selected
                        </Button>
                        <Button
                            class="btn btn-sm btn-secondary"
                            click={loadUsers}
                        >
                            <Fa icon={faRefresh} />
                        </Button>
                    </div>
                </div>

                <div class="list-group">
                    {#each filteredUsers as user (user.dn)}
                        <div
                            class="list-group-item d-flex align-items-center gap-3"
                        >
                            <input
                                type="checkbox"
                                class="form-check-input"
                                bind:group={selectedUserDns}
                                value={user.dn}
                                aria-label="Select user"
                            >
                            <div class="flex-grow-1">
                                <div>
                                    <h6 class="mb-1">
                                        {user.username}
                                        {#if user.displayName && user.displayName !== user.username}
                                            <small class="text-muted ms-1"
                                                >({user.displayName})</small
                                            >
                                        {/if}
                                    </h6>
                                </div>
                                <small class="text-muted">DN: {user.dn}</small>
                            </div>
                        </div>
                    {/each}
                </div>
            {/if}
        </div>
    {/if}
</Loadable>
