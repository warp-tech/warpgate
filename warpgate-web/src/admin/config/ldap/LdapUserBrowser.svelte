<script lang="ts">
    import { api, stringifyError } from 'admin/lib/api'
    import Loadable from 'common/Loadable.svelte'
    import AsyncButton from 'common/AsyncButton.svelte'
    import Alert from 'common/sveltestrap-s5-ports/Alert.svelte'
    import Fa from 'svelte-fa'
    import { faRefresh } from '@fortawesome/free-solid-svg-icons'

    interface Props {
        params: { id: string }
    }

    let { params }: Props = $props()

    let server = $state<any>(null)
    let users = $state<any[]>([])
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
                    u.displayName?.toLowerCase().includes(searchTerm.toLowerCase()))
            : users,
    )

    async function batchImport () {
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
        } catch (e: any) {
            error = await stringifyError(e)
        }
    }
</script>


{#if error}
    <Alert color="danger">{error}</Alert>
{/if}
{#if success}
    <Alert color="success">{success}</Alert>
{/if}

<Loadable promise={load()}>
    {#if server}
    <div class="container-max-md">
        <div class="page-summary-bar">
            <h1>{server.name}</h1>
        </div>

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
                    {filteredUsers.length} users {searchTerm ? `(filtered from ${users.length})` : ''}
                </span>
                <div class="d-flex gap-2">
                    <AsyncButton
                        class="btn btn-sm btn-primary"
                        click={batchImport}
                        disabled={selectedUserDns.length === 0}
                    >
                        Import {selectedUserDns.length} selected
                    </AsyncButton>
                    <AsyncButton class="btn btn-sm btn-secondary" click={loadUsers}>
                        <Fa icon={faRefresh} />
                    </AsyncButton>
                </div>
            </div>

            <div class="list-group">
                {#each filteredUsers as user (user.dn)}
                    <div class="list-group-item d-flex align-items-center gap-3">
                        <input
                            type="checkbox"
                            class="form-check-input"
                            bind:group={selectedUserDns}
                            value={user.dn}
                            aria-label="Select user"
                        />
                        <div class="flex-grow-1">
                            <div>
                                <h6 class="mb-1">
                                    {user.username}
                                    {#if user.displayName && user.displayName !== user.username}
                                        <small class="text-muted ms-1">({user.displayName})</small>
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
