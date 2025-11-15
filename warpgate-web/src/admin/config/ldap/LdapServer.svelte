<script lang="ts">
    import { link, push } from 'svelte-spa-router'
    import { api, stringifyError } from 'admin/lib/api'
    import AsyncButton from 'common/AsyncButton.svelte'
    import Loadable from 'common/Loadable.svelte'

    interface Props {
        params: { id: string }
    }

    let { params }: Props = $props()

    let server = $state<any>(null)
    let name = $state('')
    let host = $state('')
    let port = $state(389)
    let bindDn = $state('')
    let bindPassword = $state('')
    let userFilter = $state('')
    let baseDns = $state<string[]>([])
    let tlsMode = $state('preferred')
    let tlsVerify = $state(true)
    let enabled = $state(true)
    let description = $state('')
    let error = $state<string | null>(null)
    let testResult = $state<{ success: boolean; message: string } | null>(null)

    async function load() {
        const result = await api.getLdapServer({ id: params.id })
        server = result
        name = result.name
        host = result.host
        port = result.port
        bindDn = result.bindDn
        userFilter = result.userFilter
        baseDns = result.baseDns || []
        tlsMode = result.tlsMode
        tlsVerify = result.tlsVerify
        enabled = result.enabled
        description = result.description || ''
    }

    async function testConnection() {
        error = null
        testResult = null

        try {
            const result = await api.testLdapServerConnection({
                testLdapServerRequest: {
                    host,
                    port,
                    bindDn,
                    bindPassword: bindPassword || server.bindPassword,
                    tlsMode: tlsMode as any,
                    tlsVerify,
                },
            })
            testResult = result
        } catch (e: any) {
            error = await stringifyError(e)
        }
    }

    async function save() {
        error = null

        try {
            await api.updateLdapServer({
                id: params.id,
                updateLdapServerRequest: {
                    name,
                    host,
                    port,
                    bindDn,
                    bindPassword: bindPassword || undefined,
                    userFilter,
                    tlsMode: tlsMode as any,
                    tlsVerify,
                    enabled,
                    description: description || undefined,
                },
            })
            await load()
            bindPassword = ''
        } catch (e: any) {
            error = await stringifyError(e)
        }
    }

    async function remove() {
        if (!confirm('Are you sure you want to delete this LDAP server?')) {
            return
        }

        try {
            await api.deleteLdapServer({ id: params.id })
            push('/config/ldap-servers')
        } catch (e: any) {
            error = await stringifyError(e)
        }
    }
</script>

<Loadable promise={load()}>
    <div class="container-max-md">
        <h1>LDAP Server</h1>

        <form onsubmit={(e) => { e.preventDefault(); save() }}>
            <div class="mb-3">
                <label for="name" class="form-label">Name *</label>
                <input
                    type="text"
                    class="form-control"
                    id="name"
                    bind:value={name}
                    required
                />
            </div>

            <div class="row mb-3">
                <div class="col-md-8">
                    <label for="host" class="form-label">Host *</label>
                    <input
                        type="text"
                        class="form-control"
                        id="host"
                        bind:value={host}
                        required
                    />
                </div>
                <div class="col-md-4">
                    <label for="port" class="form-label">Port *</label>
                    <input
                        type="number"
                        class="form-control"
                        id="port"
                        bind:value={port}
                        required
                    />
                </div>
            </div>

            <div class="mb-3">
                <label for="bindDn" class="form-label">Bind DN *</label>
                <input
                    type="text"
                    class="form-control"
                    id="bindDn"
                    bind:value={bindDn}
                    required
                />
            </div>

            <div class="mb-3">
                <label for="bindPassword" class="form-label">Bind Password</label>
                <input
                    type="password"
                    class="form-control"
                    id="bindPassword"
                    bind:value={bindPassword}
                    placeholder="Leave empty to keep current password"
                />
            </div>

            <div class="mb-3">
                <label for="userFilter" class="form-label">User Filter</label>
                <input
                    type="text"
                    class="form-control"
                    id="userFilter"
                    bind:value={userFilter}
                />
            </div>

            {#if baseDns.length > 0}
                <div class="mb-3">
                    <label class="form-label">Base DNs (discovered)</label>
                    <ul class="list-group">
                        {#each baseDns as dn (dn)}
                            <li class="list-group-item">
                                <code>{dn}</code>
                            </li>
                        {/each}
                    </ul>
                </div>
            {/if}

            <div class="row mb-3">
                <div class="col-md-6">
                    <label for="tlsMode" class="form-label">TLS Mode</label>
                    <select class="form-select" id="tlsMode" bind:value={tlsMode}>
                        <option value="disabled">Disabled</option>
                        <option value="preferred">Preferred</option>
                        <option value="required">Required</option>
                    </select>
                </div>
                <div class="col-md-6">
                    <div class="form-check form-switch mt-4">
                        <input
                            class="form-check-input"
                            type="checkbox"
                            id="tlsVerify"
                            bind:checked={tlsVerify}
                        />
                        <label class="form-check-label" for="tlsVerify">
                            Verify TLS certificates
                        </label>
                    </div>
                </div>
            </div>

            <div class="mb-3">
                <div class="form-check form-switch">
                    <input
                        class="form-check-input"
                        type="checkbox"
                        id="enabled"
                        bind:checked={enabled}
                    />
                    <label class="form-check-label" for="enabled">
                        Enabled
                    </label>
                </div>
            </div>

            <div class="mb-3">
                <label for="description" class="form-label">Description</label>
                <textarea
                    class="form-control"
                    id="description"
                    rows="3"
                    bind:value={description}
                ></textarea>
            </div>

            {#if testResult}
                <div class="alert {testResult.success ? 'alert-success' : 'alert-danger'}" role="alert">
                    {testResult.message}
                </div>
            {/if}

            {#if error}
                <div class="alert alert-danger" role="alert">
                    {error}
                </div>
            {/if}

            <div class="d-flex gap-2 mb-3">
                <AsyncButton type="button" class="btn btn-secondary" click={testConnection}>
                    Test Connection
                </AsyncButton>
                <a
                    class="btn btn-info"
                    href="/config/ldap-servers/{params.id}/users"
                    use:link>
                    View Users
                </a>
                <AsyncButton type="submit" class="btn btn-primary" click={save}>
                    Save
                </AsyncButton>
                <AsyncButton type="button" class="btn btn-danger ms-auto" click={remove}>
                    Delete
                </AsyncButton>
            </div>
        </form>
    </div>
</Loadable>
