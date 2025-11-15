<script lang="ts">
    import { push } from 'svelte-spa-router'
    import { api, stringifyError } from 'admin/lib/api'
    import AsyncButton from 'common/AsyncButton.svelte'

    let name = $state('')
    let host = $state('')
    let port = $state(389)
    let bindDn = $state('')
    let bindPassword = $state('')
    let userFilter = $state('(objectClass=person)')
    let tlsMode = $state('preferred')
    let tlsVerify = $state(true)
    let enabled = $state(true)
    let description = $state('')
    let error = $state<string | null>(null)
    let testResult = $state<{ success: boolean; message: string; baseDns?: string[] } | null>(null)

    async function testConnection() {
        error = null
        testResult = null

        try {
            const result = await api.testLdapServerConnection({
                testLdapServerRequest: {
                    host,
                    port,
                    bindDn,
                    bindPassword,
                    tlsMode: tlsMode as any,
                    tlsVerify,
                },
            })
            testResult = result
        } catch (e: any) {
            error = await stringifyError(e)
        }
    }

    async function create() {
        error = null

        if (!name || !host || !bindDn || !bindPassword) {
            error = 'Please fill in all required fields'
            return
        }

        try {
            const result = await api.createLdapServer({
                createLdapServerRequest: {
                    name,
                    host,
                    port,
                    bindDn,
                    bindPassword,
                    userFilter,
                    tlsMode: tlsMode as any,
                    tlsVerify,
                    enabled,
                    description: description || undefined,
                },
            })
            push(`/config/ldap-servers/${result.id}`)
        } catch (e: any) {
            error = await stringifyError(e)
        }
    }
</script>

<div class="container-max-md">
    <h1>Add LDAP Server</h1>

    <form on:submit|preventDefault={create}>
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
                    placeholder="ldap.example.com"
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
                placeholder="cn=admin,dc=example,dc=com"
                required
            />
        </div>

        <div class="mb-3">
            <label for="bindPassword" class="form-label">Bind Password *</label>
            <input
                type="password"
                class="form-control"
                id="bindPassword"
                bind:value={bindPassword}
                required
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
            <small class="form-text text-muted">
                LDAP filter to find users (e.g., (objectClass=person))
            </small>
        </div>

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
                <label class="form-label d-block">TLS Verify</label>
                <div class="form-check form-switch">
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
                {#if testResult.baseDns && testResult.baseDns.length > 0}
                    <div class="mt-2">
                        <strong>Discovered Base DNs:</strong>
                        <ul class="mb-0 mt-1">
                            {#each testResult.baseDns as dn}
                                <li><code>{dn}</code></li>
                            {/each}
                        </ul>
                    </div>
                {/if}
            </div>
        {/if}

        {#if error}
            <div class="alert alert-danger" role="alert">
                {error}
            </div>
        {/if}

        <div class="d-flex gap-2">
            <AsyncButton type="button" class="btn btn-secondary" click={testConnection}>
                Test Connection
            </AsyncButton>
            <AsyncButton type="submit" class="btn btn-primary" click={create}>
                Create
            </AsyncButton>
        </div>
    </form>
</div>
