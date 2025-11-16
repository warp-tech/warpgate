<script lang="ts">
    import { link, push } from 'svelte-spa-router'
    import { api, stringifyError, TlsMode, type Tls } from 'admin/lib/api'
    import AsyncButton from 'common/AsyncButton.svelte'
    import Loadable from 'common/Loadable.svelte'
    import { FormGroup, Input } from '@sveltestrap/sveltestrap'
    import LdapConnectionFields from './LdapConnectionFields.svelte'

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
    let tls: Tls = $state({
        mode: TlsMode.Preferred,
        verify: true,
    })
    let enabled = $state(true)
    let autoLinkSsoUsers = $state(false)
    let description = $state('')
    let error = $state<string | null>(null)
    let testResult = $state<{ success: boolean; message: string } | null>(null)
    let isLoaded = $state(false)

    // Auto-update port based on TLS mode (only after initial load)
    $effect(() => {
        if (isLoaded) {
            if (tls.mode === TlsMode.Disabled) {
                port = 389
            } else {
                port = 636
            }
        }
    })

    async function load() {
        const result = await api.getLdapServer({ id: params.id })
        server = result
        name = result.name
        host = result.host
        port = result.port
        bindDn = result.bindDn
        userFilter = result.userFilter
        baseDns = result.baseDns || []
        tls = { mode: result.tlsMode, verify: result.tlsVerify }
        enabled = result.enabled
        autoLinkSsoUsers = result.autoLinkSsoUsers
        description = result.description || ''
        isLoaded = true
    }

    async function testConnection() {
        error = null
        testResult = null

        try {
            const timeoutPromise = new Promise((_, reject) => {
                setTimeout(() => reject(new Error('Connection test timed out after 10 seconds')), 10000)
            })

            const testPromise = api.testLdapServerConnection({
                testLdapServerRequest: {
                    host,
                    port,
                    bindDn,
                    bindPassword: bindPassword || server.bindPassword,
                    tlsMode: tls.mode,
                    tlsVerify: tls.verify,
                },
            })

            const result = await Promise.race([testPromise, timeoutPromise]) as any
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
                    tlsMode: tls.mode,
                    tlsVerify: tls.verify,
                    enabled,
                    autoLinkSsoUsers,
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
        <div class="page-summary-bar">
            <div>
                <h1>{name}</h1>
                <div class="text-muted">LDAP server</div>
            </div>
        </div>

        <form onsubmit={(e) => { e.preventDefault(); save() }}>
            <FormGroup floating label="Name">
                <Input bind:value={name} required />
            </FormGroup>

            <FormGroup floating label="Description">
                <Input bind:value={description} />
            </FormGroup>

            <LdapConnectionFields
                bind:host
                bind:port
                bind:bindDn
                bind:bindPassword
                bind:tls
                bind:userFilter
                passwordPlaceholder="Keep current password"
                passwordRequired={false}
            />

            {#if baseDns.length > 0}
                <div class="mt-4">
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

            <!-- <div class="mt-4">
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
            </div> -->

            <div class="mt-4">
                <div class="form-check form-switch">
                    <input
                        class="form-check-input"
                        type="checkbox"
                        id="autoLinkSsoUsers"
                        bind:checked={autoLinkSsoUsers}
                    />
                    <label class="form-check-label" for="autoLinkSsoUsers">
                        Auto-link SSO users
                    </label>
                </div>
                <div class="form-text">
                    Automatically link SSO users to their LDAP accounts when they log in
                </div>
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

            <div class="d-flex gap-2 mt-5">
                <AsyncButton type="button" class="btn btn-secondary" click={testConnection}>
                    Test Connection
                </AsyncButton>
                <a
                    class="btn btn-info"
                    href="/config/ldap-servers/{params.id}/users"
                    use:link>
                    View Users
                </a>
                <div class="me-auto"></div>
                <AsyncButton type="submit" class="btn btn-primary" click={save}>
                    Save
                </AsyncButton>
                <AsyncButton type="button" class="btn btn-danger" click={remove}>
                    Remove
                </AsyncButton>
            </div>
        </form>
    </div>
</Loadable>
