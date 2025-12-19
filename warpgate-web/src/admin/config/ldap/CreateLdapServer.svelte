<script lang="ts">
    import { FormGroup, Input } from '@sveltestrap/sveltestrap'
    import { push } from 'svelte-spa-router'
    import { reloadServerInfo } from 'gateway/lib/store'
    import { api, LdapUsernameAttribute, stringifyError, TlsMode, type Tls } from 'admin/lib/api'
    import AsyncButton from 'common/AsyncButton.svelte'
    import Alert from 'common/sveltestrap-s5-ports/Alert.svelte'
    import LdapConnectionFields from './LdapConnectionFields.svelte'
    import { defaultLdapPortForTlsMode, testLdapConnection } from './common'

    let name = $state('')
    let host = $state('')
    // eslint-disable-next-line svelte/prefer-writable-derived
    let port = $state(389)
    let bindDn = $state('')
    let bindPassword = $state('')
    let userFilter = $state('(objectClass=person)')
    let enabled = $state(true)
    let autoLinkSsoUsers = $state(false)
    let description = $state('')
    let usernameAttribute = $state(LdapUsernameAttribute.Cn)
    let sshKeyAttribute = $state('sshPublicKey')
    let error = $state<string | null>(null)
    let tls: Tls = $state({
        mode: TlsMode.Preferred,
        verify: true,
    })
    let testResult = $state<{ success: boolean; message: string; baseDns?: string[] } | null>(null)

    // Auto-update port based on TLS mode
    $effect(() => {
        port = defaultLdapPortForTlsMode(tls.mode)
    })

    async function testConnection() {
        error = null
        testResult = null

        try {
            testResult = await testLdapConnection({
                host,
                port,
                bindDn,
                bindPassword,
                tlsMode: tls.mode,
                tlsVerify: tls.verify,
            })
        } catch (e: any) {
            error = await stringifyError(e)
        }
    }

    async function create() {
        error = null

        try {
            const result = await api.createLdapServer({
                createLdapServerRequest: {
                    name,
                    host,
                    port,
                    bindDn,
                    bindPassword,
                    userFilter,
                    tlsMode: tls.mode,
                    tlsVerify: tls.verify,
                    enabled,
                    autoLinkSsoUsers,
                    description: description || undefined,
                    usernameAttribute,
                    sshKeyAttribute,
                },
            })

            reloadServerInfo() // update hasLdap flag
            push(`/config/ldap-servers/${result.id}`)
        } catch (e: any) {
            error = await stringifyError(e)
        }
    }
</script>

<div class="container-max-md">
    {#if error}
        <Alert color="danger">{error}</Alert>
    {/if}

    <div class="page-summary-bar">
        <h1>add an LDAP server</h1>
    </div>

    <form onsubmit={e => {e.preventDefault(); create()}}>
        <FormGroup floating label="Name">
            <Input
                bind:value={name}
                required
            />
        </FormGroup>

        <LdapConnectionFields
            bind:host
            bind:port
            bind:bindDn
            bind:bindPassword
            bind:tls
            bind:userFilter
            bind:usernameAttribute
            bind:sshKeyAttribute
        />

        {#if testResult}
            <div class="alert {testResult.success ? 'alert-success' : 'alert-danger'}" role="alert">
                {testResult.message}
                {#if testResult.baseDns && testResult.baseDns.length > 0}
                    <div class="mt-2">
                        <strong>Discovered Base DNs:</strong>
                        <ul class="mb-0 mt-1">
                            {#each testResult.baseDns as dn (dn)}
                                <li><code>{dn}</code></li>
                            {/each}
                        </ul>
                    </div>
                {/if}
            </div>
        {/if}

        <div class="d-flex gap-2 mt-5">
            <AsyncButton type="button" class="me-auto" click={testConnection}>
                Test connection
            </AsyncButton>
            <AsyncButton type="submit" color="primary" click={create}>
                Create
            </AsyncButton>
        </div>
    </form>
</div>
