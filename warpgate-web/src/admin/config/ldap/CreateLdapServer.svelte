<script lang="ts">
    import {
        api,
        LdapUsernameAttribute,
        type Tls,
        TlsMode,
    } from 'admin/lib/api'
    import { stringifyError } from 'common/errors'
    import { reloadServerInfo } from 'gateway/lib/store'
    import { push } from 'svelte-spa-router'
    import Button from 'ui/Button.svelte'
    import Callout from 'ui/Callout.svelte'
    import Input from 'ui/Input.svelte'
    import { defaultLdapPortForTlsMode, testLdapConnection } from './common'
    import LdapConnectionFields from './LdapConnectionFields.svelte'

    let name = $state('')
    let host = $state('')
    let port = $state(389)
    let bindDn = $state('')
    let bindPassword = $state('')
    let userFilter = $state('(objectClass=person)')
    let enabled = $state(true)
    let autoLinkSsoUsers = $state(false)
    let description = $state('')
    let usernameAttribute = $state(LdapUsernameAttribute.Cn)
    let sshKeyAttribute = $state('sshPublicKey')
    let uuidAttribute = $state('')
    let error = $state<string | null>(null)
    let tls: Tls = $state({
        mode: TlsMode.Preferred,
        verify: true,
    })
    let testResult = $state<{
        success: boolean
        message: string
        baseDns?: string[]
    } | null>(null)

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
        } catch (e) {
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
                    uuidAttribute,
                },
            })

            reloadServerInfo() // update hasLdap flag
            push(`/config/ldap-servers/${result.id}`)
        } catch (e) {
            error = await stringifyError(e)
        }
    }
</script>

<div class="container-max-md">
    {#if error}
        <Callout tone="danger" title="Something went wrong">{error}</Callout>
    {/if}

    <div class="page-summary-bar">
        <h1>add an LDAP server</h1>
    </div>

    <form onsubmit={e => {e.preventDefault(); create()}}>
        <Input label="Name" bind:value={name} required />

        <LdapConnectionFields
            bind:host
            bind:port
            bind:bindDn
            bind:bindPassword
            bind:tls
            bind:userFilter
            bind:usernameAttribute
            bind:sshKeyAttribute
            bind:uuidAttribute
        />

        {#if testResult}
            <div
                class="alert {testResult.success ? 'alert-success' : 'alert-danger'}"
                role="alert"
            >
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
            <Button type="button" class="me-auto" click={testConnection}>
                Test connection
            </Button>
            <Button type="submit" variant="primary" click={create}>
                Create
            </Button>
        </div>
    </form>
</div>
