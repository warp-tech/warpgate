<script lang="ts">
import { api, type SSHKey, type SSHKnownHost } from 'admin/lib/api'
import Alert from 'common/sveltestrap-s5-ports/Alert.svelte'
import CopyButton from 'common/CopyButton.svelte'
import { stringifyError } from 'common/errors'

let error: string|undefined = $state()
let knownHosts: SSHKnownHost[]|undefined = $state()
let ownKeys: SSHKey[]|undefined = $state()

async function load () {
    ownKeys = await api.getSshOwnKeys()
    knownHosts = await api.getSshKnownHosts()
}

load().catch(async e => {
    error = await stringifyError(e)
})

async function deleteHost (host: SSHKnownHost) {
    await api.deleteSshKnownHost(host)
    load()
}

</script>

<div class="page-summary-bar">
    <h1>SSH</h1>
</div>

{#if error}
    <Alert color="danger">{error}</Alert>
{/if}

{#if ownKeys}
    <h2>Warpgate's own SSH keys</h2>
    <Alert color="info">Add these keys to the targets' <code>authorized_keys</code> files</Alert>
    <div class="list-group list-group-flush">
        {#each ownKeys as key}
            <div class="list-group-item d-flex">
                <pre>{key.kind} {key.publicKeyBase64}</pre>
                <div class="ms-auto">
                    <CopyButton class="ms-3" link text={key.kind + ' ' + key.publicKeyBase64} />
                </div>
            </div>
        {/each}
    </div>
{/if}

<div class="mb-3"></div>
{#if knownHosts}
    {#if knownHosts.length }
        <h2>Known hosts: {knownHosts.length}</h2>
    {:else}
        <h2>No known hosts</h2>
    {/if}
    <div class="list-group list-group-flush">
        {#each knownHosts as host}
            <div class="list-group-item">
                <div class="d-flex">
                    <strong>
                        {host.host}:{host.port}
                    </strong>

                    <a class="ms-auto" href={''} onclick={e => {
                        e.preventDefault()
                        deleteHost(host)
                    }}>Delete</a>
                </div>
                <pre>{host.keyType} {host.keyBase64}</pre>
            </div>
        {/each}
    </div>
{/if}

<style lang="scss">
    pre {
        word-break: break-word;
        white-space: normal;
    }
</style>
