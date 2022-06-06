<script lang="ts">
import { api, SSHKey, SSHKnownHost } from 'admin/lib/api'
import { Alert } from 'sveltestrap'

let error: Error|undefined
let knownHosts: SSHKnownHost[]|undefined
let ownKeys: SSHKey[]|undefined

async function load () {
    ownKeys = await api.getSshOwnKeys()
    knownHosts = await api.getSshKnownHosts()
}

load().catch(e => {
    error = e
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
    <Alert color="info">Add these keys to the targets' <code>authorized_hosts</code> files</Alert>
    <div class="list-group list-group-flush">
        {#each ownKeys as key}
            <div class="list-group-item">
                <pre>{key.kind} {key.publicKeyBase64}</pre>
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

                    <a class="ms-auto" href={''} on:click|preventDefault={() => deleteHost(host)}>Delete</a>
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
