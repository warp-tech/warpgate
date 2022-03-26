<script lang="ts">
import { api, SSHKnownHost } from 'lib/api'
import { Alert } from 'sveltestrap'

let error: Error|undefined
let knownHosts: SSHKnownHost[]|undefined

async function load () {
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

{#if error}
<Alert color="danger">{error.message}</Alert>
{/if}

{#if knownHosts }
<div class="page-summary-bar">
    {#if knownHosts.length }
        <h1>Trusted SSH keys: {knownHosts.length}</h1>
    {:else}
        <h1>No trusted SSH keys</h1>
    {/if}
</div>
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
