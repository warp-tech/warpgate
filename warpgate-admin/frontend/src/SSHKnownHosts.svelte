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
<div class="list-group list-group-flush">
    {#each knownHosts as host}
        <div class="list-group-item">
            <div class="main">
                <strong>
                    {host.host}:{host.port}
                </strong>

                <code>{host.keyType}</code>
                <code>{host.keyBase64}</code>
                <button on:click="{() => deleteHost(host)}">Delete</button>
            </div>
        </div>
    {/each}
</div>
{/if}
