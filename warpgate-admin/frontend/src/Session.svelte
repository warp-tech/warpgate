<script lang="ts">
import { api, SessionSnapshot, Recording } from 'lib/api'
import { link } from 'svelte-spa-router'
import { Alert, Spinner } from 'sveltestrap'

export let params = { id: '' }

let error: Error|null = null
let session: SessionSnapshot|null = null
let recordings: Recording[]|null = null

async function load () {
    session = await api.getSession(params)
    recordings = await api.getSessionRecordings(params)
}

load().catch(e => {
    error = e
})

</script>

{#if session}
<h1>{session.id}</h1>
{/if}

{#if !session && !error}
<Spinner />
{/if}

{#if error}
<Alert color="danger">{error.message}</Alert>
{/if}

{#if recordings }
<div class="list-group list-group-flush">
    {#each recordings as recording, i}
        <a
            class="list-group-item list-group-item-action"
            href="/recordings/{recording.id}"
            use:link>
            <div class="main">
                <strong>
                    {recording.id}
                </strong>

                <code>{recording.name}</code>
            </div>
            <div class="meta">
                <small>{recording.started}</small>
            </div>
        </a>
    {/each}
</div>
{/if}

<style lang="scss">
.list-group-item {
    .main {
        display: flex;
        align-items: center;

        > * {
            margin-right: 20px;
        }
    }

    .meta {
        opacity: .75;
    }
}
</style>
