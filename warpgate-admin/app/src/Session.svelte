<script lang="ts">
import { api, SessionSnapshot, Recording } from 'lib/api'
import { timeAgo } from 'lib/time'
import { link } from 'svelte-spa-router'
import { Alert, Button, Spinner } from 'sveltestrap'

export let params = { id: '' }

let error: Error|null = null
let session: SessionSnapshot|null = null
let recordings: Recording[]|null = null

async function load () {
    session = await api.getSession(params)
    recordings = await api.getSessionRecordings(params)
}

async function close () {

}

load().catch(e => {
    error = e
})

</script>

{#if session}
    <div class="page-summary-bar">
        <div>
            <h1>Session</h1>
            <small class="d-block text-muted">{session.id}</small>
        </div>
        <Button class="ms-auto" outline on:click={close}>
            Close now
        </Button>
    </div>
{/if}

{#if !session && !error}
    <Spinner />
{/if}

{#if error}
    <Alert color="danger">{error.message}</Alert>
{/if}

{#if recordings }
<div class="list-group list-group-flush">
    {#each recordings as recording}
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
                <small>Started {timeAgo(recording.started)}</small>
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
